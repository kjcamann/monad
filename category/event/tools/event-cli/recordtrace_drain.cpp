// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "command.hpp"
#include "err_cxx.hpp"
#include "file.hpp"
#include "iterator.hpp"
#include "recordtrace.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <print>
#include <span>
#include <string>
#include <thread>
#include <utility>

#include <pthread.h>
#include <sysexits.h>

#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_def.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>

constexpr unsigned HistogramSampleShift = 10;
constexpr unsigned HistogramPrintShift = 24;
constexpr uint64_t HistogramSampleMask = (1UL << HistogramSampleShift) - 1;
constexpr uint64_t HistogramPrintMask = (1UL << HistogramPrintShift) - 1;
constexpr size_t BackpressureHistogramSize = 30;

namespace
{

inline void VBUF_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "vbuf library error -- {}",
            monad_vbuf_writer_get_last_error());
    }
}

struct TraceEventSourceState
{
    EventIterator iter;
    bool finished;
    monad_vbuf_writer *event_vbuf_writer;
    monad_vbuf_writer *seqno_vbuf_writer;
    uint64_t blocks_processed;
    EventSourceSpec const *event_source;
    uint64_t backpressure_histogram[BackpressureHistogramSize];
};

// XXX: copied from the old record.cpp implementation
void print_histogram(std::span<uint64_t> histogram, std::FILE *out)
{
    for (size_t b = 0; uint64_t const v : histogram) {
        if (b == 0) {
            std::println(out, "{:7} - {:7} {}", 0, 0, v);
        }
        else {
            std::println(
                out, "{:7} - {:7} {}", 1UL << (b - 1), (1UL << b) - 1, v);
        }
        ++b;
    }
}

void drain_trace_events(
    std::stop_token stop_token, TraceEventSourceState *state,
    BlockTrace *cur_block_trace)
{
    monad_event_descriptor event;
    std::byte const *payload;
    char const *const trace_type_name =
        g_monad_event_content_type_names[state->iter.content_type];

    state->iter.set_seqno(cur_block_trace->initial_seqno);
    while (!stop_token.stop_requested() && !state->finished) {
        using enum EventIteratorResult;
        switch (state->iter.next(&event, &payload)) {
        case Error:
            errx_f(
                EX_SOFTWARE,
                "EventIterator::next error {} -- {}",
                state->iter.error_code,
                state->iter.last_error_msg);

        case End:
            state->finished = true;
            [[fallthrough]];
        case NotReady:
            continue;

        case Gap:
            // TODO(ken): we don't actually need to do this, we just won't
            //   have the trace
            errx_f(
                EX_SOFTWARE,
                "ERROR: {} trace source event gap from {} -> {}, record is "
                "destroyed",
                trace_type_name,
                state->iter.get_last_read_seqno(),
                state->iter.get_last_written_seqno());

        case Success:
            [[likely]]
            // Handled in the main body of the loop
            break;

        default:
            std::unreachable();
        }

#if 1
        if (/* XXX: print_backpressure_stats*/ true &&
            ((event.seqno + 1) & HistogramSampleMask) == 0) [[unlikely]] {
            uint64_t const available_events =
                state->iter.get_last_written_seqno() - event.seqno;
            unsigned bp_bucket =
                static_cast<unsigned>(std::bit_width(available_events));
            if (bp_bucket >= std::size(state->backpressure_histogram)) {
                bp_bucket = static_cast<unsigned>(
                    std::size(state->backpressure_histogram) - 1);
            }
            ++state->backpressure_histogram[bp_bucket];
            if (((event.seqno + 1) & HistogramPrintMask) == 0) [[unlikely]] {
                print_histogram(state->backpressure_histogram, stderr);
            }
        }
#endif

        // Append trace event to vbuf
        size_t const cur_event_offset = monad_round_size_to_align(
            monad_vbuf_writer_get_offset(state->event_vbuf_writer),
            alignof(monad_event_descriptor));
        VBUF_CHECK(monad_vbuf_writer_memcpy(
            state->seqno_vbuf_writer,
            &cur_event_offset,
            sizeof cur_event_offset,
            1,
            &cur_block_trace->seqno_vbufs));
        VBUF_CHECK(monad_evcap_vbuf_append_event(
            state->event_vbuf_writer,
            &event,
            payload,
            &cur_block_trace->event_vbufs));
        if (!state->iter.check_payload(&event)) [[unlikely]] {
            errx_f(
                EX_SOFTWARE,
                "payload expired for {} trace event {}",
                trace_type_name,
                event.seqno);
        }
        if (cur_block_trace->event_count++ == 0) {
            cur_block_trace->start_seqno = event.seqno;
        }
        // XXX: not sure how to formalize this protocol, but all trace content
        // types have the first two events after RECORD_ERROR as being the
        // associated BLOCK_START and BLOCK_END events
        if (event.event_type == 3) [[unlikely]] {
            break;
        }
    }

    monad_vbuf_writer_reset(
        state->event_vbuf_writer, &cur_block_trace->event_vbufs);
    monad_vbuf_writer_reset(
        state->seqno_vbuf_writer, &cur_block_trace->seqno_vbufs);
    cur_block_trace->finished = true;
    ++state->blocks_processed;
}

} // End of anonymous namespace

void recordtrace_drain(
    std::stop_token stop, EventSourceSpec const *spec,
    monad_vbuf_segment_allocator *segment_allocator, RecordTraceContext const *,
    RecordTraceState *rts)
{
    TraceEventSourceState state{};
    state.event_source = spec;
    if (std::string const err = state.event_source->init_iterator(&state.iter);
        !err.empty()) {
        errx_f(
            EX_SOFTWARE,
            "trace event source {} init_iterator failed: {}",
            state.event_source->describe(),
            err);
    }

    VBUF_CHECK(
        monad_vbuf_writer_create(&state.event_vbuf_writer, segment_allocator));
    VBUF_CHECK(
        monad_vbuf_writer_create(&state.seqno_vbuf_writer, segment_allocator));

    rts->start_latch->arrive_and_wait();
    while (!stop.stop_requested()) {
        TracedProposal *tp;
        BlockTrace *next_trace = nullptr;
        pthread_spin_lock(&rts->pending_proposal_lock);
        TAILQ_FOREACH(tp, &rts->pending_proposal_queue, entry)
        {
            BlockTrace *const our_trace =
                tp->trace_map[state.iter.content_type];
            if (our_trace != nullptr && !our_trace->finished) {
                next_trace = our_trace;
                break;
            }
        }
        pthread_spin_unlock(&rts->pending_proposal_lock);
        if (next_trace) {
            drain_trace_events(stop, &state, next_trace);
            rts->release_hold(next_trace->traced_proposal);
        }
    }
}
