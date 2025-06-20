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

#include "eventcap.hpp"
#include "eventsource.hpp"
#include "metadata.hpp"
#include "options.hpp"
#include "util.hpp"

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <iterator>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <utility>

#include <alloca.h>

#include <category/core/event/event_metadata.h>
#include <category/core/event/event_ring.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_event_ctypes_fmt.hpp>

namespace
{

struct EventSourceState
{
    EventSource::Iterator iter;
    size_t not_ready_count;
    bool finished;
    EventSource const *event_source;
    Command const *command;
};

bool hexdump_event_payload(
    EventSource::Iterator const *iter, monad_event_descriptor const *event,
    std::byte const *const payload_base, std::FILE *out)
{
    // Large thread_locals will cause a stack overflow, so make the
    // thread-local a pointer to a dynamic buffer
    constexpr size_t hexdump_buf_size = 1UL << 25;
    thread_local static std::unique_ptr<char[]> const hexdump_buf{
        new char[hexdump_buf_size]};

    bool const overflow = event->payload_size > hexdump_buf_size;
    std::byte const *const payload_end =
        overflow
            ? std::bit_cast<std::byte *>(hexdump_buf.get()) + hexdump_buf_size
            : payload_base + event->payload_size;
    char *o = hexdump_buf.get();
    for (std::byte const *line = payload_base; line < payload_end; line += 16) {
        // Print one line of the dump, which is 16 bytes, in the form:
        // <offset> <8 bytes> <8 bytes>
        o = std::format_to(o, "{:#08x} ", line - payload_base);
        for (uint8_t b = 0; b < 16 && line + b < payload_end; ++b) {
            o = std::format_to(o, "{:02x}", std::to_underlying(line[b]));
            if (b == 7) {
                *o++ = ' '; // Extra padding after 8 bytes
            }
        }
        *o++ = '\n';

        // Every 512 bytes, check if the payload data is still valid; the +16
        // bias is to prevent checking the first iteration
        if ((line - payload_base + 16) % 512 == 0 &&
            !iter->check_payload(event)) {
            break; // Escape to the end, which checks the final time
        }
    }

    if (!iter->check_payload(event)) {
        return false;
    }
    std::fwrite(
        hexdump_buf.get(), static_cast<size_t>(o - hexdump_buf.get()), 1, out);
    if (overflow) {
        std::println(
            out,
            "ERROR: hexdump overflowed; event payload size {}, hexdump buffer "
            "size {}",
            event->payload_size,
            hexdump_buf_size);
    }
    return true;
}

char *format_exec_event_user_array(
    EventSource::Iterator const *iter, monad_event_descriptor const *event,
    char *o)
{
    if (uint64_t const block_start_seqno =
            event->content_ext[MONAD_FLOW_BLOCK_SEQNO]) {
        monad_event_descriptor block_start_event;
        std::byte const *block_start_payload;
        std::optional<uint64_t> block_number;
        if (iter->read_seqno(
                block_start_seqno,
                nullptr,
                &block_start_event,
                &block_start_payload)) {
            auto const *const bs =
                reinterpret_cast<monad_exec_block_start const *>(
                    block_start_payload);
            block_number = bs->block_tag.block_number;
            if (!iter->check_payload(&block_start_event)) {
                block_number.reset();
            }
        }
        if (block_number) {
            o = std::format_to(o, " BLK: {}", *block_number);
        }
        else {
            o = std::format_to(o, " BLK: N/A");
        }
    }
    if (uint64_t const txn_id = event->content_ext[MONAD_FLOW_TXN_ID]) {
        o = std::format_to(o, " TXN: {}", txn_id - 1);
    }
    return o;
}

bool print_event(
    EventSource::Iterator const *iter, monad_event_content_type content_type,
    monad_event_descriptor const *event, std::byte const *payload,
    DumpCommandOptions const *dump_opts, std::FILE *out)
{
    using std::chrono::seconds, std::chrono::nanoseconds;
    static std::chrono::sys_time<seconds> last_second{};
    static std::chrono::sys_time<nanoseconds> last_second_nanos;
    static char time_buf[32];
    char event_buf[512];

    monad_event_metadata const &event_md =
        MetadataTable[content_type].entries[event->event_type];
    std::chrono::sys_time const event_time{
        nanoseconds{event->record_epoch_nanos}};

    // An optimization to only do the string formatting of the %H:%M:%S part
    // of the time each second when it changes; this is a slow operation
    if (auto const cur_second = std::chrono::floor<seconds>(event_time);
        cur_second != last_second) {
        // The below should, but std::format formats the local time in the
        // UTC zone
        std::chrono::zoned_time const event_time_tz{
            std::chrono::current_zone(), cur_second};
        *std::format_to(time_buf, "{:%T}", event_time_tz) = '\0';
        last_second = cur_second;
        last_second_nanos =
            std::chrono::time_point_cast<nanoseconds>(last_second);
    }

    // Print a summary line of this event
    // <HH:MM::SS.nanos> <event-c-name> [<event-type> <event-type-hex>]
    //     SEQ: <sequence-no> LEN: <payload-length>
    char *o = std::format_to(
        event_buf,
        "{}.{:09}: {} [{} {:#x}] SEQ: {} LEN: {} BUF_OFF: {}",
        time_buf,
        (event_time - last_second_nanos).count(),
        event_md.c_name,
        event->event_type,
        event->event_type,
        event->seqno,
        event->payload_size,
        event->payload_buf_offset);

    // Print the `event->content_ext` array. There are two different approaches:
    //
    //   1. For execution rings the program understands the meaning of these
    //      values and prints them in an ergonomic way, e.g.,
    //      `event->content_ext[MONAD_FLOW_TXN_ID]` is a transaction index
    //      number so it prints that as `TXN: <number>`
    //
    //   2. For all other rings, or if explicitly requested for debugging
    //      purposes, the hex value of each array element is printed
    if (dump_opts->always_dump_content_ext ||
        content_type != MONAD_EVENT_CONTENT_TYPE_EXEC) {
        o = std::format_to(o, " CONTENT_EXT:");
        for (uint64_t const u : event->content_ext) {
            o = std::format_to(o, " {0:#08x}", u);
        }
    }
    if (content_type == MONAD_EVENT_CONTENT_TYPE_EXEC) {
        o = format_exec_event_user_array(iter, event, o);
    }
    *o++ = '\n';
    std::fwrite(event_buf, static_cast<size_t>(o - event_buf), 1, out);
    bool payload_ok = true;

    if (dump_opts->decode && content_type == MONAD_EVENT_CONTENT_TYPE_EXEC &&
        event->payload_size > 0) {
        // TODO(ken): generalize a decode interface beyond the exec ring
        std::string buf;
        std::back_insert_iterator mbo{buf};

        auto const event_type =
            static_cast<monad_exec_event_type>(event->event_type);
        mbo = category_labs::format_as(mbo, payload, event_type);
        if (iter->check_payload(event)) {
            std::println(out, "{}", buf);
        }
        else {
            payload_ok = false;
        }
    }
    if (dump_opts->hexdump) {
        payload_ok = hexdump_event_payload(iter, event, payload, out);
    }
    return payload_ok;
}

} // End of anonymous namespace

void dump_thread_main(std::span<Command *const> commands)
{
    EventSourceState *state_bufs = static_cast<EventSourceState *>(
        alloca(sizeof(EventSourceState) * size(commands)));
    std::span<EventSourceState> const states =
        std::span{state_bufs, size(commands)};
    size_t active_state_count = size(states);

    for (size_t i = 0; Command *const c : commands) {
        EventSourceState &state = *new (&states[i++]) EventSourceState{};
        state.event_source = c->event_sources[0];
        state.command = c;
        CommonCommandOptions const *cc_opts = c->get_common_options();
        state.event_source->init_iterator(
            &state.iter, cc_opts->start_seqno, cc_opts->end_seqno);
    }

    while (g_should_exit == 0 && active_state_count > 0) {
        for (std::size_t i = 0; EventSourceState &state : states) {
            using enum EventIteratorResult;

            size_t const ring_index = i++;
            if (state.finished) {
                continue;
            }

            monad_event_content_type content_type;
            monad_event_descriptor event;
            std::byte const *payload;
            switch (state.iter.next(&content_type, &event, &payload)) {
            case AfterEnd:
                [[fallthrough]];
            case Finished:
                --active_state_count;
                state.finished = true;
                [[fallthrough]];
            case Skipped:
                continue;

            case NotReady:
                if ((++state.not_ready_count & NotReadyCheckMask) == 0) {
                    std::fflush(state.command->output->file);
                    if (state.event_source->is_finalized()) {
                        --active_state_count;
                        state.finished = true;
                    }
                }
                continue; // Nothing produced yet

            case Gap: {
                auto const [gap_seqno, new_seqno] = state.iter.clear_gap(true);
                std::println(
                    stderr,
                    "ERROR: event gap from {} -> {}, resetting",
                    gap_seqno,
                    new_seqno);
                state.not_ready_count = 0;
                continue;
            }

            case AfterStart:
                std::println(
                    stderr,
                    "ERROR: missing start seqno {}",
                    *state.iter.start_seqno);
                [[fallthrough]];

            case Success:
                state.not_ready_count = 0;
                break; // Handled in the main loop body
            }
            auto const *const options =
                state.command->get_options<DumpCommandOptions>();
            std::FILE *const output = state.command->output->file;
            if (size(commands) > 1) {
                // We have multiple rings; prefix the event summary line with
                // an index
                std::print(output, "{}. ", ring_index);
            }
            bool const payload_ok = print_event(
                &state.iter, content_type, &event, payload, options, output);
            if (!payload_ok) {
                std::println(
                    stderr,
                    "ERROR: event {} payload lost! OFFSET: {}, WINDOW_START: "
                    "{}",
                    event.seqno,
                    event.payload_buf_offset,
                    __atomic_load_n(
                        &state.iter.ring_pair.iter.control->buffer_window_start,
                        __ATOMIC_ACQUIRE));
                (void)state.iter.clear_gap(true);
            }
        }
    }

    for (EventSourceState &s : states) {
        s.~EventSourceState();
    }
}
