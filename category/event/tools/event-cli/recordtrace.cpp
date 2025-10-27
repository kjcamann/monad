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
#include "metadata.hpp"
#include "options.hpp"
#include "util.hpp"

#include <cstddef>
#include <cstdint>
#include <flat_map>
#include <flat_set>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include <alloca.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_def.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

#include <zstd.h>

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

inline void EVCAP_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "evcap library error -- {}",
            monad_evcap_writer_get_last_error());
    }
}

inline void BC_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "bcap library error -- {}",
            monad_bcap_get_last_error());
    }
}

// Holds in the in-progress or completed vbuf chains for the event sections of
// a trace, plus some metadata (uncompressed size, start sequence number, etc.)
struct TraceEventCapture
{
    monad_vbuf_chain event_vbufs;
    monad_vbuf_chain seqno_vbufs;
    uint64_t event_uncompressed_size;
    uint64_t seqno_uncompressed_size;
    uint64_t start_seqno;
    uint64_t event_count;
};

struct TraceEventSourceState
{
    EventIterator iter;
    bool finished;
    monad_vbuf_writer *event_vbuf_writer;
    monad_vbuf_writer *seqno_vbuf_writer;
    TraceEventCapture capture;
    EventSourceSpec const *event_source;
};

struct BlockState
{
    using capture_map_t =
        std::flat_map<monad_event_content_type, TraceEventCapture>;

    uint64_t max_txn_flow_seqno;
    uint64_t txn_count;
    capture_map_t capture_map;
};

void init_vbuf_writer_options(
    uint8_t vbuf_segment_shift, std::optional<uint8_t> const &zstd_level,
    monad_vbuf_writer_options *vbuf_writer_options)
{
    *vbuf_writer_options = {
        .segment_shift = vbuf_segment_shift,
        .memfd_flags = 0,
        .zstd_cctx = zstd_level ? ZSTD_createCCtx() : nullptr};
    if (vbuf_writer_options->zstd_cctx) {
        size_t const r = ZSTD_CCtx_setParameter(
            vbuf_writer_options->zstd_cctx,
            ZSTD_c_compressionLevel,
            *zstd_level);
        if (ZSTD_isError(r)) {
            errx_f(
                EX_SOFTWARE,
                "zstd set compression error: {}",
                ZSTD_getErrorName(r));
        }
    }
}

void init_trace_state_vbufs(
    RecordTraceCommandOptions const *options,
    TraceEventSourceState *trace_state)
{
    monad_vbuf_writer_options event_writer_opts;
    monad_vbuf_writer_options seqno_index_writer_opts;

    init_vbuf_writer_options(
        options->vbuf_segment_shift,
        options->event_zstd_level,
        &event_writer_opts);
    VBUF_CHECK(monad_vbuf_writer_create(
        &trace_state->event_vbuf_writer, &event_writer_opts));
    init_vbuf_writer_options(
        options->vbuf_segment_shift,
        options->seqno_zstd_level,
        &seqno_index_writer_opts);
    VBUF_CHECK(monad_vbuf_writer_create(
        &trace_state->seqno_vbuf_writer, &seqno_index_writer_opts));

    monad_vbuf_chain_init(&trace_state->capture.event_vbufs);
    monad_vbuf_chain_init(&trace_state->capture.seqno_vbufs);
}

void drain_trace_source(
    TraceEventSourceState *state, uint64_t max_txn_flow_seqno)
{
    using enum EventIteratorResult;

    monad_event_descriptor event;
    std::byte const *payload;
    while (g_should_exit == 0) {
        switch (state->iter.copy(&event, &payload)) {
        case Error:
            errx_f(
                EX_SOFTWARE,
                "EventIterator::next error {} -- {}",
                state->iter.error_code,
                state->iter.last_error_msg);

        case End:
            state->finished = true;
            return;

        case NotReady:
            return;

        case Gap:
            // TODO(ken): improve this a lot
            errx_f(
                EX_SOFTWARE,
                "ERROR: event gap from {} -> {}, record is destroyed",
                state->iter.get_last_read_seqno(),
                state->iter.get_last_written_seqno());

        case Success:
            // Handled in the main body of the loop
            break;

        default:
            std::unreachable();
        }

        if (event.content_ext[0] > max_txn_flow_seqno) {
            return; // Not allowed to scan this yet
        }
        if (state->iter.advance(1) == EventIteratorResult::Error) {
            errx_f(
                EX_SOFTWARE,
                "ERROR: event iter can't advance at {}",
                state->iter.get_last_read_seqno());
        }

        // Append trace event to vbuf
        size_t const cur_offset = monad_round_size_to_align(
            monad_vbuf_writer_get_offset(state->event_vbuf_writer),
            alignof(monad_event_descriptor));
        VBUF_CHECK(monad_vbuf_writer_memcpy(
            state->seqno_vbuf_writer,
            &cur_offset,
            sizeof cur_offset,
            1,
            &state->capture.seqno_vbufs));
        EVCAP_CHECK(monad_evcap_vbuf_append_event(
            state->event_vbuf_writer,
            &event,
            payload,
            &state->capture.event_vbufs));
        if (!state->iter.check_payload(&event)) {
            errx_f(EX_SOFTWARE, "payload expired for event {}", event.seqno);
        }
        if (state->capture.event_count++ == 0) {
            state->capture.start_seqno = event.seqno;
        }
    }
}

void flush_to_capture_map(
    TraceEventSourceState *source_state, BlockState *block_state)
{
    auto const it =
        block_state->capture_map.try_emplace(source_state->iter.content_type);
    if (it.second) {
        TraceEventCapture &capture = it.first->second;

        monad_vbuf_chain_init(&capture.event_vbufs);
        monad_vbuf_chain_concat(
            &capture.event_vbufs, &source_state->capture.event_vbufs);
        monad_vbuf_writer_reset(
            source_state->event_vbuf_writer,
            &capture.event_vbufs,
            &capture.event_uncompressed_size);

        monad_vbuf_chain_init(&capture.seqno_vbufs);
        monad_vbuf_chain_concat(
            &capture.seqno_vbufs, &source_state->capture.seqno_vbufs);
        monad_vbuf_writer_reset(
            source_state->seqno_vbuf_writer,
            &capture.seqno_vbufs,
            &capture.seqno_uncompressed_size);

        capture.event_count = 0;
        capture.start_seqno = 0;
        std::swap(capture.event_count, source_state->capture.event_count);
        std::swap(capture.start_seqno, source_state->capture.start_seqno);
    }
}

void record_capture_map(
    monad_bcap_block_archive *block_archive, uint64_t block_number,
    BlockState *block_state)
{
    int fd;
    char block_filename_buf[64];
    monad_evcap_writer *ecw;

    BC_CHECK(monad_bcap_block_archive_open_block_fd(
        block_archive,
        block_number,
        O_RDWR,
        &fd,
        block_filename_buf,
        sizeof block_filename_buf));
    EVCAP_CHECK(monad_evcap_writer_create(&ecw, fd, /*append*/ true));
    for (auto &&[content_type, trace_capture] : block_state->capture_map) {
        monad_evcap_dynamic_section *dynsec;
        monad_evcap_section_desc const *schema_sd;
        monad_evcap_section_desc *event_sd;

        MetadataTableEntry const &entry =
            MetadataTable[std::to_underlying(content_type)];
        EVCAP_CHECK(monad_evcap_writer_add_schema_section(
            ecw, content_type, *entry.schema_hash, &schema_sd));
        EVCAP_CHECK(monad_evcap_writer_dynsec_open(ecw, &dynsec, &event_sd));

        event_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;
        event_sd->compression = MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING;
        event_sd->content_length = trace_capture.event_uncompressed_size;

        event_sd->event_bundle.schema_desc_offset =
            schema_sd->descriptor_offset;
        event_sd->event_bundle.event_count = trace_capture.event_count;
        event_sd->event_bundle.start_seqno = trace_capture.start_seqno;
        event_sd->event_bundle.block_number = block_number;
        EVCAP_CHECK(
            monad_evcap_writer_dynsec_sync_vbuf_chain(
                ecw, dynsec, &trace_capture.event_vbufs) >= 0
                ? 0
                : -1);
        EVCAP_CHECK(monad_evcap_writer_dynsec_close(ecw, dynsec));

        EVCAP_CHECK(monad_evcap_writer_commit_seqno_index(
            ecw,
            &trace_capture.seqno_vbufs,
            MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING,
            trace_capture.seqno_uncompressed_size,
            event_sd));

        monad_vbuf_chain_free(&trace_capture.event_vbufs);
        monad_vbuf_chain_free(&trace_capture.seqno_vbufs);
    }
    monad_evcap_writer_destroy(ecw);
}

} // End of anonymous namespace

void recordtrace_thread_main(std::span<Command *const> commands)
{
    MONAD_ASSERT(size(commands) == 1);

    constexpr mode_t CreateMode =
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    EventIterator iter;
    Command *const command = commands[0];
    EventSourceSpec &exec_event_source = command->event_sources[0];

    size_t const trace_state_count = size(commands[0]->event_sources) - 1;
    TraceEventSourceState *trace_state_bufs =
        static_cast<TraceEventSourceState *>(
            alloca(sizeof(TraceEventSourceState) * trace_state_count));
    std::span<TraceEventSourceState> const trace_states =
        std::span{trace_state_bufs, trace_state_count};
    std::flat_set<TraceEventSourceState *> active_trace_sources;

    // XXX: escape hatch, make this more general later
    TraceEventSourceState *evm_trace_source_state = nullptr;

    auto const *const options =
        command->get_options<RecordTraceCommandOptions>();

    for (size_t i = 0; EventSourceSpec const &spec :
                       std::span{commands[0]->event_sources}.subspan(1)) {
        TraceEventSourceState *state =
            new (&trace_states[i++]) TraceEventSourceState{};
        state->event_source = &spec;
        state->event_source->init_iterator(&state->iter);
        init_trace_state_vbufs(options, state);
        if (state->iter.content_type == MONAD_EVENT_CONTENT_TYPE_EVMT) {
            evm_trace_source_state = state;
        }
    }

    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    monad_bcap_block_archive *block_archive;

    std::string const &output_spec = options->common_options.output_spec;
    int output_fd;
    // Output is underneath a top-level archive directory which must
    // already exist
    output_fd = open(output_spec.c_str(), O_DIRECTORY | O_PATH);
    if (output_fd == -1) {
        err_f(
            EX_OSERR,
            "unable to open block archive directory `{}`",
            output_spec.c_str());
    }

    monad_vbuf_writer_options exec_event_writer_options;
    monad_vbuf_writer_options exec_seqno_index_writer_options;

    init_vbuf_writer_options(
        options->vbuf_segment_shift,
        options->event_zstd_level,
        &exec_event_writer_options);
    init_vbuf_writer_options(
        options->vbuf_segment_shift,
        options->seqno_zstd_level,
        &exec_seqno_index_writer_options);

    BC_CHECK(monad_bcap_builder_create(
        &block_builder,
        &exec_event_writer_options,
        &exec_seqno_index_writer_options));
    BC_CHECK(monad_bcap_finalize_tracker_create(&finalize_tracker));
    BC_CHECK(monad_bcap_block_archive_open(
        &block_archive, output_fd, output_spec.c_str()));
    (void)close(output_fd);

    // For recordtrace, if no explicit start sequence number is specified, we
    // set it to most recently executed proposed block
    auto &opt_begin_seqno = exec_event_source.opt_begin_seqno;
    if (!opt_begin_seqno &&
        exec_event_source.source_file->get_type() ==
            EventSourceFile::Type::EventRing &&
        exec_event_source.source_file->is_interactive()) {
        opt_begin_seqno = SequenceNumberSpec{
            .type = SequenceNumberSpec::Type::ConsensusEvent,
            .consensus_event = {.consensus_type = MONAD_EXEC_BLOCK_START}};
    }
    exec_event_source.init_iterator(&iter);
    size_t not_ready_count = 0;
    bool exec_ring_is_live = true;

    while (g_should_exit == 0 && exec_ring_is_live) {
        using enum EventIteratorResult;

        if (monad_bcap_proposal const *p =
                monad_bcap_builder_get_current_proposal(block_builder)) {
            auto const *const bs = static_cast<BlockState *>(p->user);
            for (TraceEventSourceState *state : active_trace_sources) {
                if (!state->finished) {
                    drain_trace_source(state, bs->max_txn_flow_seqno);
                }
            }
        }

        monad_event_descriptor event;
        std::byte const *payload;
        switch (iter.next(&event, &payload)) {
        case Error:
            errx_f(
                EX_SOFTWARE,
                "EventIterator::next error {} -- {}",
                iter.error_code,
                iter.last_error_msg);

        case AfterBegin:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after begin seqno {};"
                "events missing",
                event.seqno,
                *iter.begin_seqno);

        case AfterEnd:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after end seqno {}; "
                "did a gap occur?",
                event.seqno,
                *iter.end_seqno);

        case End:
            exec_ring_is_live = false;
            continue;

        case NotReady:
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                exec_ring_is_live =
                    !exec_event_source.source_file->is_finalized();
            }
            [[fallthrough]];
        case Skipped:
            continue;

        case Gap:
            // TODO(ken): finalize the writer
            errx_f(
                EX_SOFTWARE,
                "ERROR: event gap from {} -> {}, record is destroyed",
                iter.get_last_read_seqno(),
                iter.get_last_written_seqno());

        case Success:
            // TODO(ken): failure cases are the same for gap; they don't
            //   exit, do prepare and/or recover
            // Handled in the main body of the loop
            not_ready_count = 0;
            break;
        }

        monad_bcap_append_result append_result;
        monad_bcap_proposal *proposal;

        // Try to append the event to the block builder; we must always call
        // this function even for events we know aren't recorded, since the
        // block builder checks for sequence number gaps internally
        BC_CHECK(monad_bcap_builder_append_event(
            block_builder, &event, payload, &append_result, &proposal));

        if (event.event_type == MONAD_EXEC_BLOCK_START &&
            event.content_ext[2] != 0 && evm_trace_source_state != nullptr) {
            // XXX: eventually extend this to the other tracers somehow, we're
            // stashing this in a weird place just to make this work at the
            // moment. This doesn't belong in BLOCK_START and needs to be
            // extended to the db tracer
            evm_trace_source_state->iter.set_seqno(
                event.content_ext[MONAD_FLOW_ACCOUNT_INDEX]);

            auto const *const block_start =
                reinterpret_cast<monad_exec_block_start const *>(payload);
            BlockState *const bs = new BlockState{
                .max_txn_flow_seqno = 0,
                .txn_count = block_start->eth_block_input.txn_count,
            };
            if (!iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload expired for event {}", event.seqno);
            }
            MONAD_ASSERT(proposal != nullptr);
            proposal->user = bs;
            active_trace_sources.emplace(evm_trace_source_state);
        }
        if (append_result == MONAD_BCAP_PROPOSAL_APPENDED &&
            event.event_type == MONAD_EXEC_TXN_PERF_EVM_ENTER &&
            proposal->user != nullptr) {
            // Allow bulk reads up to this linked sequence number
            auto *const bs = static_cast<BlockState *>(proposal->user);
            bs->max_txn_flow_seqno = event.seqno;
        }

        if (event.event_type == MONAD_EXEC_BLOCK_FINALIZED) {
            monad_bcap_proposal_list abandon_chain;
            auto const block_tag =
                *reinterpret_cast<monad_exec_block_tag const *>(payload);
            if (!iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload expired for event {}", event.seqno);
            }
            BC_CHECK(monad_bcap_finalize_tracker_update(
                finalize_tracker, &block_tag, &proposal, &abandon_chain));
            if (proposal == nullptr) {
                // Finalization for a block we never saw; this is near the
                // beginning of the sequence
                continue;
            }

            // TODO(ken): move writer infrastructure to a different thread,
            //  do compression and sync there
            BC_CHECK(monad_bcap_block_archive_add_block(
                block_archive,
                proposal,
                CreateMode | S_IXUSR | S_IXGRP | S_IXOTH,
                CreateMode));
            if (auto *const bs = static_cast<BlockState *>(proposal->user)) {
                record_capture_map(
                    block_archive, proposal->block_tag.block_number, bs);
            }
            delete static_cast<BlockState *>(proposal->user);
            monad_bcap_proposal_free(proposal);

            while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
                TAILQ_REMOVE(&abandon_chain, proposal, entry);
                delete static_cast<BlockState *>(proposal->user);
                monad_bcap_proposal_free(proposal);
            }
            continue;
        }

        if (append_result == MONAD_BCAP_OUTSIDE_BLOCK_SCOPE) {
            continue;
        }

        if (!iter.check_payload(&event)) {
            errx_f(EX_SOFTWARE, "payload expired for event {}", event.seqno);
        }

        if (append_result == MONAD_BCAP_PROPOSAL_ABORTED) {
            if (event.event_type == MONAD_EXEC_BLOCK_REJECT) {
                continue;
            }
            MONAD_ASSERT_PRINTF(
                event.event_type == MONAD_EXEC_EVM_ERROR,
                "proposal aborted on unexpected event type %s [%hu]",
                g_monad_exec_event_metadata[event.event_type].c_name,
                event.event_type);
            uint32_t const code = *reinterpret_cast<uint32_t const *>(payload);
            errx_f(EX_SOFTWARE, "cannot record after EVM error {}", code);
        }

        if (append_result == MONAD_BCAP_PROPOSAL_FINISHED) {
            MONAD_DEBUG_ASSERT(proposal != nullptr);
            for (TraceEventSourceState *state : active_trace_sources) {
                auto *const bs = static_cast<BlockState *>(proposal->user);
                flush_to_capture_map(state, bs);
            }
            monad_bcap_finalize_tracker_add_proposal(
                finalize_tracker, proposal);
        }
    }

    monad_bcap_builder_destroy(block_builder);
    monad_bcap_finalize_tracker_destroy(finalize_tracker);
    monad_bcap_block_archive_close(block_archive);
}
