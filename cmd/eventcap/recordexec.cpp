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

#include "err_cxx.hpp"
#include "eventcap.hpp"
#include "file.hpp"
#include "iterator.hpp"
#include "options.hpp"
#include "util.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>
#include <string>

#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/event_ring.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

#include <zstd.h>

namespace
{

inline void BC_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "bcap library error -- {}",
            monad_bcap_get_last_error());
    }
}

} // End of anonymous namespace

void recordexec_thread_main(std::span<Command *const> commands)
{
    MONAD_ASSERT(size(commands) == 1);

    constexpr mode_t CreateMode =
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    EventIterator iter;
    Command *const command = commands[0];
    EventSourceSpec &event_source = command->event_sources[0];

    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    monad_bcap_pack_writer *pack_writer;
    monad_bcap_block_archive *archive_writer;

    auto const *const options =
        command->get_options<RecordExecCommandOptions>();
    std::string const &output_spec = options->common_options.output_spec;

    int output_fd;
    if (options->block_format == BlockRecordFormat::Archive) {
        // Output is underneath a top-level archive directory which must
        // already exist
        output_fd = open(output_spec.c_str(), O_DIRECTORY | O_PATH);
        if (output_fd == -1) {
            err_f(
                EX_OSERR,
                "unable to open block archive directory `{}`",
                output_spec.c_str());
        }
    }
    else {
        // Output is in a single file
        MONAD_ASSERT(options->block_format == BlockRecordFormat::Packed);
        output_fd =
            open(output_spec.c_str(), O_RDWR | O_CREAT | O_TRUNC, CreateMode);
        if (output_fd == -1) {
            err_f(
                EX_OSERR,
                "unable to open record output file `{}`",
                output_spec.c_str());
        }
    }

    monad_vbuf_writer_options const event_writer_options = {
        .segment_shift = options->vbuf_segment_shift,
        .memfd_flags = 0,
        .zstd_cctx = options->event_zstd_level ? ZSTD_createCCtx() : nullptr};
    if (event_writer_options.zstd_cctx) {
        size_t const r = ZSTD_CCtx_setParameter(
            event_writer_options.zstd_cctx,
            ZSTD_c_compressionLevel,
            *options->event_zstd_level);
        if (ZSTD_isError(r)) {
            errx_f(
                EX_SOFTWARE,
                "zstd set compression error: {}",
                ZSTD_getErrorName(r));
        }
    }

    monad_vbuf_writer_options const seqno_index_writer_options = {
        .segment_shift = options->vbuf_segment_shift,
        .memfd_flags = 0,
        .zstd_cctx = options->seqno_zstd_level ? ZSTD_createCCtx() : nullptr};
    if (seqno_index_writer_options.zstd_cctx) {
        size_t const r = ZSTD_CCtx_setParameter(
            seqno_index_writer_options.zstd_cctx,
            ZSTD_c_compressionLevel,
            *options->seqno_zstd_level);
        if (ZSTD_isError(r)) {
            errx_f(
                EX_SOFTWARE,
                "zstd set compression error: {}",
                ZSTD_getErrorName(r));
        }
    }

    BC_CHECK(monad_bcap_builder_create(
        &block_builder, &event_writer_options, &seqno_index_writer_options));
    BC_CHECK(monad_bcap_finalize_tracker_create(&finalize_tracker));
    if (options->block_format == BlockRecordFormat::Archive) {
        BC_CHECK(monad_bcap_block_archive_open(
            &archive_writer, output_fd, output_spec.c_str()));
        pack_writer = nullptr;
    }
    else {
        BC_CHECK(monad_bcap_pack_writer_create(&pack_writer, output_fd));
        archive_writer = nullptr;
    }
    (void)close(output_fd);

    // For recordexec, if no explicit start sequence number is specified, we
    // set it to most recently executed proposed block
    auto &opt_begin_seqno = event_source.opt_begin_seqno;
    if (!opt_begin_seqno &&
        event_source.source_file->get_type() ==
            EventSourceFile::Type::EventRing &&
        event_source.source_file->is_interactive()) {
        opt_begin_seqno = SequenceNumberSpec{
            .type = SequenceNumberSpec::Type::ConsensusEvent,
            .consensus_event = {.consensus_type = MONAD_EXEC_BLOCK_START}};
    }
    event_source.init_iterator(&iter);
    size_t not_ready_count = 0;
    bool ring_is_live = true;
    while (g_should_exit == 0 && ring_is_live) {
        using enum EventIteratorResult;

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
            ring_is_live = false;
            continue;

        case NotReady:
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                ring_is_live = !event_source.source_file->is_finalized();
            }
            [[fallthrough]];
        case Skipped:
            continue;

        case Gap:
            // TODO(ken): finalize the writer and prepare to recover from the
            //   archive (or do it via a C library we get from Joe?)
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
            if (archive_writer != nullptr) {
                BC_CHECK(monad_bcap_block_archive_add_block(
                    archive_writer,
                    proposal,
                    CreateMode | S_IXUSR | S_IXGRP | S_IXOTH));
            }
            else {
                MONAD_ASSERT(pack_writer != nullptr);
                BC_CHECK(
                    monad_bcap_pack_writer_add_block(pack_writer, proposal));
            }
            monad_bcap_proposal_free(proposal);

            while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
                TAILQ_REMOVE(&abandon_chain, proposal, entry);
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

            // Write the proposed block to the proposals subdirectory
            if (archive_writer != nullptr) {
                BC_CHECK(monad_bcap_block_archive_write_proposal(
                    archive_writer,
                    proposal,
                    CreateMode | S_IXUSR | S_IXGRP | S_IXOTH,
                    CreateMode));
            }

            monad_bcap_finalize_tracker_add_proposal(
                finalize_tracker, proposal);
        }
    }

    monad_bcap_builder_destroy(block_builder);
    monad_bcap_finalize_tracker_destroy(finalize_tracker);
    monad_bcap_block_archive_close(archive_writer);
    monad_bcap_pack_writer_destroy(pack_writer);
}
