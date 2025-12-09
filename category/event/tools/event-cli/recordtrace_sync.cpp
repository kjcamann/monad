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
#include "metadata.hpp"
#include "options.hpp"
#include "recordtrace.hpp"
#include "util.hpp"

#include <cstdint>
#include <expected>
#include <print>
#include <thread>
#include <utility>

#include <fcntl.h>
#include <pthread.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/blockcap.h>

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

inline void EVCAP_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "evcap library error -- {}",
            monad_evcap_writer_get_last_error());
    }
}

template <typename T>
inline T unwrap_or_err(std::expected<T, std::string> ex)
{
    if (!ex) {
        errx_f(EX_SOFTWARE, "{}", ex.error());
    }
    return std::move(ex).value();
}

void record_trace_map(
    monad_evcap_writer *ecw, TracedProposal *tp, ZSTD_CCtx *event_zstd_cctx,
    ZSTD_CCtx *seqno_index_zstd_cctx)
{
    uint64_t const block_number = tp->proposal->block_tag.block_number;
    for (auto &&[content_type, block_trace] : tp->trace_map) {
        monad_evcap_dynamic_section *dynsec;
        monad_evcap_section_desc const *schema_sd;
        monad_evcap_section_desc *event_sd;

        MetadataTableEntry const &entry =
            MetadataTable[std::to_underlying(content_type)];
        EVCAP_CHECK(monad_evcap_writer_add_schema_section(
            ecw, content_type, *entry.schema_hash, &schema_sd));
        EVCAP_CHECK(monad_evcap_writer_dynsec_open(ecw, &dynsec, &event_sd));

        event_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;
        event_sd->compression = event_zstd_cctx != nullptr
                                    ? MONAD_EVCAP_COMPRESSION_ZSTD_SINGLE_PASS
                                    : MONAD_EVCAP_COMPRESSION_NONE;
        event_sd->content_length = block_trace->event_vbufs.vbuf_length;
        event_sd->event_bundle.schema_desc_offset =
            schema_sd->descriptor_offset;
        event_sd->event_bundle.event_count = block_trace->event_count;
        event_sd->event_bundle.start_seqno = block_trace->start_seqno;
        event_sd->event_bundle.block_number = block_number;

        EVCAP_CHECK(
            monad_evcap_writer_dynsec_sync_vbuf_chain(
                ecw, dynsec, &block_trace->event_vbufs, event_zstd_cctx) >= 0
                ? 0
                : -1);
        EVCAP_CHECK(monad_evcap_writer_dynsec_close(ecw, dynsec));

        if (block_trace->seqno_vbufs.segment_count > 0) {
            monad_evcap_section_desc *seqno_index_sd;
            EVCAP_CHECK(
                monad_evcap_writer_dynsec_open(ecw, &dynsec, &seqno_index_sd));
            seqno_index_sd->type = MONAD_EVCAP_SECTION_SEQNO_INDEX;
            seqno_index_sd->compression =
                seqno_index_zstd_cctx != nullptr
                    ? MONAD_EVCAP_COMPRESSION_ZSTD_SINGLE_PASS
                    : MONAD_EVCAP_COMPRESSION_NONE;
            seqno_index_sd->content_length =
                block_trace->seqno_vbufs.vbuf_length;
            seqno_index_sd->seqno_index.event_bundle_desc_offset =
                event_sd->descriptor_offset;

            event_sd->event_bundle.seqno_index_desc_offset =
                seqno_index_sd->descriptor_offset;

            EVCAP_CHECK(
                monad_evcap_writer_dynsec_sync_vbuf_chain(
                    ecw,
                    dynsec,
                    &block_trace->seqno_vbufs,
                    seqno_index_zstd_cctx) >= 0
                    ? 0
                    : -1);
            EVCAP_CHECK(monad_evcap_writer_dynsec_close(ecw, dynsec));
        }
    }
}

} // End of anonymous namespace

void recordtrace_sync(
    std::stop_token stop_token, RecordTraceContext const *ctx,
    RecordTraceState *rts)
{
    constexpr mode_t CreateMode =
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    monad_bcap_archive *block_archive;

    ZSTD_CCtx *const event_zstd_cctx =
        unwrap_or_err(create_zstd_cctx(ctx->options->event_zstd_level));
    ZSTD_CCtx *const seqno_index_zstd_cctx =
        unwrap_or_err(create_zstd_cctx(ctx->options->seqno_zstd_level));

    BC_CHECK(monad_bcap_archive_open(
        &block_archive, ctx->output_fd, ctx->output_spec.c_str()));

    rts->start_latch->arrive_and_wait();
    while (!stop_token.stop_requested()) {
        pthread_spin_lock(&rts->sync_proposal_lock);
        TracedProposal *const tp = TAILQ_FIRST(&rts->sync_proposal_queue);
        if (tp == nullptr) {
            __builtin_ia32_pause();
            pthread_spin_unlock(&rts->sync_proposal_lock);
            continue;
        }
        TAILQ_REMOVE(&rts->sync_proposal_queue, tp, entry);
        pthread_spin_unlock(&rts->sync_proposal_lock);
        std::println(
            stderr,
            "S: dequeued traced proposal {}",
            tp->proposal->block_tag.block_number);

        if (tp->proposal->is_finalized) {
            char path_buf[32];
            monad_evcap_writer *evcap_writer;
            monad_evcap_section_desc const *exec_schema_sd;
            uint64_t const block_number = tp->proposal->block_tag.block_number;

            BC_CHECK(monad_bcap_archive_open_block_writer(
                block_archive,
                block_number,
                CreateMode | S_IXUSR | S_IXGRP | S_IXOTH,
                CreateMode,
                path_buf,
                sizeof path_buf,
                nullptr,
                &evcap_writer,
                &exec_schema_sd));

            // Write the block capture proposal into the file
            BC_CHECK(monad_bcap_write_proposal_evcap_ext(
                evcap_writer,
                tp->proposal,
                exec_schema_sd,
                nullptr,
                nullptr,
                event_zstd_cctx,
                seqno_index_zstd_cctx));

            record_trace_map(
                evcap_writer, tp, event_zstd_cctx, seqno_index_zstd_cctx);

            BC_CHECK(monad_bcap_archive_close_block_writer(
                block_archive, block_number, evcap_writer, path_buf));
        }
        for (auto &&[_, block_trace] : tp->trace_map) {
            monad_vbuf_chain_free(&block_trace->event_vbufs);
            monad_vbuf_chain_free(&block_trace->seqno_vbufs);
            delete block_trace;
        }
        std::println(
            stderr,
            "S: finished traced proposal {}",
            tp->proposal->block_tag.block_number);
        monad_bcap_proposal_free(tp->proposal);
        delete tp;
    }

    ZSTD_freeCCtx(event_zstd_cctx);
    ZSTD_freeCCtx(seqno_index_zstd_cctx);
    monad_bcap_archive_close(block_archive);
}
