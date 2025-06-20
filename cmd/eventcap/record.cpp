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
#include "metadata.hpp"
#include "options.hpp"
#include "util.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_ring.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>

#include <zstd.h>

namespace
{

constexpr unsigned HistogramSampleShift = 10;
constexpr unsigned HistogramPrintShift = 30;
constexpr uint64_t HistogramSampleMask = (1UL << HistogramSampleShift) - 1;
constexpr uint64_t HistogramPrintMask = (1UL << HistogramPrintShift) - 1;
constexpr size_t BackpressureHistogramSize = 30;
uint64_t g_backpressure_histogram[BackpressureHistogramSize] = {};

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

void print_histogram(std::span<uint64_t> histogram, std::FILE *out)
{
    for (size_t b = 0; uint64_t const v : histogram) {
        std::println(out, "{:7} - {:7} {}", 1UL << b, (1UL << (b + 1)) - 1, v);
        ++b;
    }
}

void safe_write(int fd, void *buf, size_t length)
{
    ssize_t n_written;
    do {
        n_written = write(fd, buf, length);
        if (n_written == -1) {
            err_f(EX_OSERR, "unable write {} bytes to fd={}", length, fd);
        }
        buf = static_cast<std::byte *>(buf) + static_cast<size_t>(n_written);
        length -= static_cast<size_t>(n_written);
    }
    while (length > 0);
}

struct event_vbuf
{
    monad_vbuf_chain vbuf_chain;
    monad_vbuf_writer *vbuf_writer;
    monad_evcap_dynamic_section *dynsec;
    monad_evcap_section_desc *event_bundle_sd;
    std::unique_ptr<std::byte[]> zstd_buf;
    size_t zstd_buf_size;
    ZSTD_CCtx *zstd_cctx;
};

struct seqno_index_vbuf
{
    monad_vbuf_chain vbuf_chain;
    monad_vbuf_writer *vbuf_writer;
    int memfd;
    std::unique_ptr<std::byte[]> zstd_buf;
    size_t zstd_buf_size;
    size_t content_length;
    size_t file_length;
    ZSTD_CCtx *zstd_cctx;
};

void init_event_vbuf(
    monad_evcap_writer *evcap_writer, monad_evcap_section_desc const *schema_sd,
    monad_vbuf_mmap_allocator *mmap_allocator,
    RecordCommandOptions const *options, event_vbuf *evb)
{
    monad_vbuf_chain_init(&evb->vbuf_chain);
    VBUF_CHECK(monad_vbuf_writer_create(
        &evb->vbuf_writer, (monad_vbuf_segment_allocator *)mmap_allocator));
    EVCAP_CHECK(monad_evcap_writer_dynsec_open(
        evcap_writer, &evb->dynsec, &evb->event_bundle_sd));
    evb->event_bundle_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;
    evb->event_bundle_sd->event_bundle.schema_desc_offset =
        schema_sd->descriptor_offset;
    evb->zstd_cctx = unwrap_or_err(create_zstd_cctx(options->event_zstd_level));
    if (evb->zstd_cctx) {
        evb->event_bundle_sd->compression =
            MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING;
        evb->zstd_buf_size = ZSTD_CStreamOutSize();
        evb->zstd_buf = std::make_unique<std::byte[]>(evb->zstd_buf_size);
    }
    else {
        evb->event_bundle_sd->compression = MONAD_EVCAP_COMPRESSION_NONE;
        evb->zstd_buf_size = 0;
    }
}

void drain_event_vbuf(
    monad_evcap_writer *evcap_writer, event_vbuf *evb,
    ZSTD_EndDirective end_directive)
{
    monad_vbuf_segment *vs;

    while ((vs = TAILQ_FIRST(&evb->vbuf_chain.segments)) != nullptr) {
        monad_vbuf_chain_remove(&evb->vbuf_chain, vs);
        if (evb->zstd_cctx == nullptr) {
            // No compression
            EVCAP_CHECK(
                monad_evcap_writer_dynsec_write(
                    evcap_writer, evb->dynsec, vs->map_base, vs->written) >= 0
                    ? 0
                    : -1);
        }
        else {
            ZSTD_inBuffer in_buf = {
                .src = vs->map_base, .size = vs->written, .pos = 0};
            bool finished;
            do {
                ZSTD_outBuffer out_buf = {
                    .dst = evb->zstd_buf.get(),
                    .size = evb->zstd_buf_size,
                    .pos = 0};
                size_t const zbuf_remaining = ZSTD_compressStream2(
                    evb->zstd_cctx, &out_buf, &in_buf, end_directive);
                if (ZSTD_isError(zbuf_remaining)) {
                    errx_f(
                        EX_SOFTWARE,
                        "ZSTD_compressStream2 failed in vbuf: %s",
                        ZSTD_getErrorName(zbuf_remaining));
                }
                EVCAP_CHECK(
                    monad_evcap_writer_dynsec_write(
                        evcap_writer, evb->dynsec, out_buf.dst, out_buf.pos) >=
                            0
                        ? 0
                        : -1);
                finished = end_directive == ZSTD_e_end
                               ? zbuf_remaining == 0
                               : in_buf.pos == in_buf.size;
            }
            while (!finished);
        }
        evb->event_bundle_sd->content_length += vs->written;
        monad_vbuf_segment_free(vs);
    }
}

void cleanup_event_vbuf(monad_evcap_writer *evcap_writer, event_vbuf *evb)
{
    monad_vbuf_writer_flush(evb->vbuf_writer, &evb->vbuf_chain);
    drain_event_vbuf(evcap_writer, evb, ZSTD_e_end);
    monad_vbuf_writer_destroy(evb->vbuf_writer, &evb->vbuf_chain);
    MONAD_ASSERT(evb->vbuf_chain.segment_count == 0);
    monad_vbuf_chain_free(&evb->vbuf_chain);
    EVCAP_CHECK(monad_evcap_writer_dynsec_close(evcap_writer, evb->dynsec));
    ZSTD_freeCCtx(evb->zstd_cctx);
}

void init_seqno_index_vbuf(
    monad_vbuf_mmap_allocator *mmap_allocator,
    RecordCommandOptions const *options, seqno_index_vbuf *svb)
{
    monad_vbuf_chain_init(&svb->vbuf_chain);
    VBUF_CHECK(monad_vbuf_writer_create(
        &svb->vbuf_writer, (monad_vbuf_segment_allocator *)mmap_allocator));
    svb->memfd = memfd_create("seqno-index", 0);
    if (svb->memfd == -1) {
        err_f(EX_OSERR, "unable to memfd_create(2) seqno index");
    }
    svb->zstd_cctx = unwrap_or_err(create_zstd_cctx(options->seqno_zstd_level));
    if (svb->zstd_cctx) {
        svb->zstd_buf_size = ZSTD_CStreamOutSize();
        svb->zstd_buf = std::make_unique<std::byte[]>(svb->zstd_buf_size);
    }
    else {
        svb->zstd_buf_size = 0;
    }
}

void drain_seqno_index_vbuf(
    seqno_index_vbuf *svb, ZSTD_EndDirective end_directive)
{
    monad_vbuf_segment *vs;

    while ((vs = TAILQ_FIRST(&svb->vbuf_chain.segments)) != nullptr) {
        monad_vbuf_chain_remove(&svb->vbuf_chain, vs);
        if (svb->zstd_cctx == nullptr) {
            // No compression
            safe_write(svb->memfd, vs->map_base, vs->written);
            svb->file_length += vs->written;
        }
        else {
            ZSTD_inBuffer in_buf = {
                .src = vs->map_base, .size = vs->written, .pos = 0};
            bool finished;
            do {
                ZSTD_outBuffer out_buf = {
                    .dst = svb->zstd_buf.get(),
                    .size = svb->zstd_buf_size,
                    .pos = 0};
                size_t const zbuf_remaining = ZSTD_compressStream2(
                    svb->zstd_cctx, &out_buf, &in_buf, end_directive);
                if (ZSTD_isError(zbuf_remaining)) {
                    errx_f(
                        EX_SOFTWARE,
                        "ZSTD_compressStream2 failed in vbuf: %s",
                        ZSTD_getErrorName(zbuf_remaining));
                }
                safe_write(svb->memfd, out_buf.dst, out_buf.pos);
                svb->file_length += out_buf.pos;
                finished = end_directive == ZSTD_e_end
                               ? zbuf_remaining == 0
                               : in_buf.pos == in_buf.size;
            }
            while (!finished);
        }
        svb->content_length += vs->written;
        monad_vbuf_segment_free(vs);
    }
}

void cleanup_seqno_index_vbuf(
    monad_evcap_writer *evcap_writer, monad_evcap_section_desc *event_bundle_sd,
    seqno_index_vbuf *svb)
{
    monad_vbuf_writer_flush(svb->vbuf_writer, &svb->vbuf_chain);
    drain_seqno_index_vbuf(svb, ZSTD_e_end);
    monad_vbuf_writer_destroy(svb->vbuf_writer, &svb->vbuf_chain);
    MONAD_ASSERT(svb->vbuf_chain.segment_count == 0);
    monad_vbuf_chain_free(&svb->vbuf_chain);

    void *const map_base =
        mmap(nullptr, svb->file_length, PROT_READ, MAP_PRIVATE, svb->memfd, 0);
    if (map_base == MAP_FAILED) {
        err_f(EX_OSERR, "unable to mmap seqno index memfd for write");
    }

    monad_evcap_section_desc *seqno_index_sd;
    EVCAP_CHECK(
        monad_evcap_writer_new_section(
            evcap_writer, map_base, svb->file_length, &seqno_index_sd) >= 0
            ? 0
            : -1);
    munmap(map_base, svb->file_length);

    seqno_index_sd->type = MONAD_EVCAP_SECTION_SEQNO_INDEX;
    seqno_index_sd->compression = svb->zstd_cctx
                                      ? MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING
                                      : MONAD_EVCAP_COMPRESSION_NONE;
    seqno_index_sd->content_length = svb->content_length;
    seqno_index_sd->seqno_index.event_bundle_desc_offset =
        event_bundle_sd->descriptor_offset;

    event_bundle_sd->event_bundle.seqno_index_desc_offset =
        seqno_index_sd->descriptor_offset;

    ZSTD_freeCCtx(svb->zstd_cctx);
}

} // end of anonymous namespace

void record_thread_main(std::span<Command *const> commands)
{
    MONAD_ASSERT(size(commands) == 1);
    constexpr mode_t CreateMode =
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    EventIterator iter;
    Command *const command = commands[0];
    EventSourceSpec const &event_source = command->event_sources[0];

    monad_vbuf_mmap_allocator *vbuf_mmap_allocator;
    monad_evcap_writer *evcap_writer;
    monad_evcap_section_desc const *schema_sd;
    event_vbuf event_vb{};
    std::optional<seqno_index_vbuf> opt_seqno_index_vb;

    auto const *const options = command->get_options<RecordCommandOptions>();
    std::string const &output_spec = options->common_options.output_spec;
    int const fd =
        open(output_spec.c_str(), O_RDWR | O_CREAT | O_TRUNC, CreateMode);
    if (fd == -1) {
        err_f(
            EX_OSERR,
            "unable to open fd to record output file `{}`",
            output_spec.c_str());
    }
    monad_evcap_writer_create_options const evcap_writer_options = {
        .sectab_entries_shift = 0, .append = false};
    EVCAP_CHECK(
        monad_evcap_writer_create(&evcap_writer, fd, &evcap_writer_options));
    (void)close(fd);

    monad_event_content_type const content_type =
        event_source.get_content_type();

    EVCAP_CHECK(monad_evcap_writer_add_schema_section(
        evcap_writer,
        content_type,
        *MetadataTable[content_type].schema_hash,
        &schema_sd));

    VBUF_CHECK(monad_vbuf_mmap_allocator_create(
        &vbuf_mmap_allocator, options->vbuf_segment_shift, MAP_PRIVATE));

    // vbuf initialization
    init_event_vbuf(
        evcap_writer, schema_sd, vbuf_mmap_allocator, options, &event_vb);
    if (!options->no_seqno_index) {
        init_seqno_index_vbuf(
            vbuf_mmap_allocator, options, &opt_seqno_index_vb.emplace());
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
            // TODO(ken): this corrupts some of the history, perhaps we could
            //   try to recover, but for now we don't
            errx_f(
                EX_SOFTWARE,
                "ERROR: event gap from {} -> {}, record is destroyed",
                iter.get_last_read_seqno(),
                iter.get_last_written_seqno());

        case Success:
            if (options->print_backpressure_stats &&
                ((event.seqno + 1) & HistogramSampleMask) == 0) [[unlikely]] {
                uint64_t const available_events =
                    iter.get_last_written_seqno() - event.seqno;
                unsigned bp_bucket =
                    static_cast<unsigned>(std::bit_width(available_events));
                if (bp_bucket >= std::size(g_backpressure_histogram)) {
                    bp_bucket = std::size(g_backpressure_histogram) - 1;
                }
                ++g_backpressure_histogram[bp_bucket];
                if (((event.seqno + 1) & HistogramPrintMask) == 0)
                    [[unlikely]] {
                    print_histogram(g_backpressure_histogram, stderr);
                }
            }
            not_ready_count = 0;
            if (opt_seqno_index_vb) {
                seqno_index_vbuf &svb = *opt_seqno_index_vb;
                size_t const cur_event_offset = monad_round_size_to_align(
                    monad_vbuf_writer_get_offset(event_vb.vbuf_writer),
                    alignof(monad_event_descriptor));
                VBUF_CHECK(monad_vbuf_writer_memcpy(
                    svb.vbuf_writer,
                    &cur_event_offset,
                    sizeof cur_event_offset,
                    1,
                    &svb.vbuf_chain));
                if (svb.vbuf_chain.segment_count > 0) {
                    drain_seqno_index_vbuf(&svb, ZSTD_e_continue);
                }
            }
            VBUF_CHECK(monad_evcap_vbuf_append_event(
                event_vb.vbuf_writer, &event, payload, &event_vb.vbuf_chain));
            if (!iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload expired for event {}", event.seqno);
            }
            if (event_vb.event_bundle_sd->event_bundle.event_count++ == 0) {
                event_vb.event_bundle_sd->event_bundle.start_seqno =
                    event.seqno;
            }
            if (event_vb.vbuf_chain.segment_count > 0) {
                drain_event_vbuf(evcap_writer, &event_vb, ZSTD_e_continue);
            }
            break;
        }
    }

    cleanup_event_vbuf(evcap_writer, &event_vb);
    if (opt_seqno_index_vb) {
        cleanup_seqno_index_vbuf(
            evcap_writer,
            event_vb.event_bundle_sd,
            std::addressof(*opt_seqno_index_vb));
    }
    monad_evcap_writer_destroy(evcap_writer);
    monad_vbuf_mmap_allocator_destroy(vbuf_mmap_allocator);
    if (options->print_backpressure_stats) {
        print_histogram(g_backpressure_histogram, stderr);
    }
}
