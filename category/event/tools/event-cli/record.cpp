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
#include "eventsource.hpp"
#include "options.hpp"
#include "util.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <print>
#include <span>
#include <string>

#include <fcntl.h>
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

} // end of anonymous namespace

void record_thread_main(std::span<Command *const> commands)
{
    MONAD_ASSERT(size(commands) == 1);
    constexpr mode_t CreateMode =
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    EventSource::Iterator iter;
    Command *const command = commands[0];
    EventSource *const event_source = command->event_sources[0];

    monad_evcap_writer *evcap_writer;
    monad_evcap_dynamic_section *dyn_sec;
    monad_evcap_section_desc *event_bundle_sd;
    monad_vbuf_writer *event_vbuf_writer;
    monad_vbuf_writer *seqno_index_vbuf_writer = nullptr;

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
    EVCAP_CHECK(monad_evcap_writer_create(&evcap_writer, fd));
    (void)close(fd);
    EventSource::Type const source_type = event_source->get_type();
    if (source_type == EventSource::Type::EventRing) {
        auto const *const mr =
            static_cast<MappedEventRing const *>(event_source);
        monad_event_ring_header const *const header = mr->get_header();
        EVCAP_CHECK(monad_evcap_writer_add_schema_section(
            evcap_writer, header->content_type, header->schema_hash));
    }
    else {
        MONAD_ASSERT(source_type == EventSource::Type::CaptureFile);
        auto const *const capture =
            static_cast<EventCaptureFile const *>(event_source);
        copy_all_schema_sections(
            evcap_writer, capture, MONAD_EVENT_CONTENT_TYPE_NONE);
    }
    EVCAP_CHECK(monad_evcap_writer_dyn_sec_open(
        evcap_writer, &dyn_sec, &event_bundle_sd));
    event_bundle_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;

    monad_vbuf_writer_options const event_vbuf_writer_options = {
        .segment_shift = options->vbuf_segment_shift,
        .memfd_flags = 0,
        .zstd_cctx = nullptr,
    };
    VBUF_CHECK(monad_vbuf_writer_create(
        &event_vbuf_writer, &event_vbuf_writer_options));
    if (!options->no_seqno_index) {
        monad_vbuf_writer_options const seqno_writer_options = {
            .segment_shift = options->vbuf_segment_shift,
            .memfd_flags = 0,
            .zstd_cctx =
                options->seqno_zstd_level ? ZSTD_createCCtx() : nullptr};
        if (seqno_writer_options.zstd_cctx) {
            size_t const r = ZSTD_CCtx_setParameter(
                seqno_writer_options.zstd_cctx,
                ZSTD_c_compressionLevel,
                *options->seqno_zstd_level);
            if (ZSTD_isError(r)) {
                errx_f(
                    EX_SOFTWARE,
                    "zstd set compression error: {}",
                    ZSTD_getErrorName(r));
            }
        }
        VBUF_CHECK(monad_vbuf_writer_create(
            &seqno_index_vbuf_writer, &seqno_writer_options));
    }

    CommonCommandOptions const &cc_opts = options->common_options;
    event_source->init_iterator(&iter, cc_opts.start_seqno, cc_opts.end_seqno);
    size_t not_ready_count = 0;
    bool ring_is_live = true;
    monad_vbuf_chain event_vbufs;
    monad_vbuf_chain seqno_vbufs;
    monad_vbuf_chain_init(&event_vbufs);
    monad_vbuf_chain_init(&seqno_vbufs);

    while (g_should_exit == 0 && ring_is_live) {
        using enum EventIteratorResult;

        monad_event_content_type content_type;
        monad_event_descriptor event;
        std::byte const *payload;

        switch (iter.next(&content_type, &event, &payload)) {
        case AfterStart:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after start seqno {};"
                "events missing",
                event.seqno,
                *iter.start_seqno);

        case AfterEnd:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after end seqno {}; "
                "did a gap occur?",
                event.seqno,
                *iter.end_seqno);

        case Finished:
            ring_is_live = false;
            continue;

        case NotReady:
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                ring_is_live = !event_source->is_finalized();
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
            if (seqno_index_vbuf_writer != nullptr) {
                size_t const cur_offset = monad_round_size_to_align(
                    monad_vbuf_writer_get_offset(event_vbuf_writer),
                    alignof(monad_event_descriptor));
                VBUF_CHECK(monad_vbuf_writer_memcpy(
                    seqno_index_vbuf_writer,
                    &cur_offset,
                    sizeof cur_offset,
                    1,
                    &seqno_vbufs));
            }
            EVCAP_CHECK(monad_evcap_vbuf_append_event(
                event_vbuf_writer,
                content_type,
                &event,
                payload,
                &event_vbufs));
            if (!iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload expired for event {}", event.seqno);
            }
            if (event_bundle_sd->event_bundle.event_count++ == 0) {
                event_bundle_sd->event_bundle.start_seqno = event.seqno;
            }
            EVCAP_CHECK(
                monad_evcap_writer_dyn_sec_sync_vbuf_chain(
                    evcap_writer, dyn_sec, &event_vbufs) >= 0
                    ? 0
                    : -1);
            monad_vbuf_chain_free(&event_vbufs);
            break;
        }
    }

    VBUF_CHECK(monad_vbuf_writer_destroy(event_vbuf_writer, &event_vbufs));
    EVCAP_CHECK(
        monad_evcap_writer_dyn_sec_sync_vbuf_chain(
            evcap_writer, dyn_sec, &event_vbufs) >= 0
            ? 0
            : -1);
    monad_vbuf_chain_free(&event_vbufs);
    EVCAP_CHECK(monad_evcap_writer_dyn_sec_close(evcap_writer, dyn_sec));
    if (seqno_index_vbuf_writer != nullptr) {
        size_t uncompressed_length;
        VBUF_CHECK(monad_vbuf_writer_reset(
            seqno_index_vbuf_writer, &seqno_vbufs, &uncompressed_length));
        EVCAP_CHECK(monad_evcap_writer_commit_seqno_index(
            evcap_writer,
            &seqno_vbufs,
            options->seqno_zstd_level.has_value()
                ? MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING
                : MONAD_EVCAP_COMPRESSION_NONE,
            uncompressed_length,
            event_bundle_sd));
    }
    monad_evcap_writer_destroy(evcap_writer);
    if (options->print_backpressure_stats) {
        print_histogram(g_backpressure_histogram, stderr);
    }
}
