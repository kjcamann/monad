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

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <utility>

#include <alloca.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

namespace fs = std::filesystem;

namespace
{

constexpr size_t PAGE_2MB = 1UL << 21;

inline void VBUF_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "vbuf library error -- {}",
            monad_vbuf_writer_get_last_error());
    }
}

struct snapshot_vbuf_state
{
    struct monad_vbuf_writer *writer;
    struct monad_vbuf_chain chain;
};

class SnapshotWriter
{
public:
    explicit SnapshotWriter(
        EventSource const *event_source, uint8_t segment_shift)
        : event_source_{event_source}
        , event_count_{0}
        , last_block_ref_{0}
    {
        struct monad_vbuf_writer_options const vbuf_writer_ops = {
            .segment_shift = segment_shift,
            .memfd_flags = 0,
            .zstd_cctx = nullptr};
        VBUF_CHECK(monad_vbuf_writer_create(
            &descriptor_vbuf_state_.writer, &vbuf_writer_ops));
        VBUF_CHECK(monad_vbuf_writer_create(
            &payload_vbuf_state_.writer, &vbuf_writer_ops));
        monad_vbuf_chain_init(&descriptor_vbuf_state_.chain);
        monad_vbuf_chain_init(&payload_vbuf_state_.chain);

        EventSource::Type const source_type = event_source_->get_type();
        if (source_type == EventSource::Type::EventRing) {
            header_ = *static_cast<MappedEventRing const *>(event_source_)
                           ->get_header();
        }
        else {
            MONAD_ASSERT_PRINTF(
                source_type == EventSource::Type::CaptureFile,
                "do not know how init header from source type %hhu",
                std::to_underlying(source_type));
            EventCaptureFile const *const capture =
                static_cast<EventCaptureFile const *>(event_source_);
            monad_evcap_reader *const evcap_reader = capture->get_reader();
            monad_evcap_section_desc const *sd = nullptr;

            uint8_t const *schema_hash = nullptr;
            while (monad_evcap_reader_next_section(
                evcap_reader, MONAD_EVCAP_SECTION_SCHEMA, &sd)) {
                if (schema_hash != nullptr) {
                    errx_f(
                        EX_CONFIG,
                        "capture file {} contains multiple metadata sections",
                        event_source_->describe());
                }
                memcpy(
                    header_.magic, sd->schema.ring_magic, sizeof header_.magic);
                header_.content_type = sd->schema.content_type;
                schema_hash = sd->schema.schema_hash;
            }
            if (schema_hash == nullptr) {
                errx_f(
                    EX_CONFIG,
                    "capture file {} had no schema section",
                    event_source_->describe());
            }
            memcpy(
                header_.schema_hash, schema_hash, sizeof header_.schema_hash);
            header_.size.context_area_size = 0;
        }
    }

    ~SnapshotWriter()
    {
        for (auto *vs : {&descriptor_vbuf_state_, &payload_vbuf_state_}) {
            monad_vbuf_chain flushed;
            VBUF_CHECK(monad_vbuf_writer_destroy(vs->writer, &flushed));
            monad_vbuf_chain_free(
                monad_vbuf_chain_concat(&vs->chain, &flushed));
        }
    }

    void append_event(
        EventSource::Iterator const *source_iter,
        monad_event_descriptor const *event, std::byte const *payload,
        bool erase_timestamps)
    {
        uint64_t const buf_offset = get_payload_buf_virtual_offset();
        VBUF_CHECK(monad_vbuf_writer_memcpy(
            payload_vbuf_state_.writer,
            payload,
            event->payload_size,
            MONAD_EVENT_PAYLOAD_ALIGN,
            &payload_vbuf_state_.chain));
        if (!source_iter->check_payload(event)) {
            errx_f(
                EX_SOFTWARE,
                "ERROR: event {} payload lost! OFFSET: {}, WINDOW_START: "
                "{}",
                event->seqno,
                event->payload_buf_offset,
                __atomic_load_n(
                    &source_iter->ring_pair.iter.control->buffer_window_start,
                    __ATOMIC_ACQUIRE));
        }

        monad_event_descriptor event_copy = *event;
        event_copy.seqno = ++event_count_;
        event_copy.payload_buf_offset = buf_offset;
        if (erase_timestamps) {
            event_copy.record_epoch_nanos = 0;
        }

        // TODO(ken): we don't like having special logic for different
        //   ring types, but it's not clear how else to handle this; figure
        //   something out...
        if (header_.content_type == MONAD_EVENT_CONTENT_TYPE_EXEC &&
            event_copy.content_ext[MONAD_FLOW_BLOCK_SEQNO] != 0) {
            if (event_copy.event_type == MONAD_EXEC_BLOCK_START) {
                last_block_ref_ = event_copy.seqno;
            }
            event_copy.content_ext[MONAD_FLOW_BLOCK_SEQNO] = last_block_ref_;
        }

        VBUF_CHECK(monad_vbuf_writer_memcpy(
            descriptor_vbuf_state_.writer,
            &event_copy,
            sizeof event_copy,
            alignof(monad_event_descriptor),
            &descriptor_vbuf_state_.chain));
    }

    void write_snapshot(int fd, fs::path const &output_path)
    {
        // Flush the residual vbuf segments onto their respective chains
        for (auto *vs : {&descriptor_vbuf_state_, &payload_vbuf_state_}) {
            monad_vbuf_chain flushed;
            monad_vbuf_chain_init(&flushed);
            monad_vbuf_writer_flush(vs->writer, &flushed);
            monad_vbuf_chain_concat(&vs->chain, &flushed);
        }

        uint64_t const next_payload_byte = get_payload_buf_virtual_offset();
        header_.size.descriptor_capacity = std::max(
            std::bit_ceil(event_count_),
            1UL << MONAD_EVENT_MIN_DESCRIPTORS_SHIFT);
        header_.size.payload_buf_size = std::max(
            std::bit_ceil(next_payload_byte),
            1UL << MONAD_EVENT_MIN_PAYLOAD_BUF_SHIFT);

        header_.control.last_seqno = event_count_;
        header_.control.next_payload_byte = next_payload_byte;
        header_.control.buffer_window_start = 0;

        std::print(
            stderr,
            "writing {} events to {}, total size is: {}",
            header_.size.descriptor_capacity,
            output_path.string(),
            monad_event_ring_calc_storage(&header_.size));

        checked_write(fd, &header_, sizeof header_);
        skip_bytes(fd, PAGE_2MB - sizeof header_);

        monad_vbuf_segment *segment;
        size_t count = 0;
        TAILQ_FOREACH(segment, &descriptor_vbuf_state_.chain.segments, entry)
        {
            copy_vbuf_segment(fd, segment->fd, segment->size);
            std::print(
                stderr,
                " ... D:{}/{}",
                ++count,
                descriptor_vbuf_state_.chain.segment_count);
        }

        uint64_t const descriptor_skip =
            header_.size.descriptor_capacity * sizeof(monad_event_descriptor) -
            monad_vbuf_writer_get_offset(descriptor_vbuf_state_.writer);
        skip_bytes(fd, descriptor_skip);

        count = 0;
        TAILQ_FOREACH(segment, &payload_vbuf_state_.chain.segments, entry)
        {
            copy_vbuf_segment(fd, segment->fd, segment->size);
            std::print(
                stderr,
                " ... P:{}/{}",
                ++count,
                payload_vbuf_state_.chain.segment_count);
        }

        uint64_t const payload_skip =
            header_.size.payload_buf_size - next_payload_byte;
        skip_bytes(fd, payload_skip);

        if (event_source_->get_type() == EventSource::Type::EventRing) {
            auto const *const mr =
                static_cast<MappedEventRing const *>(event_source_);
            checked_write(
                fd,
                mr->get_event_ring()->context_area,
                header_.size.context_area_size);
        }
        std::println(stderr, " ... done");
    }

private:
    uint64_t get_payload_buf_virtual_offset()
    {
        return monad_round_size_to_align(
            monad_vbuf_writer_get_offset(payload_vbuf_state_.writer),
            MONAD_EVENT_PAYLOAD_ALIGN);
    }

    void skip_bytes(int out_fd, size_t n_bytes)
    {
        // Usually the output is a pipe (stdout piped into the stdin of the
        // zstd compression CLI utility), so we can't skip bytes with lseek
        // or splice `/dev/zero` into `fd`; we need to actually write zeros
        while (n_bytes > PAGE_2MB) {
            checked_write(out_fd, Zero.get(), PAGE_2MB);
            n_bytes -= PAGE_2MB;
        }
        checked_write(out_fd, Zero.get(), n_bytes);
    }

    void copy_vbuf_segment(int out_fd, int segment_fd, size_t segment_size)
    {
        size_t residual = segment_size;
        while (residual > 0) {
            ssize_t const n_written =
                sendfile(out_fd, segment_fd, nullptr, residual);
            if (n_written == -1) {
                err_f(EX_OSERR, "sendfile failed");
            }
            residual -= static_cast<size_t>(n_written);
        }
    }

    void checked_write(int fd, void const *buf, size_t n)
    {
        auto const *p = static_cast<std::byte const *>(buf);
        auto const *const end = p + n;
        while (p != end) {
            ssize_t const n_written =
                write(fd, p, static_cast<size_t>(end - p));
            if (n_written == -1) {
                err_f(EX_OSERR, "write of {} bytes failed", n);
            }
            p += static_cast<size_t>(n_written);
        }
    }

    EventSource const *event_source_;

    snapshot_vbuf_state descriptor_vbuf_state_;
    snapshot_vbuf_state payload_vbuf_state_;
    uint64_t event_count_;
    uint64_t last_block_ref_;
    monad_event_ring_header header_;

    static std::unique_ptr<std::byte[]> Zero;
};

std::unique_ptr<std::byte[]> SnapshotWriter::Zero{new std::byte[PAGE_2MB]{}};

struct EventSourceState
{
    SnapshotWriter snap_writer;
    EventSource::Iterator iter;
    size_t not_ready_count;
    EventSource *event_source;
    bool finished;
    Command const *command;
};

void kill_event_ring_writers(int ring_fd)
{
    pid_t writer_pids[32];
    size_t num_pids = std::size(writer_pids);
    if (monad_event_ring_find_writer_pids(ring_fd, writer_pids, &num_pids) ==
        -1) {
        errx_f(
            EX_SOFTWARE,
            "library error: {}",
            monad_event_ring_get_last_error());
    }
    for (size_t i = 0; i < num_pids; ++i) {
        kill(writer_pids[i], SIGINT);
    }
}

} // End of anonymous namespace

void snapshot_thread_main(std::span<Command *const> commands)
{
    EventSourceState *state_bufs = static_cast<EventSourceState *>(
        alloca(sizeof(EventSourceState) * size(commands)));
    std::span<EventSourceState> states = std::span{state_bufs, size(commands)};

    for (size_t i = 0; Command *const c : commands) {
        auto const *const options = c->get_options<SnapshotCommandOptions>();
        EventSourceState &state = *new (&states[i++]) EventSourceState{
            SnapshotWriter{c->event_sources[0], options->vbuf_segment_shift},
            {},
            0,
            nullptr,
            false,
            nullptr};
        state.event_source = c->event_sources[0];
        state.command = c;
        state.event_source->init_iterator(
            &state.iter,
            options->common_options.start_seqno,
            options->common_options.end_seqno);
    }

    size_t active_state_count = size(states);
    while (g_should_exit == 0 && active_state_count > 0) {
        for (EventSourceState &state : states) {
            if (state.finished) {
                continue;
            }

            using enum EventIteratorResult;
            monad_event_content_type content_type;
            monad_event_descriptor event;
            std::byte const *payload;
            switch (state.iter.next(&content_type, &event, &payload)) {
            case AfterStart:
                errx_f(
                    EX_SOFTWARE,
                    "event seqno {} occurs after start seqno {};"
                    "events missing",
                    event.seqno,
                    *state.iter.start_seqno);

            case AfterEnd:
                errx_f(
                    EX_SOFTWARE,
                    "event seqno {} occurs after end seqno {}; "
                    "did a gap occur?",
                    event.seqno,
                    *state.iter.end_seqno);

            case Finished:
                --active_state_count;
                state.finished = true;
                continue;

            case NotReady:
                if ((++state.not_ready_count & NotReadyCheckMask) == 0) {
                    if (state.event_source->is_finalized()) {
                        --active_state_count;
                        state.finished = true;
                    }
                }
                [[fallthrough]];
            case Skipped:
                continue;

            case Gap:
                errx_f(
                    EX_SOFTWARE,
                    "ERROR: event gap from {} -> {}, snapshot can't be written",
                    state.iter.get_last_read_seqno(),
                    state.iter.get_last_written_seqno());

            case Success:
                state.not_ready_count = 0;
                state.snap_writer.append_event(
                    &state.iter,
                    &event,
                    payload,
                    state.command->get_options<SnapshotCommandOptions>()
                        ->erase_timestamps);
                break; // Handled in the main loop body
            }
        }
    }

    for (EventSourceState const &state : states) {
        if (state.command->get_options<SnapshotCommandOptions>()->kill_at_end &&
            state.event_source->get_type() == EventSource::Type::EventRing) {
            kill_event_ring_writers(state.event_source->get_source_file().fd);
        }
    }

    for (EventSourceState &state : states) {
        OutputFile const *o = state.command->output;
        state.snap_writer.write_snapshot(fileno(o->file), o->canonical_path);
        state.~EventSourceState();
    }
}
