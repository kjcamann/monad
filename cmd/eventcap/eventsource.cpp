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

#include "eventsource.hpp"
#include "err_cxx.hpp"
#include "options.hpp"
#include "util.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>

#include <sysexits.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_iter_help.h>

MappedEventRing::MappedEventRing(MappedEventRing &&other) noexcept
    : source_file_{std::move(other.source_file_)}
    , initial_liveness_{other.initial_liveness_}
    , force_live_{other.force_live_}
    , event_ring_{other.event_ring_}
    , metadata_entries_{other.metadata_entries_}
{
    other.event_ring_ = {};
}

MappedEventRing::~MappedEventRing()
{
    monad_event_ring_unmap(&event_ring_);
}

std::string MappedEventRing::describe() const
{
    constexpr size_t MAX_WRITER_PIDS = 128;

    EventRingLiveness current_liveness = initial_liveness_;
    std::string live_suffix;
    if (current_liveness == EventRingLiveness::Live) {
        pid_t pids[MAX_WRITER_PIDS];
        size_t npids = std::size(pids);
        if (int const rc = monad_event_ring_find_writer_pids(
                source_file_.fd, pids, &npids)) {
            live_suffix = std::format(", pids not available {}", rc);
        }
        else if (npids == 1) {
            live_suffix = std::format(", pid: {}", pids[0]);
        }
        else if (npids == 0) {
            current_liveness = EventRingLiveness::Abandoned;
        }
        else {
            live_suffix = std::format(", pids: {}", std::span{pids, npids});
        }
    }
    if (force_live_) {
        live_suffix += ", forced live";
    }
    return std::format(
        "{} [{}{}]",
        source_file_.origin_path.string(),
        ::describe(current_liveness),
        live_suffix);
}

bool MappedEventRing::is_finalized() const
{
    if (force_live_) {
        return false;
    }
    switch (initial_liveness_) {
    case EventRingLiveness::Live:
        return event_ring_is_abandoned(source_file_.fd);
    case EventRingLiveness::Abandoned:
        [[fallthrough]];
    case EventRingLiveness::Snapshot:
        return true;
    default:
        std::unreachable();
    }
}

void MappedEventRing::init_iterator(
    Iterator *source_iter, std::optional<SequenceNumberSpec> start_seqno,
    std::optional<uint64_t> end_seqno) const
{
    monad_event_ring_header const *const header = get_header();
    monad_event_iterator &ring_iter = source_iter->ring_pair.iter;
    source_iter->source_type = EventSource::Type::EventRing;
    source_iter->content_type = header->content_type;
    source_iter->finished = false;
    source_iter->ring_pair.ring = this;

    int const rc = monad_event_ring_init_iterator(&event_ring_, &ring_iter);
    MONAD_DEBUG_ASSERT(rc == 0);

    if (start_seqno) {
        if (auto const *ssn =
                std::get_if<SemanticSequenceNumber>(&*start_seqno)) {
            monad_event_descriptor event;
            if (source_iter->content_type != MONAD_EVENT_CONTENT_TYPE_EXEC) {
                errx_f(
                    EX_CONFIG,
                    "specified semantic --start-seqno on event ring file {} "
                    "but file has content type {} [{}], expected "
                    "{} [{}]",
                    describe(),
                    g_monad_event_content_type_names[source_iter->content_type],
                    std::to_underlying(source_iter->content_type),
                    g_monad_event_content_type_names
                        [MONAD_EVENT_CONTENT_TYPE_EXEC],
                    std::to_underlying(MONAD_EVENT_CONTENT_TYPE_EXEC));
            }
            if (auto const *const block_number =
                    std::get_if<uint64_t>(&ssn->block_label)) {
                bool event_valid;
                if (ssn->consensus_type == MONAD_EXEC_NONE) {
                    event_valid = monad_exec_iter_rewind_for_simple_replay(
                        &ring_iter, &event_ring_, *block_number, &event);
                }
                else {
                    event_valid = monad_exec_iter_block_number_prev(
                        &ring_iter,
                        &event_ring_,
                        *block_number,
                        ssn->consensus_type,
                        &event);
                }
                if (event_valid) {
                    start_seqno = event.seqno;
                }
                else {
                    // TODO(ken): we do this because the above probably
                    //   means we're too late (vs. too early) so this will
                    //   give the correct return code, but we could try harder
                    //   to diagnose it. If we're too early, it's inherently
                    //   race-y.
                    start_seqno = 0UL;
                }
            }
            else if (
                auto const *const block_id =
                    std::get_if<std::array<std::byte, 32>>(&ssn->block_label)) {
                monad_c_bytes32 id;
                std::memcpy(std::data(id), block_id->data(), sizeof id);
                if (monad_exec_iter_block_id_prev(
                        &ring_iter,
                        &event_ring_,
                        &id,
                        ssn->consensus_type,
                        &event)) {
                    start_seqno = event.seqno;
                }
                else {
                    // As above
                    start_seqno = 0UL;
                }
            }
            else {
                if (monad_exec_iter_consensus_prev(
                        &ring_iter, ssn->consensus_type, &event)) {
                    start_seqno = event.seqno;
                }
                else {
                    // As above
                    start_seqno = 0UL;
                }
            }
        }
        MONAD_ASSERT(std::holds_alternative<uint64_t>(*start_seqno));
        uint64_t const int_start_seqno = std::get<uint64_t>(*start_seqno);
        if (int_start_seqno <= ring_iter.read_last_seqno) {
            ring_iter.read_last_seqno =
                int_start_seqno == 0 ? 0 : int_start_seqno - 1;
        }
        else {
            source_iter->start_seqno = int_start_seqno;
        }
    }
    else if (initial_liveness_ == EventRingLiveness::Abandoned) {
        // Abandoned ring and no --start-seqno parameter; start as
        // far back as possible
        size_t const desc_capacity = header->size.descriptor_capacity;
        uint64_t const last_seqno =
            __atomic_load_n(&header->control.last_seqno, __ATOMIC_ACQUIRE);
        if (last_seqno < desc_capacity) {
            ring_iter.read_last_seqno = 0;
        }
        else {
            ring_iter.read_last_seqno = last_seqno + 1 - desc_capacity;
        }
    }
    else if (initial_liveness_ == EventRingLiveness::Snapshot) {
        // Snapshot ring and no --start-seqno parameter; start at zero
        ring_iter.read_last_seqno = 0;
    }

    source_iter->end_seqno = end_seqno;
}

EventCaptureFile::EventCaptureFile(EventCaptureFile &&other)
    : source_file_{std::move(other.source_file_)}
    , evcap_reader_{other.evcap_reader_}
{
    other.evcap_reader_ = nullptr;
}

EventCaptureFile::~EventCaptureFile()
{
    monad_evcap_reader_destroy(evcap_reader_);
}

std::string EventCaptureFile::describe() const
{
    return std::format("{} [capture]", source_file_.origin_path.string());
}

monad_evcap_event_iterator
EventCaptureFile::open_event_section(monad_evcap_section_desc const *sd) const
{
    monad_evcap_event_iterator iter;
    if (monad_evcap_reader_open_iterator(evcap_reader_, sd, &iter) != 0) {
        errx_f(
            EX_SOFTWARE,
            "evcap reader library error -- {}",
            monad_evcap_reader_get_last_error());
    }
    return iter;
}

EventCaptureFile::MultiSectionIterator
EventCaptureFile::create_multi_section_iterator() const
{
    MultiSectionIterator iter{};
    iter.capture = this;
    iter.current_section = nullptr;
    monad_evcap_reader_next_section(
        evcap_reader_, MONAD_EVCAP_SECTION_EVENT_BUNDLE, &iter.current_section);
    if (iter.current_section != nullptr) {
        int const rc = monad_evcap_reader_open_iterator(
            evcap_reader_, iter.current_section, &iter.section_iter);
        MONAD_ASSERT(rc == 0);
    }
    return iter;
}

void EventCaptureFile::init_iterator(
    Iterator *iter, std::optional<SequenceNumberSpec> start_seqno,
    std::optional<uint64_t> end_seqno) const
{
    iter->source_type = EventSource::Type::CaptureFile;
    iter->content_type = MONAD_EVENT_CONTENT_TYPE_NONE;
    iter->finished = false;
    iter->capture_iter = create_multi_section_iterator();
    if (start_seqno) {
        if (auto *ssn = std::get_if<SemanticSequenceNumber>(&*start_seqno)) {
            // TODO(ken): it's not clear what we should do here, because of
            //   the issues introduced by support for mixed ring captures
            (void)ssn;
            errx_f(
                EX_SOFTWARE,
                "semantic sequence numbers for start-seqno not implemented for "
                "capture files yet");
        }
        else {
            iter->start_seqno = std::get<uint64_t>(*start_seqno);
        }
    }
    iter->end_seqno = end_seqno;
}

EventCaptureFile::MultiSectionIterator::MultiSectionIterator()
    : current_section{nullptr}
    , section_iter{}
    , capture{nullptr}
    , last_read_seqno{0}
{
}

EventCaptureFile::MultiSectionIterator::MultiSectionIterator(
    MultiSectionIterator &&rhs)
    : current_section{rhs.current_section}
    , section_iter{rhs.section_iter}
    , capture{rhs.capture}
    , last_read_seqno{rhs.last_read_seqno}
{
    rhs.section_iter = {};
}

EventCaptureFile::MultiSectionIterator::~MultiSectionIterator()
{
    monad_evcap_iterator_close(&section_iter);
}

bool EventCaptureFile::MultiSectionIterator::next(
    monad_event_content_type *content_type,
    monad_event_descriptor const **event, std::byte const **payload)
{
TryAgain:
    if (current_section == nullptr) {
        // No more MONAD_EVCAP_SECTION_EVENT_BUNDLE sections; we're done
        *content_type = MONAD_EVENT_CONTENT_TYPE_NONE;
        *event = nullptr;
        *payload = nullptr;
        return false;
    }
    // Try to read an event from the local iterator to the current event
    // bundle section; if it is exhausted, open a new iterator to the next
    // event bundle section and try again
    if (monad_evcap_iterator_next(
            &section_iter,
            content_type,
            event,
            reinterpret_cast<uint8_t const **>(payload))) [[likely]] {
        last_read_seqno = (*event)->seqno;
        return true;
    }
    monad_evcap_iterator_close(&section_iter);
    if (monad_evcap_reader_next_section(
            capture->evcap_reader_,
            MONAD_EVCAP_SECTION_EVENT_BUNDLE,
            &current_section)) {
        section_iter = capture->open_event_section(current_section);
    }
    goto TryAgain;
}

bool EventCaptureFile::MultiSectionIterator::read_seqno(
    uint64_t const seqno, monad_event_content_type *content_type,
    monad_event_descriptor const **event, std::byte const **payload) const
{
    return monad_evcap_iterator_copy_seqno(
        &section_iter,
        seqno,
        content_type,
        event,
        reinterpret_cast<uint8_t const **>(payload));
}

EventCaptureFile::MultiSectionIterator &
EventCaptureFile::MultiSectionIterator::operator=(MultiSectionIterator &&rhs)
{
    return *new (this) EventCaptureFile::MultiSectionIterator{std::move(rhs)};
}
