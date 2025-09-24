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

#pragma once

/**
 * @file
 *
 * This files defines a unified interface for working with event ring and
 * event capture files, so that most code can read event data from either
 * source using a single API
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>

#include <category/core/assert.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_iterator.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_source.h>

#include "metadata.hpp"

struct monad_event_metadata;
struct SemanticSequenceNumber;
using SequenceNumberSpec = std::variant<uint64_t, SemanticSequenceNumber>;

enum class EventRingLiveness
{
    Unknown,
    Live,
    Abandoned,
    Snapshot,
};

constexpr char const *describe(EventRingLiveness l)
{
    using enum EventRingLiveness;
    switch (l) {
    case Live:
        return "live";
    case Abandoned:
        return "abandoned";
    case Snapshot:
        return "snapshot";
    default:
        return "<unknown>";
    }
}

struct EventSourceFile
{
    std::filesystem::path origin_path;
    int fd;
};

/// Events can come from event ring files or event capture files, this
/// interface represents the common functionality of both
class EventSource
{
public:
    struct Iterator;

    enum class Type : uint8_t
    {
        EventRing,
        CaptureFile,
    };

    virtual ~EventSource() = default;
    virtual std::string describe() const = 0;
    virtual EventSourceFile const &get_source_file() const = 0;
    virtual Type get_type() const = 0;
    virtual bool is_finalized() const = 0;
    virtual bool is_interactive() const = 0;
    virtual void init_iterator(
        Iterator *, std::optional<SequenceNumberSpec> start_seqno,
        std::optional<uint64_t> end_seqno) const = 0;
};

class MappedEventRing : public EventSource
{
public:
    MappedEventRing() = delete;
    MappedEventRing(MappedEventRing const &) = delete;
    MappedEventRing(MappedEventRing &&) noexcept;
    ~MappedEventRing() override;

    explicit MappedEventRing(
        EventSourceFile source_file, EventRingLiveness initial_liveness,
        monad_event_ring const &event_ring,
        std::span<monad_event_metadata const> metadata_entries)
        : source_file_{std::move(source_file)}
        , initial_liveness_{initial_liveness}
        , force_live_{false}
        , event_ring_{event_ring}
        , metadata_entries_{metadata_entries}
    {
        event_ring_.user = this;
    }

    std::string describe() const override;

    EventSourceFile const &get_source_file() const override
    {
        return source_file_;
    }

    Type get_type() const override
    {
        return Type::EventRing;
    }

    bool is_finalized() const override;

    bool is_interactive() const override
    {
        return initial_liveness_ == EventRingLiveness::Live;
    }

    EventRingLiveness get_initial_liveness() const
    {
        return initial_liveness_;
    }

    monad_event_ring const *get_event_ring() const
    {
        return &event_ring_;
    }

    monad_event_ring_header const *get_header() const
    {
        return event_ring_.header;
    }

    uint64_t get_buffer_window_start() const
    {
        return __atomic_load_n(
            &event_ring_.header->control.buffer_window_start, __ATOMIC_ACQUIRE);
    }

    bool set_force_live(bool force)
    {
        std::swap(force_live_, force);
        return force;
    }

    void init_iterator(
        Iterator *, std::optional<SequenceNumberSpec> start_seqno,
        std::optional<uint64_t> end_seqno) const override;

private:
    EventSourceFile source_file_;
    EventRingLiveness initial_liveness_;
    bool force_live_;
    monad_event_ring event_ring_;
    std::span<monad_event_metadata const> metadata_entries_;
};

class EventCaptureFile : public EventSource
{
public:
    struct MultiSectionIterator;

    EventCaptureFile() = delete;
    EventCaptureFile(EventCaptureFile const &) = delete;
    EventCaptureFile(EventCaptureFile &&);
    ~EventCaptureFile() override;

    explicit EventCaptureFile(
        EventSourceFile source_file, monad_evcap_reader *evcap_reader)
        : source_file_{std::move(source_file)}
        , evcap_reader_{evcap_reader}
    {
    }

    std::string describe() const override;

    EventSourceFile const &get_source_file() const override
    {
        return source_file_;
    }

    Type get_type() const override
    {
        return Type::CaptureFile;
    }

    bool is_finalized() const override
    {
        return true;
    }

    bool is_interactive() const override
    {
        return false;
    }

    monad_evcap_reader *get_reader() const
    {
        return evcap_reader_;
    }

    monad_evcap_iterator
    open_event_section(monad_evcap_section_desc const *) const;

    MultiSectionIterator
        create_multi_section_iterator(monad_event_content_type) const;

    void init_iterator(
        Iterator *, std::optional<SequenceNumberSpec> start_seqno,
        std::optional<uint64_t> end_seqno) const override;

private:
    EventSourceFile source_file_;
    monad_evcap_reader *evcap_reader_;
};

/// Iterator which visits all events in each MONAD_EVCAP_SECTION_EVENT_BUNDLE
/// section in a capture file
struct EventCaptureFile::MultiSectionIterator
{
    MultiSectionIterator();
    MultiSectionIterator(MultiSectionIterator const *) = delete;
    MultiSectionIterator(MultiSectionIterator &&);
    ~MultiSectionIterator();

    bool next(monad_event_descriptor const **event, std::byte const **payload);

    bool read_seqno(uint64_t const seqno, monad_event_descriptor const **event,
                    std::byte const **payload) const;

    MultiSectionIterator &operator=(MultiSectionIterator const &) = delete;
    MultiSectionIterator &operator=(MultiSectionIterator &&);

    monad_evcap_section_desc const *current_section;
    monad_evcap_iterator section_iter;
    EventCaptureFile const *capture;
};

// clang-format off

/// Generalization of `monad_evsrc_iter_result` that also implements the
/// --start-seqno and --end-seqno range filtering command line options; the
/// return value of EventSource::Iterator::next
enum class EventIteratorResult
{
    Success = MONAD_EVSRC_SUCCESS,     ///< Event produced and iterator advanced
    NotReady = MONAD_EVSRC_NOT_READY,  ///< No events ready yet (ring only)
    Gap = MONAD_EVSRC_GAP,             ///< Sequence gap (ring only)
    NoMoreEvents =
        MONAD_EVSRC_NO_MORE_EVENTS,    ///< Would move before begin or past end
    Error = MONAD_EVSRC_ERROR,         ///< Error occurred (evcap only)
    Skipped,                           ///< Before --start-seqno, but copied out
    AfterStart,                        ///< First seen seqno > --start-seqno
    AfterEnd                           ///< Saw a seqno > --end-seqno
};

// clang-format on

/// Common interface that generalizes both event ring and event capture
/// iterators; the performance sensitive functionality remains inlined for the
/// event ring case
struct EventSource::Iterator
{
    Iterator();
    ~Iterator();

    enum class Type : uint8_t
    {
        EventRing,
        CaptureSection,
        CaptureMultiSection,
    };

    Type iter_type;
    bool finished;

    union
    {
        monad_event_iterator ring_iter;
        monad_evcap_iterator evcap_iter;
        EventCaptureFile::MultiSectionIterator multi_evcap_iter;
    };

    std::optional<uint64_t> start_seqno;
    std::optional<uint64_t> end_seqno;

    /// Try to consume the next event in the stream and advance the iterator
    EventIteratorResult next(
        monad_event_descriptor *event, std::byte const **payload);

    /// Read an event with this sequence number
    EventIteratorResult read_seqno(
        uint64_t const seqno, monad_event_descriptor *event,
        std::byte const **payload) const;

    /// Check if a payload is still valid (no-op for capture files)
    bool check_payload(monad_event_descriptor const *event) const;

    /// Return the last read sequence number
    uint64_t get_last_read_seqno() const;

    /// Return the last known sequence number (last written for event rings,
    /// last recorded for evcap files)
    uint64_t get_last_written_seqno() const;

    /// Clear an event gap (no-op for capture files)
    std::pair<uint64_t, uint64_t> clear_gap(bool can_recover);

    /// Create an event source iterator from this one
    monad_evsrc_iterator_t to_evsrc();

    monad_evsrc_const_iterator_t to_evsrc() const;
};

inline EventSource::Iterator::Iterator()
    : iter_type{Type::EventRing}
    , finished{false}
    , ring_iter{}
{
}

inline EventSource::Iterator::~Iterator()
{
    switch (iter_type) {
    case Type::CaptureSection:
        monad_evcap_iterator_close(&evcap_iter);
        break;
    case Type::CaptureMultiSection:
        multi_evcap_iter
            .EventCaptureFile::MultiSectionIterator::~MultiSectionIterator();
        break;
    default:
        break;
    }
}

inline EventIteratorResult EventSource::Iterator::next(
    monad_event_descriptor *event, std::byte const **payload)
{
    if (finished) {
        return EventIteratorResult::NoMoreEvents;
    }

    EventIteratorResult r;
    monad_event_descriptor const *mapped_event;

    // Get the next event descriptor and payload
    switch (iter_type) {
    case Type::EventRing:
        r = static_cast<EventIteratorResult>(
            monad_event_iterator_try_next(&ring_iter, event));
        if (r == EventIteratorResult::Success) {
            *payload =
                static_cast<std::byte const *>(monad_event_ring_payload_peek(
                    ring_iter.event_ring, event));
        }
        break;

    case Type::CaptureSection:
        if (monad_evcap_iterator_next(&evcap_iter, &mapped_event,
                                      reinterpret_cast<void const **>(payload))) [[likely]] {
            *event = *mapped_event;
            r = EventIteratorResult::Success;
        }
        else {
            finished = true;
            r = EventIteratorResult::NoMoreEvents;
        }
        break;

    case Type::CaptureMultiSection:
        if (multi_evcap_iter.next(&mapped_event, payload)) [[likely]] {
            *event = *mapped_event;
            r = EventIteratorResult::Success;
        }
        else {
            finished = true;
            r = EventIteratorResult::NoMoreEvents;
        }
        break;

    default:
        MONAD_ABORT_PRINTF(
            "unknown source_type %hhu", std::to_underlying(iter_type));
    }

    if (r != EventIteratorResult::Success) {
        return r;
    }

    // In the success case, we do some post-processing for the common
    // start-seqno, end-seqno options
    if (start_seqno) {
        if (event->seqno < *start_seqno) {
            // Too early, skip it
            return EventIteratorResult::Skipped;
        }
        bool const saw_start = event->seqno == *start_seqno;
        // Clear this so the comparison won't happen twice
        start_seqno.reset();
        return saw_start ? EventIteratorResult::Success
                         : EventIteratorResult::AfterStart;
    }

    // Check if we've advanced to end_seqno (or past it, if we gapped or
    // started too late); if so we're done
    if (end_seqno) {
        if (event->seqno == *end_seqno) {
            finished = true;
            return EventIteratorResult::NoMoreEvents;
        }
        if (event->seqno > *end_seqno) {
            finished = true;
            return EventIteratorResult::AfterEnd;
        }
    }

    return r;
}

inline EventIteratorResult EventSource::Iterator::read_seqno(
    uint64_t const seqno, monad_event_descriptor *event,
    std::byte const **payload) const
{
    EventIteratorResult r;
    monad_event_descriptor const *mapped_event;

    switch (iter_type) {
    case Type::EventRing:
        r = static_cast<EventIteratorResult>(monad_event_ring_try_copy(ring_iter.event_ring, seqno, event));
        if (r == EventIteratorResult::Success) {
            *payload =
                static_cast<std::byte const *>(monad_event_ring_payload_peek(
                    ring_iter.event_ring, event));
        }
        return r;

    case Type::CaptureSection:
        if (monad_evcap_iterator_copy_seqno(&evcap_iter, seqno, &mapped_event, reinterpret_cast<void const **>(payload))) {
            *event = *mapped_event;
            return EventIteratorResult::Success;
        }
        return EventIteratorResult::Error;

    case Type::CaptureMultiSection:
        if (multi_evcap_iter.read_seqno(seqno, &mapped_event, payload)) {
            *event = *mapped_event;
            return EventIteratorResult::Success;
        }
        return EventIteratorResult::Error;
    }
    std::unreachable();
}

inline bool
EventSource::Iterator::check_payload(monad_event_descriptor const *event) const
{
    switch (iter_type) {
    case Type::EventRing:
        return monad_event_ring_payload_check(ring_iter.event_ring, event);
    default:
        return true;
    }
}

inline uint64_t EventSource::Iterator::get_last_read_seqno() const
{
    switch (iter_type) {
    case Type::EventRing:
        return ring_iter.read_last_seqno;
    default:
        return 0; // TODO(ken): do something reasonable here
    }
}

inline uint64_t EventSource::Iterator::get_last_written_seqno() const
{
    switch (iter_type) {
    case Type::EventRing:
        return monad_event_ring_get_last_written_seqno(
            ring_iter.event_ring, false);
    case Type::CaptureSection:
        return evcap_iter.seqno_index.seqno_end;
    case Type::CaptureMultiSection:
        return multi_evcap_iter.section_iter.seqno_index.seqno_end;
    default:
        std::unreachable();
    }
}

inline std::pair<uint64_t, uint64_t>
EventSource::Iterator::clear_gap(bool can_recover)
{
    if (iter_type == Type::EventRing) {
        auto const p = std::make_pair(
            ring_iter.read_last_seqno,
            monad_event_iterator_reset(&ring_iter));
        finished = !can_recover;
        return p;
    }
    return {};
}

inline monad_evsrc_iterator_t EventSource::Iterator::to_evsrc()
{
    switch (iter_type) {
    case Type::EventRing:
        return monad_evsrc_iterator_from_ring(&ring_iter);
    case Type::CaptureSection:
        return monad_evsrc_iterator_from_evcap(&evcap_iter);
    case Type::CaptureMultiSection:
        return monad_evsrc_iterator_from_evcap(&multi_evcap_iter.section_iter);
    default:
        std::unreachable();
    }
}

inline monad_evsrc_const_iterator_t EventSource::Iterator::to_evsrc() const
{
    switch (iter_type) {
    case Type::EventRing:
        return monad_evsrc_iterator_from_ring_const(&ring_iter);
    case Type::CaptureSection:
        return monad_evsrc_iterator_from_evcap_const(&evcap_iter);
    case Type::CaptureMultiSection:
        return monad_evsrc_iterator_from_evcap_const(&multi_evcap_iter.section_iter);
    default:
        std::unreachable();
    }
}
