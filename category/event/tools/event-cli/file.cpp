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

#include "file.hpp"
#include "command.hpp"
#include "err_cxx.hpp"
#include "iterator.hpp"
#include "util.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_iter.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/event/event_source.h>
#include <category/execution/ethereum/core/base_ctypes.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_iter_help.h>

namespace fs = std::filesystem;

template <>
struct std::formatter<monad_event_flock_info> : std::formatter<std::string_view>
{
    template <class FmtContext>
    FmtContext::iterator
    format(monad_event_flock_info &i, FmtContext &ctx) const
    {
        std::string const s =
            std::format("{} [{:c}]", i.pid, i.lock == LOCK_EX ? 'W' : 'R');
        return this->std::formatter<std::string_view>::format(
            std::string_view{s}, ctx);
    }
};

namespace
{

struct ResolvedCaptureSections
{
    monad_evcap_section_desc const *schema_sd;
    monad_evcap_section_desc const *event_sd;
    size_t position;
};

std::string validate_consensus_seqno_arguments(
    EventSourceSpec const &source_spec, monad_event_content_type content_type)
{
    struct Param
    {
        std::string_view name;
        std::optional<SequenceNumberSpec> const &spec;
    };

    if (content_type == MONAD_EVENT_CONTENT_TYPE_EXEC) {
        return {};
    }
    for (auto const &[name, spec] :
         {Param{"--begin-seqno", source_spec.opt_begin_seqno},
          Param{"--end-seqno", source_spec.opt_end_seqno}}) {
        if (!spec || spec->type == SequenceNumberSpec::Type::Number) {
            continue;
        }
        MONAD_ASSERT(
            spec->type == SequenceNumberSpec::Type::ConsensusEvent &&
            content_type != MONAD_EVENT_CONTENT_TYPE_EXEC);
        return std::format(
            "specified consensus {} on event source {} "
            "but source has content type {} [{}], expected "
            "{} [{}]",
            name,
            source_spec.describe(),
            g_monad_event_content_type_names[content_type],
            std::to_underlying(content_type),
            g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_EXEC],
            std::to_underlying(MONAD_EVENT_CONTENT_TYPE_EXEC));
    }

    return {};
}

template <typename Iter>
std::optional<uint64_t>
try_seek_seqno(Iter *iter, SequenceNumberSpec const &sns)
{
    if (sns.type == SequenceNumberSpec::Type::Number) {
        return monad_evsrc_iter_set_seqno(iter, sns.seqno) ==
                       MONAD_EVSRC_SUCCESS
                   ? std::optional{sns.seqno}
                   : std::nullopt;
    }

    MONAD_ASSERT(sns.type == SequenceNumberSpec::Type::ConsensusEvent);
    monad_event_descriptor event;
    void const *payload;

    ConsensusEventSpec const &search_spec = sns.consensus_event;
    if (!search_spec.opt_block_label) {
        return monad_exec_iter_consensus_prev(
                   iter, search_spec.consensus_type, &event, &payload)
                   ? std::optional{event.seqno}
                   : std::nullopt;
    }

    BlockLabel const &block_label = *search_spec.opt_block_label;
    bool event_valid;
    if (block_label.type == BlockLabel::Type::BlockNumber) {
        event_valid =
            search_spec.consensus_type == MONAD_EXEC_NONE
                ? monad_exec_iter_rewind_for_simple_replay(
                      iter, block_label.block_number, &event, &payload)
                : monad_exec_iter_block_number_prev(
                      iter,
                      block_label.block_number,
                      search_spec.consensus_type,
                      &event,
                      &payload);
    }
    else {
        MONAD_ASSERT(block_label.type == BlockLabel::Type::BlockNumber);
        event_valid = monad_exec_iter_block_id_prev(
            iter,
            &block_label.block_id,
            search_spec.consensus_type,
            &event,
            &payload);
    }

    return event_valid ? std::optional{event.seqno} : std::nullopt;
}

std::optional<ResolvedCaptureSections> lookup_capture_spec(
    monad_evcap_reader const *evcap_reader,
    std::optional<EventCaptureSpec> const &opt_capture_spec)
{
    monad_evcap_section_desc const *scan_sd = nullptr;
    monad_evcap_section_desc const *event_sd = nullptr;
    size_t section_count = 0;

    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_EVENT_BUNDLE, &scan_sd)) {
        if (!opt_capture_spec) {
            // When there is no capture spec, just take the first event section
            // we find
            event_sd = scan_sd;
            break;
        }
        if (opt_capture_spec->use_block_number &&
            scan_sd->event_bundle.block_number ==
                opt_capture_spec->first_section) {
            event_sd = scan_sd;
            break;
        }
        if (!opt_capture_spec->use_block_number &&
            section_count == opt_capture_spec->first_section) {
            event_sd = scan_sd;
            break;
        }
        ++section_count;
    }
    if (event_sd == nullptr) {
        return std::nullopt;
    }
    return ResolvedCaptureSections{
        .schema_sd = monad_evcap_reader_load_linked_section_desc(
            evcap_reader, event_sd->event_bundle.schema_desc_offset),
        .event_sd = event_sd,
        .position = section_count};
}

size_t count_subsequent_sections(
    monad_evcap_reader const *evcap_reader, monad_evcap_section_desc const *sd)
{
    size_t count = 0;
    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_EVENT_BUNDLE, &sd)) {
        ++count;
    }
    return count;
}

} // End of anonymous namespace

std::string describe(EventCaptureSpec const &ecs)
{
    char const *const what = ecs.use_block_number ? "block" : "section";
    if (!ecs.count) {
        return std::format("{} range [{}, inf)", what, ecs.first_section);
    }
    if (*ecs.count == 1) {
        return std::format("{} {}", what, ecs.first_section);
    }
    return std::format(
        "{} range [{}, {})",
        what,
        ecs.first_section,
        ecs.first_section + *ecs.count);
}

std::string EventSourceSpec::describe() const
{
    if (opt_capture_spec) {
        return std::format(
            "{} {}", source_file->describe(), ::describe(*opt_capture_spec));
    }
    return source_file->describe();
}

monad_event_content_type EventSourceSpec::get_content_type() const
{
    return source_file->get_content_type(*this);
}

void EventSourceSpec::init_iterator(EventIterator *iter) const
{
    source_file->init_iterator(iter, *this);
}

MappedEventRing::MappedEventRing(MappedEventRing &&other) noexcept
    : origin_path_{std::move(other.origin_path_)}
    , ring_fd_{other.ring_fd_}
    , initial_liveness_{other.initial_liveness_}
    , force_live_{other.force_live_}
    , event_ring_{other.event_ring_}
{
    other.ring_fd_ = -1;
    other.event_ring_ = {};
}

MappedEventRing::~MappedEventRing()
{
    (void)close(ring_fd_);
    monad_event_ring_unmap(&event_ring_);
}

std::string MappedEventRing::describe() const
{
    constexpr size_t MAX_FLOCKS = 128;

    EventRingLiveness current_liveness = initial_liveness_;
    std::string live_suffix;
    if (current_liveness == EventRingLiveness::Live) {
        monad_event_flock_info flocks[MAX_FLOCKS];
        size_t lock_count = std::size(flocks);
        if (int const rc =
                monad_event_ring_query_flocks(ring_fd_, flocks, &lock_count)) {
            live_suffix = std::format(", pids not available {}", rc);
        }
        else if (lock_count == 1) {
            live_suffix = std::format(", {}", flocks[0]);
        }
        else if (lock_count == 0) {
            current_liveness = EventRingLiveness::Abandoned;
        }
        else {
            live_suffix = std::format(", {}", std::span{flocks, lock_count});
        }
    }
    if (force_live_) {
        live_suffix += ", forced live";
    }
    return std::format(
        "{} [{}{}]",
        origin_path_.string(),
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
        return event_ring_is_abandoned(ring_fd_);
    case EventRingLiveness::Abandoned:
        [[fallthrough]];
    case EventRingLiveness::Snapshot:
        return true;
    default:
        std::unreachable();
    }
}

std::string MappedEventRing::validate(EventSourceSpec const &source_spec) const
{
    if (source_spec.opt_capture_spec) {
        return std::format(
            "event ring file `{}` cannot have a capture specification",
            describe());
    }
    auto const content_type = get_content_type(source_spec);
    if (std::string const s =
            validate_consensus_seqno_arguments(source_spec, content_type);
        !std::empty(s)) {
        return s;
    }
    return {};
}

void MappedEventRing::init_iterator(
    EventIterator *iter, EventSourceSpec const &source_spec) const
{
    monad_event_ring_header const *const header = get_header();
    monad_event_ring_iter &ring_iter = iter->ring.iter;
    iter->ring.mapped_event_ring = this;
    iter->iter_type = EventIterator::Type::EventRing;
    iter->finished = false;
    iter->content_type = get_content_type(source_spec);
    iter->error_code = 0;
    iter->last_error_msg = nullptr;

    int rc = monad_event_ring_init_iterator(&event_ring_, &ring_iter);
    MONAD_ASSERT(rc == 0);

    if (source_spec.opt_begin_seqno) {
        iter->begin_seqno =
            try_seek_seqno(&ring_iter, *source_spec.opt_begin_seqno);
    }
    else if (initial_liveness_ == EventRingLiveness::Abandoned) {
        // Abandoned ring and no --begin-seqno parameter; start as
        // far back as possible
        size_t const desc_capacity = header->size.descriptor_capacity;
        uint64_t const last_seqno =
            __atomic_load_n(&header->control.last_seqno, __ATOMIC_ACQUIRE);
        if (last_seqno <= desc_capacity) {
            monad_event_ring_iter_set_seqno(&ring_iter, 1);
        }
        else {
            monad_event_ring_iter_set_seqno(
                &ring_iter, last_seqno + 1 - desc_capacity);
        }
    }
    else if (initial_liveness_ == EventRingLiveness::Snapshot) {
        // Snapshot ring without --begin-seqno parameter; start at 1
        monad_event_ring_iter_set_seqno(&ring_iter, 1);
    }

    if (source_spec.opt_end_seqno) {
        monad_event_ring_iter dummy_iter;
        rc = monad_event_ring_init_iterator(&event_ring_, &dummy_iter);
        MONAD_ASSERT(rc == 0);
        iter->end_seqno =
            try_seek_seqno(&dummy_iter, *source_spec.opt_end_seqno);
    }

    if (iter->begin_seqno && iter->end_seqno &&
        *iter->end_seqno < *iter->begin_seqno) {
        // XXX: there's some validation done for this in init.cpp, but it's
        // not perfect; there are a bunch of different cases, some should
        // be hard errors (if they "should have known better") others should
        // warn and reset the parameters as we're doing here
        iter->begin_seqno.reset();
        iter->end_seqno.reset();
    }
}

EventCaptureFile::EventCaptureFile(EventCaptureFile &&other) noexcept
    : origin_path_{std::move(other.origin_path_)}
    , evcap_fd_{other.evcap_fd_}
    , evcap_reader_{other.evcap_reader_}
{
    other.evcap_fd_ = -1;
    other.evcap_reader_ = nullptr;
}

EventCaptureFile::~EventCaptureFile()
{
    (void)close(evcap_fd_);
    monad_evcap_reader_destroy(evcap_reader_);
}

std::string EventCaptureFile::describe() const
{
    return std::format("{} [capture]", origin_path_.string());
}

monad_event_content_type
EventCaptureFile::get_content_type(EventSourceSpec const &source_spec) const
{
    auto const opt_resolved =
        lookup_capture_spec(evcap_reader_, source_spec.opt_capture_spec);
    return opt_resolved ? opt_resolved->schema_sd->schema.content_type
                        : MONAD_EVENT_CONTENT_TYPE_NONE;
}

std::string EventCaptureFile::validate(EventSourceSpec const &source_spec) const
{
    auto const opt_resolved =
        lookup_capture_spec(evcap_reader_, source_spec.opt_capture_spec);
    if (!opt_resolved) {
        if (source_spec.opt_capture_spec) {
            return std::format(
                "no section in {} for capture specification {}",
                describe(),
                ::describe(*source_spec.opt_capture_spec));
        }
        else {
            // No EVENT_BUNDLE section present; empty capture files are not
            // an error
            return {};
        }
    }
    ResolvedCaptureSections const &sections = *opt_resolved;
    if (sections.schema_sd == nullptr) {
        // TODO(ken): validation of event capture files does not belong here;
        //   this should eventually be checked by monad_evcap_reader_create
        return std::format(
            "EVENT_BUNDLE section #{} has no schema", sections.position);
    }

    // There is a single section if
    //
    //   1. They didn't specify a section, and there is only one section OR
    //   2. They did explicitly ask for one section, regardless
    //      of how many there are
    size_t const actual_section_count =
        1 + count_subsequent_sections(evcap_reader_, sections.event_sd);
    bool const is_single_section =
        (!source_spec.opt_capture_spec && actual_section_count == 1) ||
        (source_spec.opt_capture_spec && source_spec.opt_capture_spec->count &&
         *source_spec.opt_capture_spec->count == 1);

    if (!is_single_section && source_spec.opt_capture_spec &&
        source_spec.opt_capture_spec->count &&
        actual_section_count < *source_spec.opt_capture_spec->count) {
        return std::format(
            "capture spec requests {} sections, but only {} are "
            "available",
            *source_spec.opt_capture_spec->count,
            actual_section_count);
    }

    // Static sequence number checks
    bool const has_seqno_bounds =
        source_spec.opt_begin_seqno || source_spec.opt_end_seqno;
    if (has_seqno_bounds && !is_single_section) {
        return std::format("--begin-seqno/--end-seqno cannot be specified on "
                           "multi-section iteration");
    }
    if (has_seqno_bounds) {
        if (sections.event_sd->event_bundle.seqno_index_desc_offset != 0) {
            return std::format("--begin-seqno/--end-seqno specified but bundle "
                               "has no seqno index");
        }

        monad_event_content_type const content_type =
            sections.schema_sd->schema.content_type;
        if (std::string const s =
                validate_consensus_seqno_arguments(source_spec, content_type);
            !std::empty(s)) {
            return s;
        }

        uint64_t const section_begin_seqno =
            sections.event_sd->event_bundle.start_seqno;
        uint64_t const section_end_seqno =
            section_begin_seqno + sections.event_sd->event_bundle.event_count;
        if (source_spec.opt_begin_seqno &&
            source_spec.opt_begin_seqno->type !=
                SequenceNumberSpec::Type::Number &&
            source_spec.opt_begin_seqno->seqno < section_begin_seqno) {
            return std::format(
                "--begin-seqno {} is before first sequence number {}",
                source_spec.opt_begin_seqno->seqno,
                section_begin_seqno);
        }
        if (source_spec.opt_end_seqno &&
            source_spec.opt_end_seqno->type !=
                SequenceNumberSpec::Type::Number &&
            source_spec.opt_end_seqno->seqno > section_end_seqno) {
            return std::format(
                "--end-seqno {} is after last sequence number {}",
                source_spec.opt_end_seqno->seqno,
                section_end_seqno);
        }
    }

    return {};
}

void EventCaptureFile::init_iterator(
    EventIterator *iter, EventSourceSpec const &source_spec) const
{
    auto const opt_resolved =
        lookup_capture_spec(evcap_reader_, source_spec.opt_capture_spec);

    iter->iter_type = EventIterator::Type::EventCaptureSection;
    iter->error_code = 0;
    iter->last_error_msg = nullptr;
    if (!opt_resolved) {
        // Empty capture file case
        iter->finished = true;
        iter->content_type = MONAD_EVENT_CONTENT_TYPE_NONE;
        return;
    }
    iter->finished = false;

    ResolvedCaptureSections const &sections = *opt_resolved;
    iter->content_type = sections.schema_sd->schema.content_type;
    iter->evcap.capture_file = this;
    iter->evcap.section_limit = source_spec.opt_capture_spec
                                    ? source_spec.opt_capture_spec->count
                                    : std::nullopt;
    iter->evcap.sections_consumed = 0;

    if (monad_evcap_event_section_open(
            &iter->evcap.cur_section, evcap_reader_, sections.event_sd) != 0) {
        errx_f(
            EX_SOFTWARE,
            "evcap library error opening iterator to section {} in {} -- {}",
            sections.event_sd->descriptor_offset,
            describe(),
            monad_evcap_reader_get_last_error());
    }

    monad_evcap_event_section_open_iterator(
        &iter->evcap.cur_section, &iter->evcap.iter);
    if (source_spec.opt_begin_seqno) {
        iter->begin_seqno =
            try_seek_seqno(&iter->evcap.iter, *source_spec.opt_begin_seqno);
    }
    if (source_spec.opt_end_seqno) {
        monad_evcap_event_iter dummy_iter;
        monad_evcap_event_section_open_iterator(
            &iter->evcap.cur_section, &dummy_iter);
        iter->end_seqno =
            try_seek_seqno(&dummy_iter, *source_spec.opt_end_seqno);
    }
}

BlockArchiveDirectory::BlockArchiveDirectory(
    BlockArchiveDirectory &&other) noexcept
    : origin_path_{std::move(other.origin_path_)}
    , archive_fd_{other.archive_fd_}
    , archive_{other.archive_}
{
    other.archive_fd_ = -1;
    other.archive_ = nullptr;
}

BlockArchiveDirectory::~BlockArchiveDirectory()
{
    (void)close(archive_fd_);
    monad_bcap_block_archive_close(archive_);
}

std::string BlockArchiveDirectory::describe() const
{
    return std::format("{} [block archive]", origin_path_.string());
}

std::string
BlockArchiveDirectory::validate(EventSourceSpec const &source_spec) const
{
    if (!source_spec.opt_capture_spec) {
        // TODO(ken): eventually support some kind of min/max range
        //  functionality in the bcap API
        return "block archive with no capture specification not supported yet";
    }

    EventCaptureSpec const &ecs = *source_spec.opt_capture_spec;
    // Check that the first block is present
    char path_buf[64];
    int const rc = monad_bcap_block_archive_open_block_fd(
        archive_,
        ecs.first_section,
        O_RDONLY,
        0,
        0,
        path_buf,
        sizeof path_buf,
        nullptr);
    if (rc == ENOENT) {
        return std::format(
            "starting block {} not present in archive", ecs.first_section);
    }
    if (rc != 0) {
        return std::format(
            "bcap library error -- {}", monad_bcap_get_last_error());
    }

    // Static sequence number checks
    bool const has_seqno_bounds =
        source_spec.opt_begin_seqno || source_spec.opt_end_seqno;
    bool const has_single_block = ecs.count && *ecs.count == 1;
    if (has_seqno_bounds && !has_single_block) {
        return std::format("--begin-seqno/--end-seqno cannot be specified on "
                           "multi-block iteration");
    }

    return {};
}

void BlockArchiveDirectory::init_iterator(
    EventIterator *iter, EventSourceSpec const &source_spec) const
{
    iter->iter_type = EventIterator::Type::BlockArchive;
    iter->finished = false;
    iter->content_type = MONAD_EVENT_CONTENT_TYPE_EXEC;
    iter->error_code = 0;
    iter->last_error_msg = nullptr;

    uint64_t const first_block = source_spec.opt_capture_spec->first_section;

    monad_evcap_reader *evcap_reader;
    monad_evcap_section_desc const *event_sd;
    int fd;
    char path_buf[64];
    int const rc = monad_bcap_block_archive_open_block_reader(
        archive_,
        first_block,
        path_buf,
        sizeof path_buf,
        &fd,
        &evcap_reader,
        &event_sd);
    if (rc != 0) {
        errx_f(
            EX_SOFTWARE,
            "cannot open iterator to archive block {} -- {}",
            first_block,
            monad_bcap_get_last_error());
    }
    iter->archive.cur_capture_file = std::make_unique<EventCaptureFile>(
        origin_path_ / fs::path{path_buf}, fd, evcap_reader);
    iter->archive.archive_dir = this;
    iter->archive.block_limit = source_spec.opt_capture_spec
                                    ? source_spec.opt_capture_spec->count
                                    : std::nullopt;
    iter->archive.blocks_consumed = 0;

    EventIterator::CaptureSectionImpl &cs = iter->archive.open_section;
    cs.capture_file = iter->archive.cur_capture_file.get();
    cs.section_limit = 1;
    if (monad_evcap_event_section_open(
            &cs.cur_section, evcap_reader, event_sd) != 0) {
        errx_f(
            EX_SOFTWARE,
            "evcap library error opening iterator to section {} in {} inside "
            "{}-- {}",
            event_sd->descriptor_offset,
            iter->archive.cur_capture_file->describe(),
            describe(),
            monad_evcap_reader_get_last_error());
    }

    monad_evcap_event_section_open_iterator(&cs.cur_section, &cs.iter);
    if (source_spec.opt_begin_seqno) {
        iter->begin_seqno =
            try_seek_seqno(&cs.iter, *source_spec.opt_begin_seqno);
    }
    if (source_spec.opt_end_seqno) {
        monad_evcap_event_iter dummy_iter;
        monad_evcap_event_section_open_iterator(&cs.cur_section, &dummy_iter);
        iter->end_seqno =
            try_seek_seqno(&dummy_iter, *source_spec.opt_end_seqno);
    }
}
