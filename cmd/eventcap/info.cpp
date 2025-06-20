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
#include "file.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <print>
#include <ranges>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/hex.hpp>
#include <category/execution/ethereum/event/blockcap.h>

namespace
{

void print_event_ring_headers(
    std::span<MappedEventRing const *const> rings, std::FILE *out)
{
    // Print the event ring file header information:
    // <type-name> [<type-code>] <descriptor capacity> <descriptor byte size>
    //    <payload buf size> <context area size> <last write seqno>
    //    <next payload buf byte> <pbuf window start> <meta-hash> <file-name>
    std::println(
        out,
        "{:10} {:>9} {:>10} {:>10} {:>10} {:>12} {:>14} {:>14} {:14} {}",
        "TYPE",
        "DESC_CAP",
        "DESC_SZ",
        "PBUF_SZ",
        "CTX_SZ",
        "WR_SEQNO",
        "PBUF_NEXT",
        "PBUF_WIN",
        "METADATA_HASH",
        "FILE_NAME");
    for (MappedEventRing const *mr : rings) {
        using monad::as_hex;
        monad_event_ring_header const *const h = mr->get_header();
        std::println(
            out,
            "{:6} [{}] {:9} {:10} {:10} {:10} {:12} {:14} {:14} {:{#}14} {}",
            g_monad_event_content_type_names[h->content_type],
            std::to_underlying(h->content_type),
            h->size.descriptor_capacity,
            h->size.descriptor_capacity * sizeof(monad_event_descriptor),
            h->size.payload_buf_size,
            h->size.context_area_size,
            __atomic_load_n(&h->control.last_seqno, __ATOMIC_ACQUIRE),
            __atomic_load_n(&h->control.next_payload_byte, __ATOMIC_ACQUIRE),
            __atomic_load_n(&h->control.buffer_window_start, __ATOMIC_ACQUIRE),
            as_hex(std::span{h->schema_hash}.first(4)),
            mr->describe());
    }
}

void print_event_capture_header(
    EventCaptureFile const *capture, bool print_full_section_table,
    std::FILE *out)
{
    std::println(out, "{} section table", capture->describe());

    monad_evcap_reader const *const evcap_reader = capture->get_reader();
    monad_evcap_file_header const *const file_header =
        monad_evcap_reader_get_file_header(evcap_reader);
    std::byte const *const map_base = reinterpret_cast<std::byte const *>(
        monad_evcap_reader_get_mmap_base(evcap_reader));
    monad_evcap_section_desc const *sd = nullptr;
    std::span<monad_bcap_pack_index_entry const> pack_index_table;
    SectionTableLocation section_loc{};

    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_NONE, &sd)) {
        if (section_loc.sectab_index == 0) {
            print_evcap_sectab_header(out);
        }
        print_evcap_sectab_entry(section_loc, *sd, pack_index_table, out);
        ++section_loc.entry_number;
        if (sd->type == MONAD_EVCAP_SECTION_LINK) {
            ++section_loc.table_number;
            section_loc.entry_number = 0;
        }
        ++section_loc.sectab_index;

        switch (sd->type) {
        case MONAD_EVCAP_SECTION_PACK_INDEX:
            pack_index_table = std::span{
                reinterpret_cast<monad_bcap_pack_index_entry const *>(
                    map_base + sd->content_offset),
                sd->pack_index.block_count};
            break;
        default:
            break;
        }

        if (!print_full_section_table && section_loc.sectab_index > 10) {
            std::println(
                "skipping {} additional sections...",
                file_header->section_count - section_loc.sectab_index - 1);
            break;
        }
    }
}

void print_block_archive_info(
    BlockArchiveDirectory const *archive, std::FILE *out)
{
    std::println(out, "{} information:", archive->describe());
}

} // End of anonymous namespace

void print_event_source_headers(
    std::span<EventSourceSpec const> event_sources,
    bool print_full_section_table, std::FILE *out)
{
    auto const is_event_ring = [](EventSourceSpec const &ess) {
        return ess.source_file->get_type() == EventSourceFile::Type::EventRing;
    };
    auto const extract_event_ring = [](EventSourceSpec const &ess) {
        return static_cast<MappedEventRing const *>(ess.source_file);
    };
    auto event_ring_range = event_sources | std::views::filter(is_event_ring) |
                            std::views::transform(extract_event_ring);

    std::vector<MappedEventRing const *> const rings{
        std::from_range, event_ring_range};
    if (!empty(rings)) {
        print_event_ring_headers(rings, out);
    }

    auto const is_capture_file = [](EventSourceSpec const &ess) {
        return ess.source_file->get_type() ==
               EventSourceFile::Type::EventCaptureFile;
    };
    for (size_t i = 0; EventSourceSpec const &ess :
                       event_sources | std::views::filter(is_capture_file)) {
        if (i++ == 0) {
            std::println(out, "Event capture files:");
        }
        print_event_capture_header(
            static_cast<EventCaptureFile const *>(ess.source_file),
            print_full_section_table,
            out);
    }

    auto const is_archive_dir = [](EventSourceSpec const &ess) {
        return ess.source_file->get_type() ==
               EventSourceFile::Type::BlockArchiveDirectory;
    };
    for (size_t i = 0; EventSourceSpec const &ess :
                       event_sources | std::views::filter(is_archive_dir)) {
        if (i++ == 0) {
            std::println(out, "Block archives:");
        }
        print_block_archive_info(
            static_cast<BlockArchiveDirectory const *>(ess.source_file), out);
    }
}
