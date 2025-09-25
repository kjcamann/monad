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

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/hex.hpp>
#include <category/execution/ethereum/event/blockcap.h>

namespace
{

char const *describe(monad_evcap_section_compression c)
{
    switch (c) {
    case MONAD_EVCAP_COMPRESSION_NONE:
        return "*";
    case MONAD_EVCAP_COMPRESSION_ZSTD_SINGLE_PASS:
        return "Z1P";
    case MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING:
        return "ZST";
    default:
        return "?";
    }
}

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
    size_t sectab_index = 0;
    size_t table_number = 0;
    size_t entry_number = 0;

    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_NONE, &sd)) {
        if (sectab_index == 0) {
            // Print section table header
            // <index> [<tab>:<ent>] <section-type> <offset> <file-length>
            //    <compressed-length> <extra>
            std::println(
                out,
                "{:>6} {:>3}:{:<4} {:20} {:>12} {:>5} {:>12} {:>12} {:>12} {}",
                "INDEX",
                "TAB",
                "ENT",
                "SECTION_TYPE",
                "DESC_OFF",
                "COM",
                "CONTENT_OFF",
                "CONTENT_LEN",
                "FILE_LEN",
                "EXTRA");
        }
        std::print(
            out,
            "{:6} {:3}:{:<4} {:16} [{}] {:12} {:>5} {:12} {:12} {:12}",
            sectab_index,
            table_number,
            entry_number,
            g_monad_evcap_section_names[sd->type],
            std::to_underlying(sd->type),
            sd->descriptor_offset,
            describe(sd->compression),
            sd->content_offset,
            sd->content_length,
            sd->file_length);

        ++entry_number;
        if (sd->type == MONAD_EVCAP_SECTION_LINK) {
            ++table_number;
            entry_number = 0;
        }
        ++sectab_index;

        switch (sd->type) {
        case MONAD_EVCAP_SECTION_LINK:
            std::print(out, "   NEXT_TAB: {}", sd->content_offset);
            break;

        case MONAD_EVCAP_SECTION_SCHEMA:
            std::print(
                out,
                "   CONTENT_TYPE: {:6} [{}] HASH: {:{#}}",
                g_monad_event_content_type_names[sd->schema.content_type],
                std::to_underlying(sd->schema.content_type),
                monad::as_hex(std::span{sd->schema.schema_hash}.first(4)));
            break;

        case MONAD_EVCAP_SECTION_EVENT_BUNDLE:
            if (sd->event_bundle.pack_index_id == 0 ||
                empty(pack_index_table)) {
                std::print(
                    out,
                    "   SCH_OFF: {} #EVT: {} SSEQ: {} SIDX_OFF: {} BLK: {}",
                    sd->event_bundle.schema_desc_offset,
                    sd->event_bundle.event_count,
                    sd->event_bundle.start_seqno,
                    sd->event_bundle.seqno_index_desc_offset,
                    sd->event_bundle.block_number);
            }
            else {
                // We have a block index section descriptor (which usually
                // appears before event bundles because of how the writer
                // works)
                monad_bcap_pack_index_entry const &index_entry =
                    pack_index_table[sd->event_bundle.pack_index_id - 1];
                std::print(
                    out,
                    "   BLK: {:9} EVT: {:6} SIDX_OFF: {}",
                    index_entry.block_number,
                    sd->event_bundle.event_count,
                    sd->event_bundle.seqno_index_desc_offset);
            }
            break;

        case MONAD_EVCAP_SECTION_SEQNO_INDEX:
            std::print(
                out, "   EB_OFF: {}", sd->seqno_index.event_bundle_desc_offset);
            break;

        case MONAD_EVCAP_SECTION_PACK_INDEX:
            pack_index_table = std::span{
                reinterpret_cast<monad_bcap_pack_index_entry const *>(
                    map_base + sd->content_offset),
                sd->pack_index.block_count};
            std::print(
                out,
                "   ACT: {:c} START: {} END: {} CAP: {}",
                __atomic_load_n(&sd->pack_index.is_active, __ATOMIC_ACQUIRE)
                    ? 'Y'
                    : 'N',
                sd->pack_index.start_block,
                sd->pack_index.start_block +
                    __atomic_load_n(
                        &sd->pack_index.block_count, __ATOMIC_ACQUIRE),
                sd->pack_index.entry_capacity);
            break;

        case MONAD_EVCAP_SECTION_NONE:
            MONAD_ABORT("NONE section should not be returned by iterator");
        }
        std::println(out);

        if (!print_full_section_table && sectab_index > 10) {
            std::println(
                "skipping {} additional sections...",
                file_header->section_count - sectab_index - 1);
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
