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
#include "options.hpp"
#include "util.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <iterator>
#include <memory>
#include <print>
#include <span>
#include <utility>

#include <sysexits.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/hex.hpp>
#include <category/execution/ethereum/event/blockcap.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <zstd.h>

namespace
{

std::unique_ptr<std::byte const[]> decompress_section(
    std::byte const *map_base, monad_evcap_section_desc const *sd)
{
    std::unique_ptr contents =
        std::make_unique_for_overwrite<std::byte[]>(sd->content_length);
    size_t const zstd_rc = ZSTD_decompress(
        contents.get(),
        sd->content_length,
        map_base + sd->content_offset,
        sd->file_length);
    if (ZSTD_isError(zstd_rc)) {
        errx_f(
            EX_SOFTWARE,
            "ZSTD_decompress error for compressed {} section: {}",
            g_monad_evcap_section_names[sd->type],
            ZSTD_getErrorName(zstd_rc));
    }
    return contents;
}

void digest(std::span<std::byte const> bytes, std::FILE *out)
{
    uint8_t section_digest[32];
    unsigned section_digest_size = sizeof section_digest;
    if (EVP_Digest(
            bytes.data(),
            bytes.size(),
            section_digest,
            &section_digest_size,
            EVP_sha256(),
            nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        errx_f(EX_SOFTWARE, "EVP_DigestInit_ex failed");
    }
    std::println(
        out,
        "SHA256 digest: {}",
        monad::as_hex(std::as_bytes(std::span{section_digest})));
}

void hexdump(std::span<std::byte const> bytes, size_t offset, std::FILE *out)
{
    std::byte const *const section_start = bytes.data();
    std::byte const *const section_end = section_start + bytes.size();
    char linebuf[80];
    for (std::byte const *line = section_start;
         line < section_end && g_should_exit == 0;
         line += 16) {
        // <offset> <8 bytes> <8 bytes>
        char *o = std::format_to(
            linebuf,
            "{:#08x} ",
            static_cast<size_t>(line - section_start) + offset);
        for (uint8_t b = 0; b < 16 && line + b < section_end; ++b) {
            o = std::format_to(o, "{:02x}", std::to_underlying(line[b]));
            if (b == 7) {
                *o++ = ' '; // Extra padding after 8 bytes
            }
        }
        *o++ = '\0';
        std::println(out, "{}", linebuf);
    }
}

} // End of anonymous namespace

void dump_evcap_sections(
    SectionDumpCommandOptions const *options,
    EventCaptureFile const *evcap_file, std::span<unsigned const> sections,
    std::FILE *out)
{
    std::span<monad_bcap_pack_index_entry const> pack_index_table;

    monad_evcap_reader const *const evcap_reader = evcap_file->get_reader();
    monad_evcap_file_header const *const file_header =
        monad_evcap_reader_get_file_header(evcap_reader);
    std::byte const *const map_base = reinterpret_cast<std::byte const *>(
        monad_evcap_reader_get_mmap_base(evcap_reader));
    auto i_section_input = std::begin(sections);
    monad_evcap_section_desc const *sd = nullptr;
    while (monad_evcap_reader_next_section(
               evcap_reader, MONAD_EVCAP_SECTION_NONE, &sd) &&
           i_section_input != std::end(sections)) {
        if (sd->index == *i_section_input) {
            print_evcap_sectab_header(out);
            print_evcap_sectab_entry(*file_header, *sd, pack_index_table, out);

            std::unique_ptr<std::byte const[]> decompressed_content;
            std::span section_content =
                std::span{map_base + sd->content_offset, sd->file_length};
            if (sd->compression != MONAD_EVCAP_COMPRESSION_NONE &&
                !options->no_decompress) {
                decompressed_content = decompress_section(map_base, sd);
                section_content =
                    std::span{decompressed_content.get(), sd->content_length};
            }
            if (options->digest) {
                digest(section_content, out);
            }
            if (options->hexdump) {
                // XXX: whether offset is section relative or file relative
                // should be configurable
                std::println(out, "Contents: {} bytes", sd->content_length);
                hexdump(section_content, /*offset*/ 0, out);
            }
            ++i_section_input;
        }

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
    }

    while (i_section_input != std::end(sections)) {
        std::println(out, "section #{} does not exist", *i_section_input++);
    }
}
