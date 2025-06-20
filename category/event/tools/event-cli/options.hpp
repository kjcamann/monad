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
 * The eventcap utility is configured via CLI11 subcommands, each of which
 * populates an instance of a "command options" structure that captures the
 * inputs for an operation.
 *
 * Common fields in command options structures include:
 *
 *   - `ring_spec` specifies which event ring file to operate on. It can be
 *     one of the three things:
 *
 *     1. a path to a file
 *
 *     2. the name of an event ring type (e.g., `exec` or `test`) in which case
 *        the default path for that event ring type will be used
 *
 *     3. the label of a "named input" created by the -i,--input option; this
 *        allows multiple subcommands to easily reference the same file path,
 *        e.g.:
 *
 *           eventcap -i foo:/nonstandard/path dump -r foo header -r foo
 *
 *  - `thread` specifies which thread to run on
 *
 *  - `output_spec` specifies an output file, which will be `stdout` if it is
 *    blank or the value `-`
 *
 * Command options structures represent raw input from CLI11 and not much input
 * validation has been performed on them. They will be analyzed for validity
 * when a formal `Command` structure is created for them (see eventcap.hpp).
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

enum monad_exec_event_type : uint16_t;

enum class TextUIMode : unsigned
{
    Never,
    Always,
    Auto
};

struct SemanticSequenceNumber
{
    monad_exec_event_type consensus_type;
    std::variant<std::monostate, uint64_t, std::array<std::byte, 32>>
        block_label;
};

using SequenceNumberSpec = std::variant<uint64_t, SemanticSequenceNumber>;

// Must be the first member field of all options structures; not all commands
// use all of these options, but they're common enough to share a lot of
// options processing in init.cpp
struct CommonCommandOptions
{
    std::string ring_spec;
    std::string thread;
    std::string output_spec;
    std::optional<SequenceNumberSpec> start_seqno;
    std::optional<uint64_t> end_seqno;
};

// blockstat subcommand
struct BlockStatCommandOptions
{
    CommonCommandOptions common_options;
    std::optional<unsigned> outlier_size;
    std::optional<unsigned> long_txn_time_min_txn;
    std::optional<unsigned> gas_efficiency_min_txn;
    bool display_blocks;
};

// digest subcommand
struct DigestCommandOptions
{
    CommonCommandOptions common_options;
    bool erase_timestamps;
    bool erase_payload_offset;
    uint8_t erase_content_ext_mask;
};

// dump subcommand; there is one of these for each ring you want to dump
struct DumpCommandOptions
{
    CommonCommandOptions common_options;
    bool hexdump;
    bool decode;
    bool always_dump_content_ext;
};

// execstat subcommand
struct ExecStatCommandOptions
{
    CommonCommandOptions common_options;
    TextUIMode tui_mode;
};

// header subcommand; even if the subcommand is repeated there is only one of
// these (but the `ring_specs` list is merged, and the single ring_spec in
// `common_options` is left empty)
struct HeaderCommandOptions
{
    CommonCommandOptions common_options;
    std::vector<std::string> inputs;
    std::optional<uint32_t> stats_interval;
    bool discard_zero_samples;
    bool full_evcap_section_table;
    TextUIMode tui_mode;
};

// record subcommand
struct RecordCommandOptions
{
    CommonCommandOptions common_options;
    uint8_t vbuf_segment_shift;
    std::optional<uint8_t> seqno_zstd_level;
    bool no_seqno_index;
    bool print_backpressure_stats;
};

// recordexec subcommand
struct RecordExecCommandOptions
{
    CommonCommandOptions common_options;
    uint8_t vbuf_segment_shift;
    std::optional<uint8_t> event_zstd_level;
    std::optional<uint8_t> seqno_zstd_level;
};

// snapshot subcommand
struct SnapshotCommandOptions
{
    CommonCommandOptions common_options;
    uint8_t vbuf_segment_shift;
    bool kill_at_end;
    bool erase_timestamps;
};
