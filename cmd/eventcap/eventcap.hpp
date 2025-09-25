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

#include "options.hpp"

#include <array>
#include <concepts>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

enum monad_event_content_type : uint16_t;
enum monad_exec_event_type : uint16_t;
extern std::sig_atomic_t g_should_exit;

struct Command;
struct EventIterator;

class EventSourceFile;

// Represents a block number or block ID
struct BlockLabel
{
    enum class Type
    {
        BlockNumber,
        BlockId,
    };

    Type type;

    union
    {
        uint64_t block_number;
        std::array<uint8_t, 32> block_id;
    };
};

// Represents a directive to rewind to a consensus event using the
// exec_iter_help API
struct ConsensusEventSpec
{
    monad_exec_event_type consensus_type;
    std::optional<BlockLabel> opt_block_label;
};

// Represents a directive to seek to a given sequence number, either directly
// given as a number or represented as a ConsensusEventSpec search directive
struct SequenceNumberSpec
{
    enum class Type
    {
        Number,
        ConsensusEvent,
    };

    Type type;

    union
    {
        uint64_t seqno;
        ConsensusEventSpec consensus_event;
    };
};

// Represents a subset of an event capture file or finalized block archive;
// this range (which may be open on the right end, if no count is specified)
// can represent either EVENT_BUNDLE sections in a capture file, or entire
// single-block capture files in a block archive directory
struct EventCaptureSpec
{
    uint64_t first_section;
    std::optional<uint64_t> count;
    bool use_block_number;
};

// Represents a fully-parsed event source specification, plus the sequence
// number limit options that are usually present
struct EventSourceSpec
{
    EventSourceFile *source_file;
    std::optional<EventCaptureSpec> opt_capture_spec;
    std::optional<SequenceNumberSpec> opt_begin_seqno;
    std::optional<SequenceNumberSpec> opt_end_seqno;

    [[nodiscard]] std::string describe() const;

    [[nodiscard]] monad_event_content_type get_content_type() const;

    void init_iterator(EventIterator *) const;
};

using ThreadEntrypointFunction = std::function<void(std::span<Command *const>)>;

struct ThreadInput
{
    ThreadEntrypointFunction thread_main;
    std::vector<Command *> commands;
};

struct OutputFile
{
    ~OutputFile()
    {
        if (file && file != stdout && file != stderr) {
            std::fclose(file);
        }
    }

    std::filesystem::path canonical_path;
    std::FILE *file;
};

using ThreadMap = std::unordered_map<std::string, ThreadInput>;

struct Command
{
    enum class Type
    {
        BlockStat,
        Digest,
        Dump,
        ExecStat,
        HeadStat,
        Info,
        Record,
        RecordExec,
        Snapshot,
    };

    explicit Command(
        Type t, std::span<EventSourceSpec const> s, OutputFile *o,
        void const *parsed_command)
        : type{t}
        , event_sources{std::from_range, s}
        , output{o}
        , origin{parsed_command}
    {
    }

    bool has_type(Type t) const
    {
        return type == t;
    }

    CommonCommandOptions const *get_common_options() const
    {
        return static_cast<CommonCommandOptions const *>(origin);
    }

    template <typename T>
    T const *get_options() const
    {
        T const *cast = static_cast<T const *>(origin);
        switch (type) {
        case Type::BlockStat:
            return std::same_as<T, BlockStatCommandOptions> ? cast : nullptr;
        case Type::Digest:
            return std::same_as<T, DigestCommandOptions> ? cast : nullptr;
        case Type::Dump:
            return std::same_as<T, DumpCommandOptions> ? cast : nullptr;
        case Type::ExecStat:
            return std::same_as<T, ExecStatCommandOptions> ? cast : nullptr;
        case Type::HeadStat:
            return std::same_as<T, HeadStatCommandOptions> ? cast : nullptr;
        case Type::Info:
            return std::same_as<T, InfoCommandOptions> ? cast : nullptr;
        case Type::Record:
            return std::same_as<T, RecordCommandOptions> ? cast : nullptr;
        case Type::RecordExec:
            return std::same_as<T, RecordExecCommandOptions> ? cast : nullptr;
        case Type::Snapshot:
            return std::same_as<T, SnapshotCommandOptions> ? cast : nullptr;
        default:
            return nullptr;
        }
    }

    Type type;
    std::vector<EventSourceSpec> event_sources;
    OutputFile *output;
    void const *origin;
    ThreadMap::const_iterator thread_map_location;
};

void print_event_source_headers(
    std::span<EventSourceSpec const>, bool print_full_section_table,
    std::FILE *);

void blockstat_thread_main(std::span<Command *const>);

void digest_thread_main(std::span<Command *const>);

void dump_thread_main(std::span<Command *const>);

void execstat_thread_main(std::span<Command *const>);

void headstat_thread_main(std::span<Command *const>);

void record_thread_main(std::span<Command *const>);

void recordexec_thread_main(std::span<Command *const>);

void snapshot_thread_main(std::span<Command *const>);
