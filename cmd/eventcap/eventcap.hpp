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

#include <concepts>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iterator>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/types.h>

extern std::sig_atomic_t g_should_exit;

struct Command;
class EventSource;

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

using NamedInputMap = std::unordered_map<std::string, std::filesystem::path>;
using ThreadMap = std::unordered_map<std::string, ThreadInput>;
using EventSourceMap = std::unordered_map<ino_t, std::unique_ptr<EventSource>>;
using OutputFileMap = std::unordered_map<ino_t, std::unique_ptr<OutputFile>>;

struct Command
{
    enum class Type
    {
        BlockStat,
        Digest,
        Dump,
        ExecStat,
        Header,
        Record,
        RecordExec,
        Snapshot,
    };

    explicit Command(
        Type t, std::span<EventSource *> s, OutputFile *o,
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
        case Type::Header:
            return std::same_as<T, HeaderCommandOptions> ? cast : nullptr;
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
    std::vector<EventSource *> event_sources;
    OutputFile *output;
    void const *origin;
    ThreadMap::const_iterator thread_map_location;
};

struct Topology
{
    std::vector<std::unique_ptr<Command>> commands;
    EventSourceMap event_sources;
    ThreadMap thread_map;
    OutputFileMap output_file_map;
};

class CommandBuilder
{
public:
    explicit CommandBuilder(
        std::span<std::pair<std::string, std::string> const> named_input_specs,
        std::span<std::string const> force_live_specs);

    Topology finish();

    Command *build_blockstat_command(BlockStatCommandOptions const &);
    Command *build_digest_command(DigestCommandOptions const &);
    Command *build_dump_command(DumpCommandOptions const &);
    Command *build_execstat_command(ExecStatCommandOptions const &);
    Command *build_header_command(HeaderCommandOptions const &);
    Command *build_record_command(RecordCommandOptions const &);
    Command *build_recordexec_command(RecordExecCommandOptions const &);
    Command *build_snapshot_command(SnapshotCommandOptions const &);

private:
    Command *build_basic_command(
        Command::Type, CommonCommandOptions const &, bool set_output);

    Topology topology_;
    NamedInputMap named_input_map_;
    std::unordered_set<ino_t> force_live_set_;
};

void print_event_source_headers(
    std::span<EventSource const *const>, bool print_full_section_table,
    std::FILE *);

void blockstat_thread_main(std::span<Command *const>);

void digest_thread_main(std::span<Command *const>);

void dump_thread_main(std::span<Command *const>);

void execstat_thread_main(std::span<Command *const>);

void header_stats_thread_main(std::span<Command *const>);

void record_thread_main(std::span<Command *const>);

void recordexec_thread_main(std::span<Command *const>);

void snapshot_thread_main(std::span<Command *const>);
