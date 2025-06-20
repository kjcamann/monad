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

#include "init.hpp"
#include "command.hpp"
#include "err_cxx.hpp"
#include "file.hpp"
#include "metadata.hpp"
#include "options.hpp"
#include "parse.hpp"
#include "util.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <iterator>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>
#include <wordexp.h>

#include <zstd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/event/test_event_ctypes.h>
#include <category/core/mem/align.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

namespace fs = std::filesystem;

#if defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wc99-designator"
#endif

extern char const *__progname;

namespace
{

struct EventContentTypeToDefaultFileNameEntry
{
    std::string_view type_name;
    char const *default_file_name;
} EventContentTypeToDefaultFileNameTable[] = {
    [MONAD_EVENT_CONTENT_TYPE_NONE] =
        {.type_name =
             g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_NONE],
         .default_file_name = {}},
    [MONAD_EVENT_CONTENT_TYPE_TEST] =
        {.type_name =
             g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_TEST],
         .default_file_name = MONAD_EVENT_DEFAULT_TEST_FILE_NAME},
    [MONAD_EVENT_CONTENT_TYPE_EXEC] = {
        .type_name =
            g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_EXEC],
        .default_file_name = MONAD_EVENT_DEFAULT_EXEC_FILE_NAME}};

#if defined(__clang__)
    #pragma GCC diagnostic pop
#endif

constexpr size_t PAGE_2MB = 1UL << 21;

constexpr char const *describe(Command::Type t)
{
    using enum Command::Type;
    switch (t) {
    case BlockStat:
        return "blockstat";
    case Digest:
        return "digest";
    case Dump:
        return "dump";
    case ExecStat:
        return "execstat";
    case HeadStat:
        return "headstat";
    case Info:
        return "info";
    case Record:
        return "record";
    case RecordExec:
        return "recordexec";
    case SectionDump:
        return "sectiondump";
    case Snapshot:
        return "snapshot";
    }
    std::unreachable();
}

constexpr ThreadEntrypointFunction get_thread_entrypoint(Command::Type t)
{
    using enum Command::Type;
    switch (t) {
    case BlockStat:
        return blockstat_thread_main;
    case Digest:
        return digest_thread_main;
    case Dump:
        return dump_thread_main;
    case ExecStat:
        return execstat_thread_main;
    case HeadStat:
        return headstat_thread_main;
    case Record:
        return record_thread_main;
    case RecordExec:
        return recordexec_thread_main;
    case Snapshot:
        return snapshot_thread_main;
    default:
        break;
    }
    std::unreachable();
}

void try_insert_named_input(
    std::string const &named_input, fs::path const &canonical_path,
    NamedInputMap &input_map, std::string_view context)
{
    auto const [i_existing, inserted] =
        input_map.emplace(named_input, canonical_path);
    if (!inserted && !equivalent(canonical_path, i_existing->second)) {
        errx_f(
            EX_USAGE,
            "{} error: named input {} bound to {} but shadows existing binding "
            "{}->{}",
            context,
            named_input,
            canonical_path.string(),
            named_input,
            i_existing->second.string());
    }
}

fs::path resolve_event_source_file(
    ParsedEventSourceSpec const &ess, NamedInputMap &input_map,
    std::string_view context)
{
    auto const i_named_map_entry = input_map.find(ess.event_source_file);
    if (i_named_map_entry != input_map.end()) {
        if (!empty(ess.named_input)) {
            // Injecting an alias, e.g.,
            //   -i <name1>:path_to_file
            //   -i <name2>:<name1>
            try_insert_named_input(
                ess.named_input, i_named_map_entry->second, input_map, context);
        }
        return i_named_map_entry->second;
    }

    std::string unexpanded_input = ess.event_source_file;
    auto const *const i_default_entry = std::ranges::find(
        EventContentTypeToDefaultFileNameTable,
        ess.event_source_file,
        &EventContentTypeToDefaultFileNameEntry::type_name);
    if (i_default_entry !=
        std::ranges::end(EventContentTypeToDefaultFileNameTable)) {
        unexpanded_input = i_default_entry->default_file_name;
    }

    // Expand the source file as the shell would, using wordexp(3)
    wordexp_t exp;
    if (auto const rc = wordexp(
            unexpanded_input.c_str(), &exp, WRDE_SHOWERR | WRDE_UNDEF)) {
        errx_f(
            EX_CONFIG,
            "{} error: wordexp(3) of `{}` returned {}",
            context,
            unexpanded_input,
            rc);
    }
    else if (exp.we_wordc != 1) {
        errx_f(
            EX_CONFIG,
            "{} error: wordexp(3) of `{}` expanded to {} files; expected 1",
            context,
            unexpanded_input,
            exp.we_wordc);
    }
    fs::path input_file = exp.we_wordv[0];
    wordfree(&exp);

    if (!input_file.has_parent_path()) {
        char event_ring_default_dir[PATH_MAX];
        if (monad_event_open_hugetlbfs_dir_fd(
                nullptr,
                event_ring_default_dir,
                sizeof event_ring_default_dir) != 0) {
            errx_f(
                EX_SOFTWARE,
                "event library error -- {}",
                monad_event_ring_get_last_error());
        }
        // XXX: explain this complex selection logic...
        fs::path const default_path_ring_file =
            fs::path{event_ring_default_dir} / input_file;
        bool const use_default_path =
            exists(default_path_ring_file) || !exists(input_file);
        if (use_default_path) {
            input_file = default_path_ring_file;
        }
    }

    if (!exists(input_file)) {
        // TODO(ken): .string() because both standard libraries are still
        //  missing P2845
        errc_f(
            EX_CONFIG,
            std::errc::no_such_file_or_directory,
            "path `{}` is not an accessible event source file",
            input_file.string());
    }

    // Canonicalize the file and insert it into the
    fs::path const origin_path = canonical(input_file);
    if (!empty(ess.named_input)) {
        try_insert_named_input(
            ess.named_input, origin_path, input_map, context);
    }
    return origin_path;
}

void open_compressed_file(
    char const *zstd_file_path, std::span<char> file_magic,
    struct stat const &path_stat, int *fd)
{
    size_t const compressed_size = static_cast<size_t>(path_stat.st_size);
    void *const compressed_base = mmap(
        nullptr,
        static_cast<size_t>(path_stat.st_size),
        PROT_READ,
        MAP_SHARED,
        *fd,
        0);
    if (compressed_base == MAP_FAILED) {
        err_f(
            EX_OSERR, "mmap of zstd file `{}` contents failed", zstd_file_path);
    }

    size_t const decompressed_bound =
        ZSTD_decompressBound(compressed_base, compressed_size);
    if (decompressed_bound == ZSTD_CONTENTSIZE_ERROR) {
        errx_f(
            EX_SOFTWARE, "ZSTD_decompressBound error for `{}`", zstd_file_path);
    }
    size_t const memfd_size =
        monad_round_size_to_align(decompressed_bound, PAGE_2MB);

    std::string const memfd_name =
        std::format("memfd-unzstd:{}", zstd_file_path);
    // TODO(ken): needed to remove MFD_HUGETLB for huge snapshots, but still
    //    want it if we won't get ENOMEM
    int memfd = memfd_create(memfd_name.c_str(), MFD_CLOEXEC);
    if (memfd == -1) {
        err_f(EX_OSERR, "unable to open memfd file `{}`", memfd_name.c_str());
    }
    if (ftruncate(memfd, static_cast<off_t>(memfd_size)) == -1) {
        err_f(
            EX_OSERR,
            "ftruncate of memfd file `{}` failed",
            memfd_name.c_str());
    }
    void *const decompressed_base =
        mmap(nullptr, memfd_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (decompressed_base == MAP_FAILED) {
        err_f(EX_OSERR, "mmap of memfd file `{}` failed", memfd_name.c_str());
    }
    size_t const decompressed_size = ZSTD_decompress(
        decompressed_base, memfd_size, compressed_base, compressed_size);
    if (ZSTD_isError(decompressed_size)) {
        errx_f(
            EX_SOFTWARE,
            "zstd error decompressing `{}`: {}",
            zstd_file_path,
            ZSTD_getErrorName(decompressed_size));
    }
    if (decompressed_size < size(file_magic)) {
        errx_f(
            EX_CONFIG,
            "zstd file `{}` is an event file (magic underflow)",
            zstd_file_path);
    }

    // Remove the compressed mapping, and copy the decompressed magic bytes
    // into `magic` as if we read them fd, then remove the decompressed mapping
    // and proceed as if memfd had actually been opened as fd
    munmap(compressed_base, compressed_size);
    std::memcpy(data(file_magic), decompressed_base, size(file_magic));
    munmap(decompressed_base, memfd_size);
    std::swap(*fd, memfd);
    (void)close(memfd);
}

constexpr size_t MAGIC_SIZE = std::max(
    sizeof MONAD_EVCAP_FILE_MAGIC, sizeof MONAD_EVENT_RING_HEADER_VERSION);
static_assert(MAGIC_SIZE >= sizeof ZSTD_MAGICNUMBER);

// The safe way to get a table entry, because the input data may be malformed
MetadataTableEntry const &get_metadata_table_entry(
    fs::path const &path, monad_event_content_type content_type)
{
    if (std::to_underlying(content_type) >= std::size(MetadataTable)) {
        errx_f(
            EX_CONFIG,
            "we do not have the metadata mapping for event source `{}` type {}",
            path.string(),
            std::to_underlying(content_type));
    }

    // Check that the schema hash has been initialized
    if (MetadataTable[content_type].schema_hash == nullptr) {
        errx_f(
            EX_CONFIG,
            "event source `{}` has type {}, but we don't know its metadata "
            "hash",
            path.string(),
            std::to_underlying(content_type));
    }

    return MetadataTable[std::to_underlying(content_type)];
}

std::unique_ptr<EventSourceFile>
try_create_block_archive(fs::path const &origin_path)
{
    monad_bcap_block_archive *archive;
    char const *const dirname = origin_path.c_str();
    int const dirfd = open(dirname, O_DIRECTORY | O_PATH | O_CLOEXEC);
    if (dirfd == -1) {
        err_f(
            EX_OSERR,
            "unable to open(2) block archive directory `{}`",
            dirname);
    }
    if (monad_bcap_block_archive_open(&archive, dirfd, dirname)) {
        errx_f(
            EX_SOFTWARE,
            "blockcap library error -- {}",
            monad_bcap_get_last_error());
    }
    return std::make_unique<BlockArchiveDirectory>(origin_path, dirfd, archive);
}

std::unique_ptr<EventSourceFile> try_create_event_ring_file(
    fs::path const &origin_path, int ring_fd, bool loaded_from_zstd)
{
    EventRingLiveness initial_liveness;
    if (loaded_from_zstd) {
        initial_liveness = EventRingLiveness::Snapshot;
    }
    else {
        initial_liveness = event_ring_is_abandoned(ring_fd)
                               ? EventRingLiveness::Abandoned
                               : EventRingLiveness::Live;
    }

    int mmap_extra_flags = MAP_POPULATE;
    // Map this event ring into our address space
    monad_event_ring event_ring;
    if (monad_event_ring_mmap(
            &event_ring,
            PROT_READ,
            mmap_extra_flags,
            ring_fd,
            0,
            origin_path.c_str()) != 0) {
        errx_f(
            EX_SOFTWARE,
            "event library error -- {}",
            monad_event_ring_get_last_error());
    }

    auto const content_type = event_ring.header->content_type;
    MetadataTableEntry const &meta_entry =
        get_metadata_table_entry(origin_path, content_type);

    if (monad_event_ring_check_content_type(
            &event_ring, content_type, *meta_entry.schema_hash) != 0) {
        errx_f(
            EX_CONFIG,
            "event ring library error while loading {}:\n{}",
            origin_path.string(),
            monad_event_ring_get_last_error());
    }

    return std::make_unique<MappedEventRing>(
        origin_path, ring_fd, initial_liveness, event_ring);
}

std::unique_ptr<EventSourceFile>
try_create_event_capture_file(fs::path const &origin_path, int fd)
{
    monad_evcap_reader *evcap_reader;
    monad_evcap_section_desc const *sd = nullptr;

    if (monad_evcap_reader_create(&evcap_reader, fd, origin_path.c_str()) !=
        0) {
        errx_f(
            EX_SOFTWARE,
            "evcap library error -- {}",
            monad_evcap_reader_get_last_error());
    }

    while (monad_evcap_reader_next_section(
               evcap_reader, MONAD_EVCAP_SECTION_SCHEMA, &sd) != nullptr) {
        auto const content_type = sd->schema.content_type;
        MetadataTableEntry const &meta_entry =
            get_metadata_table_entry(origin_path, content_type);
        if (monad_evcap_reader_check_schema(
                evcap_reader,
                MONAD_EVENT_RING_HEADER_VERSION,
                content_type,
                *meta_entry.schema_hash) != 0) {
            errx_f(
                EX_SOFTWARE,
                "evcap library error for {} -- {}",
                origin_path.string(),
                monad_evcap_reader_get_last_error());
        }
    }

    return std::make_unique<EventCaptureFile>(origin_path, fd, evcap_reader);
}

// Helper function which can open regular or zstd-compressed event ring files
// and map them into the local process' address space; it can also open event
// capture files; the process will exit if the open fails
std::unique_ptr<EventSourceFile>
try_create_event_source_file(fs::path const &path, struct stat const &path_stat)
{
    std::array<char, MAGIC_SIZE> magic;
    char const *const path_cstr = path.c_str();

    if (path_stat.st_mode & S_IFDIR) {
        return try_create_block_archive(path);
    }
    if ((path_stat.st_mode & S_IFREG) != S_IFREG) {
        errx_f(
            EX_USAGE,
            "file `{}` is not a block archive directory "
            "or a regular file",
            path.string());
    }

    int fd = open(path_cstr, O_RDONLY);
    if (fd == -1) {
        err_f(EX_OSERR, "unable to open(2) event source file `{}`", path_cstr);
    }

    // Read the first few bytes so we can figure out if this is a regular event
    // ring file, a compressed one, a capture file, etc.
    if (ssize_t const nr = read(fd, data(magic), size(magic)); nr == -1) {
        err_f(
            EX_CONFIG,
            "could not read magic number from event source file `{}`",
            path_cstr);
    }
    else if (static_cast<size_t>(nr) < size(magic)) {
        errx_f(
            EX_CONFIG,
            "file `{}` does not appear to be an event ring file, snapshot, or "
            "capture",
            path_cstr);
    }

    bool const is_zstd_compressed =
        *reinterpret_cast<unsigned const *>(data(magic)) == ZSTD_MAGICNUMBER;
    if (is_zstd_compressed) {
        // This is a zstd-compressed file. Call a helper function to open it,
        // which will create a memfd to hold the decompressed contents; this
        // will become the new fd (it will close the original compressed fd)
        open_compressed_file(path_cstr, magic, path_stat, &fd);
    }

    if (std::memcmp(data(magic), "RING", 4) == 0) {
        return try_create_event_ring_file(path, fd, is_zstd_compressed);
    }
    if (std::memcmp(data(magic), "EVCAP_", 6) == 0) {
        return try_create_event_capture_file(path, fd);
    }
    errx_f(
        EX_CONFIG,
        "file `{}` does not appear to be an event source file",
        path_cstr);
}

EventSourceFile *get_or_create_event_source_file(
    fs::path const &path, std::unordered_set<ino_t> const &force_live_set,
    EventSourceFileMap &event_source_files)
{
    struct stat path_stat;
    if (stat(path.c_str(), &path_stat) == -1) {
        err_f(EX_OSERR, "stat(2) of `{}` failed", path.string());
    }
    auto i_source_file = event_source_files.find(path_stat.st_ino);
    if (i_source_file == end(event_source_files)) {
        std::tie(i_source_file, std::ignore) = event_source_files.emplace(
            path_stat.st_ino, try_create_event_source_file(path, path_stat));
        if (force_live_set.contains(path_stat.st_ino) &&
            i_source_file->second->get_type() ==
                EventSourceFile::Type::EventRing) {
            auto *const mr =
                static_cast<MappedEventRing *>(i_source_file->second.get());
            (void)mr->set_force_live(true);
        }
    }
    return i_source_file->second.get();
}

OutputFile *get_or_create_output_file(
    std::string const &output_spec, OutputFileMap &output_map)
{
    struct stat output_stat;
    ino_t inode = 0;
    bool is_stdout = false;
    if (empty(output_spec) || output_spec == "-") {
        if (fstat(STDOUT_FILENO, &output_stat) == -1) {
            err_f(EX_OSERR, "could not stat(2) stdout");
        }
        inode = output_stat.st_ino;
        is_stdout = true;
    }
    else if (exists(fs::path{output_spec})) {
        if (stat(output_spec.c_str(), &output_stat) == -1) {
            err_f(EX_OSERR, "stat(2) of `{}` failed", output_spec);
        }
        if ((output_stat.st_mode & S_IFMT) != S_IFREG) {
            errc_f(
                EX_CONFIG,
                std::errc::invalid_argument,
                "output `{}` exists but is not a regular file",
                output_spec);
        }
        inode = output_stat.st_ino;
    }
    if (auto const i = output_map.find(inode); i != end(output_map)) {
        return i->second.get();
    }
    if (is_stdout) {
        auto const [i_output, _] = output_map.emplace(
            inode, std::make_unique<OutputFile>("/dev/stdout", stdout));
        return i_output->second.get();
    }
    std::FILE *const file = std::fopen(output_spec.c_str(), "w");
    if (file == nullptr) {
        err_f(EX_OSERR, "fopen(3) of `{}` failed", output_spec);
    }
    auto const [i_output, _] = output_map.emplace(
        inode,
        std::make_unique<OutputFile>(canonical(fs::path{output_spec}), file));
    return i_output->second.get();
}

void assign_command_to_thread(
    std::string const &thread_name, Command *command,
    ThreadEntrypointFunction thread_main, ThreadMap &thread_map)
{
    auto const [i_command, inserted] = thread_map.try_emplace(
        thread_name, ThreadInput{std::move(thread_main), {command}});
    if (!inserted) {
        // This thread already exists, make sure it's hosting commands of the
        // same type
        for (Command const *c : i_command->second.commands) {
            if (command->type != c->type) {
                errx_f(
                    EX_USAGE,
                    "{} command placed on thread `{}`, but "
                    "thread is already hosting a command with incompatible "
                    "type {}",
                    describe(command->type),
                    thread_name,
                    describe(c->type));
            }
        }
        i_command->second.commands.push_back(command);
    }
    command->thread_map_location = i_command;
}

void expect_content_type(
    EventSourceFile const *const source_file,
    monad_event_content_type expected_content_type)
{
    // Ensure that the source is either:
    //
    //   1. An event ring file with the expected type
    //
    //   2. An event capture file with a SCHEMA section of that type
    EventSourceFile::Type const file_type = source_file->get_type();
    if (file_type == EventSourceFile::Type::EventRing) {
        MappedEventRing const *const mr =
            static_cast<MappedEventRing const *>(source_file);
        if (auto const actual_content_type = mr->get_header()->content_type;
            actual_content_type != expected_content_type) {
            errx_f(
                EX_CONFIG,
                "expected event ring file {} to have content type {} [{}]"
                "but found type {} [{}]",
                mr->describe(),
                g_monad_event_content_type_names[expected_content_type],
                std::to_underlying(expected_content_type),
                g_monad_event_content_type_names[actual_content_type],
                std::to_underlying(actual_content_type));
        }
    }
    else if (file_type == EventSourceFile::Type::EventCaptureFile) {
        EventCaptureFile const *const capture_file =
            static_cast<EventCaptureFile const *>(source_file);
        monad_evcap_section_desc const *sd = nullptr;
        monad_evcap_reader const *evcap_reader = capture_file->get_reader();
        bool has_expected_content_type = false;

        while (monad_evcap_reader_next_section(
            evcap_reader, MONAD_EVCAP_SECTION_SCHEMA, &sd)) {
            if (sd->schema.content_type == expected_content_type) {
                has_expected_content_type = true;
            }
        }

        if (!has_expected_content_type) {
            errx_f(
                EX_CONFIG,
                "expected event capture file {} to have a "
                "metadata section with type {} [{}] but one was not found",
                capture_file->describe(),
                g_monad_event_content_type_names[expected_content_type],
                std::to_underlying(expected_content_type));
        }
    }
    else if (file_type == EventSourceFile::Type::BlockArchiveDirectory) {
        constexpr monad_event_content_type ActualContentType =
            MONAD_EVENT_CONTENT_TYPE_EXEC;
        if (expected_content_type != ActualContentType) {
            errx_f(
                EX_CONFIG,
                "expected content type {} [{}] but loaded a finalized "
                "block archive source, while only supports type {} [{}]",
                g_monad_event_content_type_names[expected_content_type],
                std::to_underlying(expected_content_type),
                g_monad_event_content_type_names[ActualContentType],
                std::to_underlying(ActualContentType));
        }
    }
    else {
        MONAD_ABORT("unsupported file type");
    }
}

} // End of anonymous namespace

CommandBuilder::CommandBuilder(
    std::span<std::pair<std::string, std::string> const> named_input_specs,
    std::span<std::string const> force_live_specs)
{
    for (auto const &[name, spec] : named_input_specs) {
        ParsedEventSourceSpec const phony_parsed_spec = {
            .named_input = name,
            .event_source_file = spec,
            .capture_spec = {},
        };
        (void)resolve_event_source_file(
            phony_parsed_spec, named_input_map_, "input spec processing");
    }

    for (std::string const &f : force_live_specs) {
        struct stat ring_stat;
        if (auto ex = parse_event_source_spec(f)) {
            // XXX: errx_f if `ex->capture_spec` is not empty?
            fs::path const ring_path = resolve_event_source_file(
                *ex, named_input_map_, "--force-live translation");
            if (stat(ring_path.c_str(), &ring_stat) == -1) {
                err_f(EX_OSERR, "stat(2) of `{}` failed", ring_path.string());
            }
            force_live_set_.insert(ring_stat.st_ino);
        }
        else {
            errx_f(
                EX_USAGE,
                "parse error in --force-live spec `{}`: {}",
                f,
                ex.error());
        }
    }
}

Command *
CommandBuilder::build_blockstat_command(BlockStatCommandOptions const &opts)
{
    Command *const command = build_basic_command(
        Command::Type::BlockStat, opts.common_options, /*set_output=*/true);
    expect_content_type(
        command->event_sources[0].source_file, MONAD_EVENT_CONTENT_TYPE_EXEC);
    return command;
}

Command *CommandBuilder::build_digest_command(DigestCommandOptions const &opts)
{
    return build_basic_command(
        Command::Type::Digest, opts.common_options, /*set_output=*/true);
}

Command *CommandBuilder::build_dump_command(DumpCommandOptions const &opts)
{
    return build_basic_command(
        Command::Type::Dump,
        opts.common_options,
        /*set_output=*/true);
}

Command *
CommandBuilder::build_execstat_command(ExecStatCommandOptions const &opts)
{
    Command *const command = build_basic_command(
        Command::Type::ExecStat,
        opts.common_options,
        /*set_output=*/true);
    expect_content_type(
        command->event_sources[0].source_file, MONAD_EVENT_CONTENT_TYPE_EXEC);
    return command;
}

Command *
CommandBuilder::build_headstat_command(HeadStatCommandOptions const &opts)
{
    std::vector<EventSourceSpec> source_specs;

    for (std::string const &input : opts.inputs) {
        if (auto ex_spec = parse_event_source_spec(input)) {
            fs::path const event_ring_path = resolve_event_source_file(
                *ex_spec, named_input_map_, "headstat subcommand");
            EventSourceFile *const source_file =
                get_or_create_event_source_file(
                    event_ring_path,
                    force_live_set_,
                    topology_.event_source_files);
            if (!source_file->is_interactive()) {
                std::println(
                    stderr,
                    "{}: headstat subcommand ignoring non-interactive file: {}",
                    __progname,
                    source_file->describe());
                continue;
            }
            source_specs.emplace_back(
                source_file, std::nullopt, std::nullopt, std::nullopt);
        }
        else {
            errx_f(
                EX_USAGE,
                "parse error in headstat event source `{}`: {}",
                input,
                ex_spec.error());
        }
    }

    OutputFile *const output = get_or_create_output_file(
        opts.common_options.output_spec, topology_.output_file_map);
    auto command = std::make_unique<Command>(
        Command::Type::HeadStat, source_specs, output, &opts);

    std::string const target_thread = empty(opts.common_options.thread)
                                          ? "hdr_stat"
                                          : opts.common_options.thread;
    assign_command_to_thread(
        target_thread,
        command.get(),
        headstat_thread_main,
        topology_.thread_map);

    return topology_.commands.emplace_back(std::move(command)).get();
}

Command *CommandBuilder::build_info_command(InfoCommandOptions const &opts)
{
    std::vector<EventSourceSpec> source_specs;

    for (std::string const &input : opts.inputs) {
        if (auto ex_spec = parse_event_source_spec(input)) {
            fs::path const event_source_path = resolve_event_source_file(
                *ex_spec, named_input_map_, "info subcommand");
            EventSourceFile *const source_file =
                get_or_create_event_source_file(
                    event_source_path,
                    force_live_set_,
                    topology_.event_source_files);
            source_specs.emplace_back(
                source_file, std::nullopt, std::nullopt, std::nullopt);
        }
        else {
            errx_f(
                EX_USAGE,
                "parse error in info event source `{}`: {}",
                input,
                ex_spec.error());
        }
    }
    OutputFile *const output = get_or_create_output_file(
        opts.common_options.output_spec, topology_.output_file_map);
    auto command = std::make_unique<Command>(
        Command::Type::Info, source_specs, output, &opts);
    return topology_.commands.emplace_back(std::move(command)).get();
}

Command *CommandBuilder::build_record_command(RecordCommandOptions const &opts)
{
    return build_basic_command(
        Command::Type::Record,
        opts.common_options,
        /*set_output=*/false);
}

Command *
CommandBuilder::build_recordexec_command(RecordExecCommandOptions const &opts)
{
    Command *const command = build_basic_command(
        Command::Type::RecordExec,
        opts.common_options,
        /*set_output=*/false);
    expect_content_type(
        command->event_sources[0].source_file, MONAD_EVENT_CONTENT_TYPE_EXEC);
    if (opts.block_format == BlockRecordFormat::Archive) {
        // In this case, output is expected to already exist and be a directory
        if (!fs::is_directory(opts.common_options.output_spec)) {
            errx_f(
                EX_USAGE,
                "recordexec configured in finalized block archive "
                "mode, but {} is not an existing directory",
                opts.common_options.output_spec);
        }
    }
    return command;
}

Command *
CommandBuilder::build_sectiondump_command(SectionDumpCommandOptions const &opts)
{
    std::vector<EventSourceSpec> source_specs;
    std::string const &source_spec = opts.common_options.event_source_spec;
    if (auto ex_spec = parse_event_source_spec(source_spec)) {
        fs::path const event_source_path = resolve_event_source_file(
            *ex_spec, named_input_map_, "info subcommand");
        EventSourceFile *const source_file = get_or_create_event_source_file(
            event_source_path, force_live_set_, topology_.event_source_files);
        if (source_file->get_type() !=
            EventSourceFile::Type::EventCaptureFile) {
            errx_f(
                EX_USAGE,
                "sectiondump expected an evcap file, but found {}",
                source_file->describe());
        }
        if (!ex_spec->capture_spec.empty()) {
            errx_f(
                EX_USAGE,
                "sectiondump expected an empty capture-spec trailing, "
                "found {}; use -j,--section instead",
                ex_spec->capture_spec);
        }
        source_specs.emplace_back(
            source_file, std::nullopt, std::nullopt, std::nullopt);
    }
    else {
        errx_f(
            EX_USAGE,
            "parse error in sectiondump evcap source `{}`: {}",
            source_spec,
            ex_spec.error());
    }
    OutputFile *const output = get_or_create_output_file(
        opts.common_options.output_spec, topology_.output_file_map);
    auto command = std::make_unique<Command>(
        Command::Type::SectionDump, source_specs, output, &opts);
    return topology_.commands.emplace_back(std::move(command)).get();
}

Command *
CommandBuilder::build_snapshot_command(SnapshotCommandOptions const &opts)
{
    return build_basic_command(
        Command::Type::Snapshot, opts.common_options, /*set_output=*/true);
}

Command *CommandBuilder::build_basic_command(
    Command::Type command_type, CommonCommandOptions const &common_opts,
    bool set_output)
{
    std::optional<SequenceNumberSpec> opt_begin_seqno;
    std::optional<SequenceNumberSpec> opt_end_seqno;
    std::string const context =
        describe(command_type) + std::string{" subcommand"};

    // Parse --begin-seqno and --end-seqno, and do some basic checking of them
    if (!empty(common_opts.begin_seqno)) {
        if (auto ex = parse_sequence_number_spec(common_opts.begin_seqno)) {
            opt_begin_seqno = *ex;
        }
        else {
            errx_f(
                EX_USAGE,
                "{} --begin-seqno parse error: {}",
                context,
                ex.error());
        }
    }
    if (!empty(common_opts.end_seqno)) {
        if (auto ex = parse_sequence_number_spec(common_opts.end_seqno)) {
            opt_end_seqno = *ex;
        }
        else {
            errx_f(
                EX_USAGE,
                "{} --end-seqno parse error: {}",
                context,
                ex.error());
        }
    }
    if (opt_begin_seqno && opt_end_seqno &&
        opt_begin_seqno->type == SequenceNumberSpec::Type::Number &&
        opt_end_seqno->type == SequenceNumberSpec::Type::Number &&
        opt_end_seqno->seqno < opt_begin_seqno->seqno) {
        errc_f(
            EX_USAGE,
            std::errc::invalid_argument,
            "{} error: end sequence number {} occurs before start "
            "sequence number {}",
            context,
            opt_end_seqno->seqno,
            opt_begin_seqno->seqno);
    }

    auto ex_parsed_source_spec =
        parse_event_source_spec(common_opts.event_source_spec);
    if (!ex_parsed_source_spec) {
        errx_f(
            EX_USAGE,
            "{} error: unable to parse event source specification: {}",
            context,
            ex_parsed_source_spec.error());
    }

    // Parse the event source specification
    ParsedEventSourceSpec const parsed_source_spec =
        std::move(*ex_parsed_source_spec);

    // Parse the trailing capture specification from the event source
    std::optional<EventCaptureSpec> opt_capture_spec;
    if (!empty(parsed_source_spec.capture_spec)) {
        if (auto ex =
                parse_event_capture_spec(parsed_source_spec.capture_spec)) {
            opt_capture_spec = *ex;
        }
        else {
            errx_f(
                EX_USAGE,
                "{} capture specification parse error: {}",
                context,
                ex.error());
        }
    }

    // Resolve the parsed event source specification to a canonical disk file
    fs::path const origin_path = resolve_event_source_file(
        parsed_source_spec,
        named_input_map_,
        describe(command_type) + std::string{" subcommand"});

    EventSourceFile *const source_file = get_or_create_event_source_file(
        origin_path, force_live_set_, topology_.event_source_files);

    if (source_file->get_type() ==
            EventSourceFile::Type::BlockArchiveDirectory &&
        opt_capture_spec) {
        opt_capture_spec->use_block_number = true;
    }

    // Create the EventSourceSpec that describes the source file and the
    // dynamic range of inputs it supplies, then give it to the source file
    // to validate (e.g., to check if the range parameters make sense)
    EventSourceSpec const source_spec = {
        .source_file = source_file,
        .opt_capture_spec = opt_capture_spec,
        .opt_begin_seqno = opt_begin_seqno,
        .opt_end_seqno = opt_end_seqno};
    if (std::string const error = source_file->validate(source_spec);
        !empty(error)) {
        errx_f(
            EX_SOFTWARE,
            "event source specification {} rejected by "
            "source validation against {}: {}",
            common_opts.event_source_spec,
            source_file->describe(),
            error);
    }

    // Unless certain options (thread, output, etc.) are specified, they use
    // the values from the most recent command of this same type
    auto const r = std::ranges::find_last_if(
        topology_.commands,
        [command_type](std::unique_ptr<Command> const &cmd) {
            return cmd->has_type(command_type);
        });
    Command const *const last_typed_command =
        empty(r) ? nullptr : static_cast<Command const *>(begin(r)->get());

    std::string target_thread =
        empty(common_opts.thread) && last_typed_command
            ? last_typed_command->get_common_options()->thread
            : common_opts.thread;
    if (empty(target_thread)) {
        target_thread = describe(command_type) + std::string{"_thr"};
    }
    OutputFile *output = nullptr;
    if (set_output) {
        output = std::empty(common_opts.output_spec) && last_typed_command
                     ? last_typed_command->output
                     : get_or_create_output_file(
                           common_opts.output_spec, topology_.output_file_map);
    }
    auto command = std::make_unique<Command>(
        command_type, std::span{&source_spec, 1uz}, output, &common_opts);
    assign_command_to_thread(
        target_thread,
        command.get(),
        get_thread_entrypoint(command_type),
        topology_.thread_map);
    return topology_.commands.emplace_back(std::move(command)).get();
}

Topology CommandBuilder::finish()
{
    Topology r{std::move(topology_)};
    named_input_map_.clear();
    force_live_set_.clear();
    return r;
}
