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
#include "eventsource.hpp"
#include "metadata.hpp"
#include "options.hpp"
#include "util.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <variant>
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
#include <category/core/hex.hpp>
#include <category/core/mem/align.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

namespace fs = std::filesystem;

#if defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wc99-designator"
#endif

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
    case Header:
        return "header";
    case Record:
        return "record";
    case RecordExec:
        return "recordexec";
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
    case Header:
        return header_stats_thread_main;
    case Record:
        return record_thread_main;
    case RecordExec:
        return recordexec_thread_main;
    case Snapshot:
        return snapshot_thread_main;
    }
    std::unreachable();
}

fs::path resolve_input_spec(std::string const &input)
{
    std::string unexpanded_input = input;
    auto const i_entry = std::ranges::find(
        EventContentTypeToDefaultFileNameTable,
        input,
        &EventContentTypeToDefaultFileNameEntry::type_name);
    if (i_entry != std::ranges::end(EventContentTypeToDefaultFileNameTable)) {
        unexpanded_input = i_entry->default_file_name;
    }

    // Expand the ring file as the shell would, using wordexp(3)
    wordexp_t exp;
    if (auto const rc = wordexp(
            unexpanded_input.c_str(), &exp, WRDE_SHOWERR | WRDE_UNDEF)) {
        errx_f(
            EX_CONFIG, "wordexp(3) of `{}` returned {}", unexpanded_input, rc);
    }
    else if (exp.we_wordc != 1) {
        errx_f(
            EX_CONFIG,
            "wordexp(3) of `{}` expanded to {} files; expected 1",
            unexpanded_input,
            exp.we_wordc);
    }
    fs::path input_file = exp.we_wordv[0];
    wordfree(&exp);

    if (!input_file.has_parent_path()) {
        char event_ring_default_dir[PATH_MAX];
        if (monad_event_open_ring_dir_fd(
                nullptr,
                event_ring_default_dir,
                sizeof event_ring_default_dir) != 0) {
            errx_f(
                EX_SOFTWARE,
                "event library error -- {}",
                monad_event_ring_get_last_error());
        }
        input_file = fs::path{event_ring_default_dir} / input_file;
    }

    if (!is_regular_file(input_file)) {
        // TODO(ken): .string() because both standard libraries are still
        //  missing P2845
        errc_f(
            EX_CONFIG,
            std::errc::no_such_file_or_directory,
            "path `{}` is not an accessible event ring file",
            input_file.string());
    }
    return canonical(input_file);
}

fs::path resolve_ring_spec(
    std::string const &ring_spec, NamedInputMap &named_input_map,
    std::string_view resolve_context)
{
    if (empty(ring_spec)) {
        errx_f(
            EX_USAGE,
            "no event ring specification provided to {}",
            resolve_context);
    }
    // <ring-spec> can introduce a new named input
    auto const colon_index = ring_spec.find(':');
    if (colon_index != std::string::npos) {
        std::string const name = ring_spec.substr(0, colon_index);
        fs::path const resolved =
            resolve_input_spec(ring_spec.substr(colon_index + 1));
        auto const [i_named, inserted] =
            named_input_map.try_emplace(name, resolved);
        if (!inserted && !equivalent(i_named->second, resolved)) {
            errx_f(
                EX_CONFIG,
                "<ring-spec> `{}` introduced in {} resolves "
                "to `{}` which shadows previous value `{}`",
                ring_spec,
                resolve_context,
                resolved.string(),
                i_named->second.string());
        }
        return resolved;
    }
    // Otherwise try to resolve <ring-spec> via lookup of a named input,
    // or resolve it as an ordinary input
    auto const i_named = named_input_map.find(ring_spec);
    return i_named != end(named_input_map) ? i_named->second
                                           : resolve_input_spec(ring_spec);
}

void open_compressed_file(
    char const *zstd_file_path, std::span<char> file_magic,
    EventSourceFile &source_file)
{
    struct stat zstd_file_stat;
    if (fstat(source_file.fd, &zstd_file_stat) == -1) {
        err_f(EX_OSERR, "unable to stat zstd file `{}`", zstd_file_path);
    }
    size_t const compressed_size = static_cast<size_t>(zstd_file_stat.st_size);
    void *const compressed_base = mmap(
        nullptr,
        static_cast<size_t>(zstd_file_stat.st_size),
        PROT_READ,
        MAP_SHARED,
        source_file.fd,
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
    std::swap(source_file.fd, memfd);
    (void)close(memfd);
}

constexpr size_t MAGIC_SIZE = std::max(
    sizeof MONAD_EVCAP_FILE_MAGIC, sizeof MONAD_EVENT_RING_HEADER_VERSION);
static_assert(MAGIC_SIZE >= sizeof ZSTD_MAGICNUMBER);

std::span<monad_event_metadata const> get_metadata_entries(
    monad_event_content_type content_type, fs::path const &path,
    uint8_t const *file_hash)
{
    if (std::to_underlying(content_type) >= std::size(MetadataTable)) {
        errx_f(
            EX_CONFIG,
            "we do not have the metadata mapping for event source `{}` type {}",
            path.string(),
            std::to_underlying(content_type));
    }

    // Get the metadata hash we're compiled with, or substitute the zero
    // hash if the command line told us to
    if (MetadataTable[content_type].schema_hash == nullptr) {
        errx_f(
            EX_CONFIG,
            "event source `{}` has type {}, but we don't know its metadata "
            "hash",
            path.string(),
            std::to_underlying(content_type));
    }

    // Check that our compile-time library has the same metadata version as
    // this file
    uint8_t const(&library_hash)[32] = *MetadataTable[content_type].schema_hash;
    if (memcmp(&library_hash, file_hash, sizeof library_hash) != 0) {
        using monad::as_hex;
        errx_f(
            EX_CONFIG,
            "event content type {} [{}] has schema hash {:{#}} "
            "in the library but {:{#}} in event ring file `{}`",
            g_monad_event_content_type_names[content_type],
            std::to_underlying(content_type),
            as_hex(std::span{library_hash}),
            as_hex(std::span{file_hash, 32}),
            path.string());
    }

    return MetadataTable[content_type].entries;
}

std::unique_ptr<EventSource> try_load_event_ring_file(
    EventSourceFile source_file, std::array<char, MAGIC_SIZE> magic,
    bool loaded_from_zstd)
{
    EventRingLiveness initial_liveness;
    if (loaded_from_zstd) {
        initial_liveness = EventRingLiveness::Snapshot;
    }
    else {
        initial_liveness = event_ring_is_abandoned(source_file.fd)
                               ? EventRingLiveness::Abandoned
                               : EventRingLiveness::Live;
    }

    if (std::memcmp(
            data(magic),
            MONAD_EVENT_RING_HEADER_VERSION,
            sizeof MONAD_EVENT_RING_HEADER_VERSION) != 0) {
        MONAD_ASSERT(
            std::memcmp(data(magic), "RING", 4) == 0,
            "caller is supposed to check this");
        // This starts with "RING", so it's a different version of the file
        // format that we're compiled to support
        std::string_view const file_magic{
            data(magic), sizeof MONAD_EVENT_RING_HEADER_VERSION};
        std::string_view const library_magic{
            std::bit_cast<char *>(&MONAD_EVENT_RING_HEADER_VERSION),
            sizeof MONAD_EVENT_RING_HEADER_VERSION};
        errx_f(
            EX_CONFIG,
            "event ring library is version {}, file version is {}",
            library_magic,
            file_magic);
    }

    int mmap_extra_flags = MAP_POPULATE;
    if (initial_liveness != EventRingLiveness::Snapshot) {
        bool fs_supports_hugetlb;
        if (monad_check_path_supports_map_hugetlb(
                source_file.origin_path.c_str(), &fs_supports_hugetlb) != 0) {
            errx_f(
                EX_SOFTWARE,
                "event library error -- {}",
                monad_event_ring_get_last_error());
        }
        mmap_extra_flags |= fs_supports_hugetlb ? MAP_HUGETLB : 0;
    }

    // Map this event ring into our address space
    monad_event_ring event_ring;
    if (monad_event_ring_mmap(
            &event_ring,
            PROT_READ,
            mmap_extra_flags,
            source_file.fd,
            0,
            source_file.origin_path.c_str()) != 0) {
        errx_f(
            EX_SOFTWARE,
            "event library error -- {}",
            monad_event_ring_get_last_error());
    }

    auto const metadata_entries = get_metadata_entries(
        event_ring.header->content_type,
        source_file.origin_path,
        event_ring.header->schema_hash);

    return std::make_unique<MappedEventRing>(
        std::move(source_file), initial_liveness, event_ring, metadata_entries);
}

std::unique_ptr<EventSource> try_load_event_capture_file(
    EventSourceFile source_file, std::array<char, MAGIC_SIZE> magic)
{
    monad_evcap_reader *evcap_reader;
    if (std::memcmp(
            data(magic),
            MONAD_EVCAP_FILE_MAGIC,
            sizeof MONAD_EVCAP_FILE_MAGIC) != 0) {
        MONAD_ASSERT(
            std::memcmp(data(magic), "EVCAP_", 6) == 0,
            "caller is supposed to check this");
        std::string_view const file_magic{
            data(magic), sizeof MONAD_EVCAP_FILE_MAGIC};
        std::string_view const library_magic{
            std::bit_cast<char *>(&MONAD_EVCAP_FILE_MAGIC),
            sizeof MONAD_EVCAP_FILE_MAGIC};
        errx_f(
            EX_CONFIG,
            "event capture library is version {}, file version is {}",
            library_magic,
            file_magic);
    }
    if (monad_evcap_reader_create(
            &evcap_reader, source_file.fd, source_file.origin_path.c_str()) !=
        0) {
        errx_f(
            EX_SOFTWARE,
            "evcap library error -- {}",
            monad_evcap_reader_get_last_error());
    }

    monad_evcap_section_desc const *sd = nullptr;
    while (monad_evcap_reader_next_section(
               evcap_reader, MONAD_EVCAP_SECTION_SCHEMA, &sd) != nullptr) {
        if (memcmp(
                sd->schema.ring_magic,
                MONAD_EVENT_RING_HEADER_VERSION,
                sizeof MONAD_EVENT_RING_HEADER_VERSION) != 0) {
            MONAD_ABORT("write a nicer message here"); // XXX
        }
        (void)get_metadata_entries(
            sd->schema.content_type,
            source_file.origin_path,
            sd->schema.schema_hash);
    }

    return std::make_unique<EventCaptureFile>(
        std::move(source_file), evcap_reader);
}

// Helper function which can open regular or zstd-compressed event ring files
// and map them into the local process' address space; it can also open event
// capture files; the process will exit if the open fails
std::unique_ptr<EventSource>
try_load_event_source(fs::path const &event_file_path)
{
    std::array<char, MAGIC_SIZE> magic;
    char const *const event_file_cstr = event_file_path.c_str();
    EventSourceFile source_file = {
        .origin_path = event_file_path, .fd = open(event_file_cstr, O_RDONLY)};

    if (source_file.fd == -1) {
        err_f(
            EX_OSERR,
            "unable to open(2) event source file `{}`",
            event_file_cstr);
    }

    // Read the first few bytes so we can figure out if this is a regular event
    // ring file, a compressed one, a capture file, etc.
    if (ssize_t const nr = read(source_file.fd, data(magic), size(magic));
        nr == -1) {
        err_f(
            EX_CONFIG,
            "could not read magic number from event source file `{}`",
            event_file_cstr);
    }
    else if (static_cast<size_t>(nr) < size(magic)) {
        errx_f(
            EX_CONFIG,
            "file `{}` does not appear to be an event ring file, snapshot, or "
            "capture",
            event_file_cstr);
    }

    bool const is_zstd_compressed =
        *std::bit_cast<unsigned const *>(data(magic)) == ZSTD_MAGICNUMBER;
    if (is_zstd_compressed) {
        // This is a zstd-compressed file. Call a helper function to open it,
        // which will create a memfd to hold the decompressed contents; this
        // will become the new fd (it will close the original compressed fd)
        open_compressed_file(event_file_cstr, magic, source_file);
    }

    if (std::memcmp(data(magic), "RING", 4) == 0) {
        return try_load_event_ring_file(
            std::move(source_file), magic, is_zstd_compressed);
    }
    if (std::memcmp(data(magic), "EVCAP_", 6) == 0) {
        return try_load_event_capture_file(std::move(source_file), magic);
    }
    errx_f(
        EX_CONFIG,
        "file `{}` does not appear to be an event source file",
        event_file_cstr);
}

EventSource *get_or_create_event_source(
    fs::path const &event_path, std::unordered_set<ino_t> const &force_live_set,
    EventSourceMap &event_sources)
{
    struct stat event_stat;
    if (stat(event_path.c_str(), &event_stat) == -1) {
        err_f(EX_OSERR, "stat(2) of `{}` failed", event_path.string());
    }
    auto i_event_source = event_sources.find(event_stat.st_ino);
    if (i_event_source == end(event_sources)) {
        std::tie(i_event_source, std::ignore) = event_sources.emplace(
            event_stat.st_ino, try_load_event_source(event_path));
        if (force_live_set.contains(event_stat.st_ino) &&
            i_event_source->second->get_type() ==
                EventSource::Type::EventRing) {
            auto *const mr =
                static_cast<MappedEventRing *>(i_event_source->second.get());
            (void)mr->set_force_live(true);
        }
    }
    return i_event_source->second.get();
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
    EventSource const *const source,
    monad_event_content_type expected_content_type)
{
    // Ensure that the source is either:
    //
    //   1. An event ring file with the expected type
    //
    //   2. An event capture file with a RING_METADATA section of that type
    EventSource::Type const source_type = source->get_type();
    if (source_type == EventSource::Type::EventRing) {
        MappedEventRing const *const mr =
            static_cast<MappedEventRing const *>(source);
        if (auto const actual_content_type = mr->get_header()->content_type;
            actual_content_type != expected_content_type) {
            errx_f(
                EX_CONFIG,
                "expected event ring file {} to have type {} [{}]"
                "but found type {} [{}]",
                mr->describe(),
                g_monad_event_content_type_names[expected_content_type],
                std::to_underlying(expected_content_type),
                g_monad_event_content_type_names[actual_content_type],
                std::to_underlying(actual_content_type));
        }
    }
    else {
        MONAD_ASSERT(source_type == EventSource::Type::CaptureFile);
        EventCaptureFile const *const capture =
            static_cast<EventCaptureFile const *>(source);
        monad_evcap_section_desc const *sd = nullptr;
        monad_evcap_reader const *evcap_reader = capture->get_reader();
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
                capture->describe(),
                g_monad_event_content_type_names[expected_content_type],
                std::to_underlying(expected_content_type));
        }
    }
}

} // End of anonymous namespace

CommandBuilder::CommandBuilder(
    std::span<std::pair<std::string, std::string> const> named_input_specs,
    std::span<std::string const> force_live_specs)
{
    for (auto const &[name, spec] : named_input_specs) {
        fs::path const ring_path = resolve_input_spec(spec);
        auto const [i_existing, inserted] =
            named_input_map_.try_emplace(name, ring_path);
        if (!inserted && !equivalent(i_existing->second, ring_path)) {
            errx_f(
                EX_USAGE,
                "input spec `{}` mapped to `{}`, then later to `{}`",
                name,
                i_existing->second.string(),
                ring_path.string());
        }
    }

    for (std::string const &f : force_live_specs) {
        struct stat ring_stat;
        fs::path const ring_path =
            resolve_ring_spec(f, named_input_map_, "--force-live translation");
        if (stat(ring_path.c_str(), &ring_stat) == -1) {
            err_f(EX_OSERR, "stat(2) of `{}` failed", ring_path.string());
        }
        force_live_set_.insert(ring_stat.st_ino);
    }
}

Command *
CommandBuilder::build_blockstat_command(BlockStatCommandOptions const &opts)
{
    Command *const command = build_basic_command(
        Command::Type::BlockStat, opts.common_options, /*set_output=*/true);
    expect_content_type(
        command->event_sources[0], MONAD_EVENT_CONTENT_TYPE_EXEC);
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
        command->event_sources[0], MONAD_EVENT_CONTENT_TYPE_EXEC);
    return command;
}

Command *CommandBuilder::build_header_command(HeaderCommandOptions const &opts)
{
    std::vector<EventSource *> event_sources;

    for (std::string const &spec : opts.inputs) {
        fs::path event_ring_path =
            resolve_ring_spec(spec, named_input_map_, "execstat subcommand");
        event_sources.push_back(get_or_create_event_source(
            std::move(event_ring_path),
            force_live_set_,
            topology_.event_sources));
    }

    OutputFile *const output = get_or_create_output_file(
        opts.common_options.output_spec, topology_.output_file_map);
    auto command = std::make_unique<Command>(
        Command::Type::Header, event_sources, output, &opts);

    if (opts.stats_interval) {
        std::string const target_thread = empty(opts.common_options.thread)
                                              ? "hdr_stat"
                                              : opts.common_options.thread;
        assign_command_to_thread(
            target_thread,
            command.get(),
            header_stats_thread_main,
            topology_.thread_map);
    }
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
        command->event_sources[0], MONAD_EVENT_CONTENT_TYPE_EXEC);
    return command;
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
    // TODO(ken): is there a way to do this kind of cross-option validation
    //   with CLI11?
    if (common_opts.start_seqno && common_opts.end_seqno &&
        std::holds_alternative<uint64_t>(*common_opts.start_seqno) &&
        *common_opts.end_seqno < std::get<uint64_t>(*common_opts.start_seqno)) {
        errc_f(
            EX_USAGE,
            std::errc::invalid_argument,
            "{} command error: end sequence number {} occurs before start "
            "sequence number {}",
            describe(command_type),
            *common_opts.end_seqno,
            std::get<uint64_t>(*common_opts.start_seqno));
    }

    fs::path const event_ring_path = resolve_ring_spec(
        common_opts.ring_spec,
        named_input_map_,
        describe(command_type) + std::string{" subcommand"});
    EventSource *es = get_or_create_event_source(
        std::move(event_ring_path), force_live_set_, topology_.event_sources);

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
        command_type, std::span{&es, 1uz}, output, &common_opts);
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
