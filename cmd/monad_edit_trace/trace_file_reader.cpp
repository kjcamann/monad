#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <iterator>
#include <memory>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include <monad/core/keccak.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_shmem.h>
#include <monad/trace/trace_file.h>

#include "err_cxx.hpp"
#include "trace_file_reader.hpp"

namespace fs = std::filesystem;

constexpr size_t MaxMetadataSection = 256;

MappedFile::MappedFile(MappedFile &&other)
    : file_path{std::move(other.file_path)}
    , base_addr{other.base_addr}
    , size{other.size}
{
    other.base_addr = nullptr;
}

MappedFile::~MappedFile()
{
    if (base_addr != nullptr) {
        (void)munmap(const_cast<std::byte *>(base_addr), size);
    }
}

std::expected<MappedFile, std::error_condition>
MappedFile::mmap_disk_file(std::filesystem::path const &path)
{
    struct stat file_stat;
    int const fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        return std::unexpected(
            std::make_error_condition(static_cast<std::errc>(errno)));
    }
    if (fstat(fd, &file_stat) == -1) {
        return std::unexpected(
            std::make_error_condition(static_cast<std::errc>(errno)));
    }
    size_t const file_size = static_cast<size_t>(file_stat.st_size);
    void *const map_base =
        mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map_base == MAP_FAILED) {
        return std::unexpected(
            std::make_error_condition(static_cast<std::errc>(errno)));
    }
    MappedFile mapped_file{
        path, static_cast<std::byte const *>(map_base), file_size};
    (void)close(fd);
    return mapped_file;
}

MonadTraceFileReader::MonadTraceFileReader(MappedFile mapped_file)
    : mapped_file_{std::move(mapped_file)}
    , metadata_sections_{
          std::make_unique<DomainMetadataSection[]>(MaxMetadataSection)}
{
}

static void load_domain_metadata_section(
    std::byte const *map_base, monad_trace_section_desc const &sd,
    monad_event_domain_metadata &domain_meta,
    std::unique_ptr<monad_event_metadata[]> &event_meta)
{
    std::byte const *const section_base = map_base + sd.offset;

    domain_meta.domain = static_cast<monad_event_domain>(sd.domain_info.code);
    domain_meta.num_events = sd.domain_info.num_events;
    event_meta = std::make_unique<monad_event_metadata[]>(
        sd.domain_info.num_events);
    domain_meta.event_meta = event_meta.get();
    if (int const errc = monad_event_metadata_deserialize(
        std::bit_cast<char const *>(section_base),
        sd.length, &domain_meta, nullptr, nullptr)) {
        errc_f(EX_DATAERR, std::errc{errc}, "malformed metadata section");
    }
}

bool MonadTraceFileReader::next_domain_metadata(
    SectionTableEntry *sectab_entry,
    monad_event_domain_metadata const **domain_meta,
    bool *matches_static_data) const
{
    next_section_table_entry(sectab_entry);
    monad_trace_section_desc const *&sd = sectab_entry->descriptor;
    while (sd->type != MONAD_TRACE_SECTION_NONE &&
           sd->type != MONAD_TRACE_SECTION_DOMAIN_INFO) {
        next_section_table_entry(sectab_entry);
    }
    if (sd->type == MONAD_TRACE_SECTION_NONE) {
        return false;
    }
    DomainMetadataSection const &dms = metadata_sections_[sd->domain_info.code];
    *domain_meta = &dms.domain_meta;
    *matches_static_data = dms.matches_static_data;
    return true;
}

bool MonadTraceFileReader::next_section_table_entry(
    SectionTableEntry *sectab_entry) const
{
    // The SectionTableEntry is an iterator-like type. It is a smart wrapper
    // around the underlying section table descriptor, which points into the
    // memory mapped file.
    if (sectab_entry->descriptor == nullptr) {
        // First iteration. This always succeeds because the section table
        // is at least the size of one disk block, so even if the file contains
        // no data there will be a SECTION_NONE entry telling us we're done.
        sectab_entry->table_offset = get_header().sectab_offset;
        sectab_entry->descriptor = std::bit_cast<monad_trace_section_desc *>(
            mapped_file_.base_addr + sectab_entry->table_offset);
        sectab_entry->global_index = sectab_entry->table_index =
            sectab_entry->table_number = 0;
        return sectab_entry->descriptor->type != MONAD_TRACE_SECTION_NONE;
    }

    if (sectab_entry->descriptor->type == MONAD_TRACE_SECTION_NONE) {
        return false;
    }

    // Previous iteration was not NONE, so we can advance the section
    // descriptor.
    ++sectab_entry->global_index;
    if (sectab_entry->descriptor->type == MONAD_TRACE_SECTION_LINK) {
        sectab_entry->table_offset = sectab_entry->descriptor->offset;
        sectab_entry->descriptor =
            std::bit_cast<monad_trace_section_desc const *>(
                mapped_file_.base_addr + sectab_entry->table_offset);
        ++sectab_entry->table_number;
        sectab_entry->table_index = 0;
    }
    else {
        ++sectab_entry->descriptor;
        ++sectab_entry->table_index;
    }
    return sectab_entry->descriptor->type != MONAD_TRACE_SECTION_NONE;
}

bool MonadTraceFileReader::next_recorder_page(RecorderPage *recorder_page) const
{
    if (recorder_page->sectab_entry.descriptor == nullptr) {
        recorder_page->page_number = -1;
    }

    next_section_table_entry(&recorder_page->sectab_entry);
    // `sd` is a reference because the iteration mutates the descriptor pointer
    monad_trace_section_desc const *&sd = recorder_page->sectab_entry.descriptor;
    while (sd->type != MONAD_TRACE_SECTION_NONE &&
           sd->type != MONAD_TRACE_SECTION_RECORDER_PAGE) {
        next_section_table_entry(&recorder_page->sectab_entry);
    }

    if (sd->type == MONAD_TRACE_SECTION_NONE) {
        return false;
    }

    ++recorder_page->page_number;
    recorder_page->evt_begin = std::bit_cast<monad_trace_event const *>(
        mapped_file_.base_addr + sd->offset);
    recorder_page->evt_end = std::bit_cast<monad_trace_event const *>(
        mapped_file_.base_addr + sd->offset + sd->length);
    return true;
}

bool MonadTraceFileReader::next_merge_page(MergePage *merge_page) const
{
    return next_merge_like_page(merge_page, MONAD_TRACE_SECTION_MERGE_PAGE);
}

bool MonadTraceFileReader::next_block_page(BlockPage *block_page) const
{
    return next_merge_like_page(block_page, MONAD_TRACE_SECTION_BLOCK_PAGE);
}

bool MonadTraceFileReader::next_merge_like_page(
    MergePage *merge_page,
    monad_trace_section_type section_type) const
{
    // This function works for both MergeTracePage and BlockTracePage,
    // which are similar except for the section type
    if (merge_page->sectab_entry.descriptor == nullptr) {
        merge_page->page_number = -1;
    }

    next_section_table_entry(&merge_page->sectab_entry);
    monad_trace_section_desc const *&sd = merge_page->sectab_entry.descriptor;
    while (sd->type != MONAD_TRACE_SECTION_NONE &&
           sd->type != section_type) {
        next_section_table_entry(&merge_page->sectab_entry);
           }

    if (sd->type == MONAD_TRACE_SECTION_NONE) {
        return false;
    }

    ++merge_page->page_number;
    merge_page->evt_begin = std::bit_cast<monad_trace_merged_event const *>(
        mapped_file_.base_addr + sd->offset);
    merge_page->evt_end = std::bit_cast<monad_trace_merged_event const *>(
        mapped_file_.base_addr + sd->offset + sd->length);
    return true;
}

MonadTraceFileReader MonadTraceFileReader::load(MappedFile mapped_file)
{
    MonadTraceFileReader reader{std::move(mapped_file)};

    SectionTableEntry sectab_entry{};
    uint8_t meta_hash[KECCAK256_SIZE];
    char *metabuf;
    size_t metabuf_size;
    while (reader.next_section_table_entry(&sectab_entry)) {
        monad_trace_section_desc const &sd = *sectab_entry.descriptor;
        if (sd.type == MONAD_TRACE_SECTION_DOMAIN_INFO) {
            DomainMetadataSection &dms =
                reader.metadata_sections_[sd.domain_info.code];
            dms.sectab_entry = sectab_entry;
            load_domain_metadata_section(
                reader.mapped_file_.base_addr,
                sd,
                dms.domain_meta,
                dms.event_meta);
            if (sd.domain_info.code >= MONAD_EVENT_DOMAIN_COUNT) {
                dms.matches_static_data = false;
                continue;
            }
            if (int const rc = monad_event_metadata_serialize(
                &g_monad_event_domain_meta[sd.domain_info.code],
                &metabuf,
                &metabuf_size)) {
                errc_f(EX_DATAERR, std::errc{rc},
                    "monad_event_metadata_serialize failed for file {}",
                    mapped_file.file_path);
            }
            keccak256((uint8_t const *)metabuf, metabuf_size, meta_hash);
            dms.matches_static_data = memcmp(
                &sd.domain_info.keccak_24,
                meta_hash,
                sizeof sd.domain_info.keccak_24) == 0;
            std::free(metabuf);
        }
        else if (sd.type == MONAD_TRACE_SECTION_THREAD_INFO) {
            if (!empty(reader.thread_info_)) {
                errx_f(EX_DATAERR, "file {} contains multiple thread info "
                    "sections; expected 0 or 1", reader.mapped_file_.file_path);
            }
            auto const *thread_info =
                std::bit_cast<monad_event_thread_info const *>(
                    reader.mapped_file_.base_addr + sd.offset);
            reader.thread_info_ = {thread_info, sd.thread_info.thread_count};
        }
    }

    return reader;
}

monad_event_domain_metadata const *
find_first_domain_integrity_mismatch(MonadTraceFileReader const &tf_reader)
{
    MonadTraceFileReader::SectionTableEntry sectab_entry{};
    monad_event_domain_metadata const *domain_meta;
    bool matches_static_data;
    while (tf_reader.next_domain_metadata(&sectab_entry, &domain_meta,
        &matches_static_data)) {
        if (!matches_static_data) {
            return domain_meta;
        }
    }
    return nullptr;
}
