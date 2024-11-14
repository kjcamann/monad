#pragma once

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>

#include <monad/mem/align.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_shmem.h>
#include <monad/trace/trace_file.h>

struct MappedFile
{
    MappedFile(std::filesystem::path const &p, std::byte const *b, size_t s)
        : file_path{p}
        , base_addr{b}
        , size{s}
    {
    }

    MappedFile(MappedFile &&);
    MappedFile(MappedFile const &) = delete;
    ~MappedFile();

    [[nodiscard]] static std::expected<MappedFile, std::error_condition>
    mmap_disk_file(std::filesystem::path const &);

    std::filesystem::path file_path;
    std::byte const *base_addr;
    size_t size;
};

class MonadTraceFileReader
{
public:
    struct SectionTableEntry;
    struct RecorderPage;
    struct MergePage;
    struct BlockPage;

    std::tuple<monad_event_domain_metadata const *, SectionTableEntry const *, bool>
    get_domain_metadata(monad_event_domain) const;

    std::tuple<
        monad_event_domain_metadata const *, monad_event_metadata const *, bool>
    get_event_metadata(monad_trace_event const &) const;

    bool domain_static_data_matches_file(monad_event_domain) const;

    MappedFile const &get_mapped_file() const
    {
        return mapped_file_;
    }

    monad_trace_file_header const &get_header() const
    {
        return *std::bit_cast<monad_trace_file_header const *>(
            mapped_file_.base_addr);
    }

    std::span<monad_event_thread_info const> get_thread_info() const
    {
        return thread_info_;
    }

    bool next_domain_metadata(SectionTableEntry *,
        monad_event_domain_metadata const **, bool *) const;

    bool next_section_table_entry(SectionTableEntry *) const;

    bool next_recorder_page(RecorderPage *) const;

    bool next_merge_page(MergePage *) const;

    bool next_block_page(BlockPage *) const;

    [[nodiscard]] static MonadTraceFileReader load(MappedFile);

private:
    bool next_merge_like_page(MergePage *, monad_trace_section_type) const;

    explicit MonadTraceFileReader(MappedFile mapped_file);

    struct DomainMetadataSection;

    MappedFile mapped_file_;
    std::unique_ptr<DomainMetadataSection[]> metadata_sections_;
    std::span<monad_event_thread_info const> thread_info_;
};

monad_event_domain_metadata const *
find_first_domain_integrity_mismatch(MonadTraceFileReader const &);

struct MonadTraceFileReader::SectionTableEntry
{
    uint64_t table_offset;
    size_t table_number;
    size_t table_index;
    size_t global_index;
    monad_trace_section_desc const *descriptor = nullptr;
};

struct MonadTraceFileReader::DomainMetadataSection
{
    SectionTableEntry sectab_entry;
    monad_event_domain_metadata domain_meta;
    std::unique_ptr<monad_event_metadata[]> event_meta;
    bool matches_static_data;
};

struct MonadTraceFileReader::RecorderPage
{
    uint64_t get_event_count() const
    {
        return sectab_entry.descriptor->recorder_page.event_count;
    }

    std::chrono::sys_time<std::chrono::nanoseconds> get_start_time() const
    {
        return std::chrono::sys_time{
            std::chrono::nanoseconds{evt_begin->epoch_nanos}};
    }

    bool next_event(monad_trace_event const **evt) const
    {
        if (*evt == nullptr) {
            *evt = evt_begin;
        }
        else {
            auto const end_address = std::bit_cast<uintptr_t>(*evt) +
                                     sizeof **evt + (*evt)->length;
            *evt = std::bit_cast<monad_trace_event const *>(
                monad_round_size_to_align(
                    end_address, alignof(monad_trace_event)));
        }
        if (*evt >= evt_end) {
            *evt = nullptr;
            return false;
        }
        return true;
    }

    ptrdiff_t page_number;
    SectionTableEntry sectab_entry;
    monad_trace_event const *evt_begin;
    monad_trace_event const *evt_end;
};

struct MonadTraceFileReader::MergePage
{
    std::chrono::sys_time<std::chrono::nanoseconds> get_start_time() const
    {
        return std::chrono::sys_time{
            std::chrono::nanoseconds{evt_begin->trace_evt.epoch_nanos}};
    }

    uint64_t get_event_count() const
    {
        return sectab_entry.descriptor->merge_page.event_count;
    }

    uint64_t get_block_count() const
    {
        return this->sectab_entry.descriptor->merge_page.block_count;
    }

    uint64_t get_elapsed_nanos() const
    {
        return this->sectab_entry.descriptor->merge_page.elapsed_nanos;
    }

    uint64_t get_txn_count() const
    {
        return this->sectab_entry.descriptor->merge_page.txn_count;
    }

    uint64_t get_total_gas() const
    {
        return this->sectab_entry.descriptor->merge_page.total_gas;
    }

    BlockPage const *as_block_page() const;

    bool next_event(monad_trace_merged_event const **merged_evt) const
    {
        if (*merged_evt == nullptr) {
            *merged_evt = evt_begin;
        }
        else {
            auto const end_address = std::bit_cast<uintptr_t>(*merged_evt) +
                                     sizeof **merged_evt + (*merged_evt)->trace_evt.length;
            *merged_evt = std::bit_cast<monad_trace_merged_event const *>(
                monad_round_size_to_align(
                    end_address, alignof(monad_trace_merged_event)));
        }
        if (*merged_evt >= evt_end) {
            *merged_evt = nullptr;
            return false;
        }
        return true;
    }

    ptrdiff_t page_number;
    SectionTableEntry sectab_entry;
    monad_trace_merged_event const *evt_begin;
    monad_trace_merged_event const *evt_end;
};

struct MonadTraceFileReader::BlockPage : MergePage
{
};

inline MonadTraceFileReader::BlockPage const *
MonadTraceFileReader::MergePage::as_block_page() const
{
    return sectab_entry.descriptor->type == MONAD_TRACE_SECTION_BLOCK_PAGE
        ? static_cast<BlockPage const *>(this)
        : nullptr;
}

inline std::tuple<monad_event_domain_metadata const *,
    MonadTraceFileReader::SectionTableEntry const *, bool>
MonadTraceFileReader::get_domain_metadata(monad_event_domain domain) const
{
    auto const &dms = metadata_sections_[std::to_underlying(domain)];
    if (dms.event_meta != nullptr) [[likely]] {
        return {&dms.domain_meta, &dms.sectab_entry, dms.matches_static_data};
    }
    return {nullptr, nullptr, false};
}

inline std::tuple<
    monad_event_domain_metadata const *, monad_event_metadata const *, bool>
MonadTraceFileReader::get_event_metadata(monad_trace_event const &evt) const
{
    auto const &dms =
        metadata_sections_[MONAD_EVENT_DOMAIN(evt.type)];
    if (dms.event_meta != nullptr) [[likely]] {
        return {&dms.domain_meta, &dms.event_meta[MONAD_EVENT_DRCODE(evt.type)],
            dms.matches_static_data};
    }
    return {nullptr, nullptr, false};
}

inline bool MonadTraceFileReader::domain_static_data_matches_file(monad_event_domain domain) const
{
    auto const &dms = metadata_sections_[domain];
    return dms.event_meta != nullptr ? dms.matches_static_data : false;
}
