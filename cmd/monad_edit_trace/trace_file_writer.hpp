#pragma once

#include <bit>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <span>
#include <utility>

#include <monad/mem/align.h>
#include <monad/trace/trace_file.h>

class MonadTraceFileReader;

class MonadTraceFileWriter
{
public:
    class DynamicSectionWriter;

    MonadTraceFileWriter(MonadTraceFileWriter const&) = delete;

    MonadTraceFileWriter(MonadTraceFileWriter&& other) noexcept
        : trace_file_{nullptr}
    {
        std::swap(trace_file_, other.trace_file_);
    }

    ~MonadTraceFileWriter();

    DynamicSectionWriter open_dynamic_section(monad_trace_section_desc **);

    void copy_section(MonadTraceFileReader const &, monad_trace_section_desc const *);

    void write_section(monad_trace_section_desc const *, std::span<std::byte const>);

    void write_domain_metadata(monad_event_domain_metadata const *);

    static MonadTraceFileWriter create(int fd);

    static std::expected<MonadTraceFileWriter, std::error_condition>
    create(std::filesystem::path const &);

private:
    explicit MonadTraceFileWriter(monad_trace_file *trace_file)
        : trace_file_{trace_file}
    {
    }

    monad_trace_file *trace_file_;
};

class MonadTraceFileWriter::DynamicSectionWriter
{
public:
    DynamicSectionWriter(DynamicSectionWriter const &) = delete;

    DynamicSectionWriter(DynamicSectionWriter&& other) noexcept
        : DynamicSectionWriter{nullptr, nullptr, 0, nullptr}
    {
        std::swap(tf_writer_, other.tf_writer_);
        std::swap(event_page_begin_, other.event_page_begin_);
        std::swap(event_page_next_, other.event_page_next_);
        std::swap(event_page_end_, other.event_page_end_);
        std::swap(dyn_section_, other.dyn_section_);
    }

    ~DynamicSectionWriter();

    monad_trace_merged_event *alloc_event(size_t event_size)
    {
        event_size = monad_round_size_to_align(event_size,
            alignof(monad_trace_merged_event));
        if (event_page_next_ + event_size > event_page_end_) {
            sync_full_event_page();
        }
        auto *const e =
            std::bit_cast<monad_trace_merged_event *>(event_page_next_);
        event_page_next_ += event_size;
        return e;
    }

    monad_trace_merged_event *copy_event(monad_trace_merged_event const *src)
    {
        size_t const total_size = sizeof *src + src->trace_evt.length;
        monad_trace_merged_event *const dst = alloc_event(total_size);
        memcpy(dst, src, total_size);
        return dst;
    }

private:
    void sync_full_event_page();

    friend class MonadTraceFileWriter;

    explicit DynamicSectionWriter(MonadTraceFileWriter *tf_writer,
        std::byte *event_page_buf, size_t event_page_size,
        monad_trace_dynamic_section *dyn_section)
        : tf_writer_{tf_writer}, event_page_begin_{event_page_buf}
        , event_page_next_{event_page_buf}
        , event_page_end_{event_page_buf + event_page_size}
        , dyn_section_{dyn_section}
    {
    }

    MonadTraceFileWriter *tf_writer_;
    std::byte *event_page_begin_;
    std::byte *event_page_next_;
    std::byte *event_page_end_;
    monad_trace_dynamic_section *dyn_section_;
};
