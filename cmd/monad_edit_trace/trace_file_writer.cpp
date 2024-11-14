#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <stdexcept>
#include <format>
#include <map>
#include <span>
#include <system_error>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <monad/trace/trace_file.h>

#include "trace_file_reader.hpp"
#include "trace_file_writer.hpp"

namespace fs = std::filesystem;

MonadTraceFileWriter::~MonadTraceFileWriter()
{
    if (trace_file_) {
        monad_trace_file_destroy(trace_file_);
        trace_file_ = nullptr;
    }
}

MonadTraceFileWriter::DynamicSectionWriter
MonadTraceFileWriter::open_dynamic_section(monad_trace_section_desc **sd)
{
    monad_trace_dynamic_section *dyn_section;
    if (monad_trace_file_open_dynamic_section(trace_file_, &dyn_section, sd) != 0) {
        throw std::runtime_error{
            std::format("monad_trace_file_open_dynamic_page failed: {}",
                monad_trace_file_get_last_error())};
    }

    // Allocate a dynamic memory block to use
    size_t const event_page_size = 1UL << 21;
#if defined(__linux__)
    int const map_flags = MAP_ANON | MAP_PRIVATE | MAP_HUGETLB;
#else
    int const map_flags = MAP_ANON | MAP_PRIVATE;
#endif

    std::byte *const event_page_begin =
        static_cast<std::byte *>(mmap(nullptr, event_page_size, PROT_READ | PROT_WRITE, map_flags, -1, 0));
    if (event_page_begin == MAP_FAILED) {
        throw std::system_error{std::make_error_code(std::errc{errno}),
            "mmap of merge page memory failed"};
    }

    return DynamicSectionWriter{this, event_page_begin, event_page_size, dyn_section};
}

void MonadTraceFileWriter::copy_section(MonadTraceFileReader const &tf_reader,
    monad_trace_section_desc const *sd)
{
    // Copies a section that is already part of some memory-mapped file.
    std::byte const *const map_base = tf_reader.get_mapped_file().base_addr;
    std::span const section_bits{map_base + sd->offset, sd->length};
    return write_section(sd, section_bits);
}

void MonadTraceFileWriter::write_section(monad_trace_section_desc const *sd,
    std::span<std::byte const> bits)
{
    if (monad_trace_file_write_section(trace_file_, sd, data(bits), size(bits)) < 0) {
        throw std::runtime_error{
            std::format("monad_trace_file_write_section failed: {}",
                monad_trace_file_get_last_error())};
    }
}

void MonadTraceFileWriter::write_domain_metadata(monad_event_domain_metadata const *edm)
{
    if (monad_trace_file_write_domain_metadata(trace_file_, edm) < 0) {
        throw std::runtime_error{
            std::format("monad_trace_file_write_domain_metadata: {}",
                monad_trace_file_get_last_error())};
    }
}

MonadTraceFileWriter MonadTraceFileWriter::create(int fd)
{
    monad_trace_file *trace_file;
    if (monad_trace_file_create(&trace_file, nullptr) != 0) {
        throw std::system_error{std::make_error_code(std::errc{errno}),
            "monad_trace_file_create failed"};
    }
    if (monad_trace_file_set_output(trace_file, fd) != 0) {
        throw std::runtime_error{std::format(
            "monad_trace_file_set_output failed: {}",
            monad_trace_file_get_last_error())};
    }
    return MonadTraceFileWriter{trace_file};
}

std::expected<MonadTraceFileWriter, std::error_condition>
MonadTraceFileWriter::create(fs::path const &file_path)
{
    // Create the output file and create a merged trace file writer for it
    constexpr int output_oflag = O_CREAT | O_RDWR | O_TRUNC;
    constexpr mode_t output_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    int const fd = open(file_path.c_str(), output_oflag, output_mode);
    if (fd == -1) {
        return std::unexpected(std::make_error_condition(std::errc{errno}));
    }
    MonadTraceFileWriter tf_writer = create(fd);
    close(fd); // The `monad_trace_file` object makes a dup(2) copy
    return tf_writer;
}

MonadTraceFileWriter::DynamicSectionWriter::~DynamicSectionWriter()
{
    sync_full_event_page();
    (void)monad_trace_file_close_dynamic_section(tf_writer_->trace_file_, dyn_section_);
    munmap(event_page_begin_, event_page_end_ - event_page_begin_);
}

void MonadTraceFileWriter::DynamicSectionWriter::sync_full_event_page()
{
    if (monad_trace_file_sync_dynamic_section(tf_writer_->trace_file_, dyn_section_,
        event_page_begin_, event_page_next_ - event_page_begin_) != 0) {
        throw std::runtime_error{std::format(
            "unable to sync merge page: {}",
            monad_trace_file_get_last_error())};
    }
    event_page_next_ = event_page_begin_;
}
