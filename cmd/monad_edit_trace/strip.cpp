#include <cstddef>
#include <cstring>
#include <exception>
#include <filesystem>
#include <set>
#include <string>
#include <utility>

#include <sysexits.h>
#include <unistd.h>

#include <monad/core/assert.h>
#include <monad/trace/trace_file.h>

#include "err_cxx.hpp"
#include "options.hpp"
#include "print_compat.hpp"
#include "trace_file_reader.hpp"
#include "trace_file_writer.hpp"

namespace fs = std::filesystem;

static void strip_sections(
    MonadTraceFileReader tf_reader,
    std::set<unsigned> const &sorted_sections,
    MonadTraceFileWriter tf_writer)
{
    MonadTraceFileReader::SectionTableEntry sectab_entry{};
    auto i_next_strip = begin(sorted_sections);
    auto const end_strip = end(sorted_sections);

    while (tf_reader.next_section_table_entry(&sectab_entry)) {
        bool const section_is_filtered_out = i_next_strip != end_strip &&
            *i_next_strip == sectab_entry.global_index;
        bool const section_is_safe_to_copy =
            sectab_entry.descriptor->type != MONAD_TRACE_SECTION_LINK;
        if (section_is_safe_to_copy && !section_is_filtered_out) {
            tf_writer.copy_section(tf_reader, sectab_entry.descriptor);
            continue;
        }

        // We are skipping this section, not copying it.
        MONAD_ASSERT(*i_next_strip == sectab_entry.global_index);
        ++i_next_strip;
    }
}

void strip_main(Options const *opts)
{
    fs::path const &input_file = opts->strip_options.input_file;
    auto ex_mapped_file = MappedFile::mmap_disk_file(input_file);
    if (!ex_mapped_file) {
        errc_f(
            EX_OSERR,
            ex_mapped_file.error(),
            "unable to mmap input file {}",
            input_file);
    }
    if (std::memcmp(
            ex_mapped_file->base_addr,
            MONAD_TRACE_FILE_MAGIC,
            sizeof MONAD_TRACE_FILE_MAGIC) != 0) {
        errx_f(EX_DATAERR, "input file `{}` has unknown format", input_file);
    }

    fs::path const output_file = opts->merge_options.output_file.empty()
        ? fs::path{input_file.filename().string() + ".stripped"}
        : opts->merge_options.output_file;

    auto ex_tf_writer = MonadTraceFileWriter::create(output_file);
    if (!ex_tf_writer) {
        errc_f(
            EX_OSERR,
            ex_tf_writer.error(),
            "unable to open output file {}",
            output_file);
    }

    try {
        strip_sections(
            MonadTraceFileReader::load(std::move(*ex_mapped_file)),
            opts->strip_options.section_numbers,
            std::move(*ex_tf_writer));
    }
    catch (std::exception const &ex)
    {
        // It failed, unlink the file
        (void)unlink(output_file.c_str());
        errx_f(EX_SOFTWARE, "error stripping sections from {}: {}",
            output_file, ex.what());
    }
}
