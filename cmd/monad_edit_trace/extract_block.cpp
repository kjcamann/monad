#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <set>
#include <utility>

#include <sysexits.h>
#include <unistd.h>

#include <monad/core/assert.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/trace/trace_file.h>

#include "err_cxx.hpp"
#include "options.hpp"
#include "print_compat.hpp"
#include "trace_file_reader.hpp"
#include "trace_file_writer.hpp"

namespace fs = std::filesystem;

static bool extract_single_block(
    MonadTraceFileReader::MergePage const &merge_page,
    monad_trace_merged_event const **merged_evt,
    MonadTraceFileWriter &tf_writer)
{
    monad_trace_section_desc *section_desc;
    MonadTraceFileWriter::DynamicSectionWriter writer =
        tf_writer.open_dynamic_section(&section_desc);
    section_desc->type = MONAD_TRACE_SECTION_BLOCK_PAGE;
    section_desc->merge_page.block_count = (*merged_evt)->flow_id;
    bool has_more_events = true;

    uint64_t event_count = 0;
    uint64_t txn_count = 0;
    uint64_t total_gas = 0;
    uint64_t const block_start_time = (*merged_evt)->trace_evt.epoch_nanos;
    uint64_t last_block_time = block_start_time;
    while (has_more_events &&
           (*merged_evt)->trace_evt.type != MONAD_EVENT_BLOCK_END) {
        (void)writer.copy_event(*merged_evt);

        if ((*merged_evt)->trace_evt.type == MONAD_EVENT_TXN_EXEC_END) {
            ++txn_count;
            total_gas += *std::bit_cast<uint64_t const *>(*merged_evt + 1);
        }

        // We need to copy the last seen timestamp on every iteration, because
        // if the sequence ends pre-maturely, `*merged_evt` will be set to
        // nullptr and it will be too late to access it
        last_block_time = (*merged_evt)->trace_evt.epoch_nanos;
        has_more_events = merge_page.next_event(merged_evt);
        ++event_count;
    }
    if (has_more_events) {
        // Copy the MONAD_EVENT_BLOCK_END event, but do not consume it (the
        // primary loop that finds the start of the block will do that)
        writer.copy_event(*merged_evt);
        last_block_time = (*merged_evt)->trace_evt.epoch_nanos;
        ++event_count;
    }
    section_desc->merge_page.event_count = event_count;
    section_desc->merge_page.elapsed_nanos = last_block_time - block_start_time;
    section_desc->merge_page.txn_count = txn_count;
    section_desc->merge_page.total_gas = total_gas;
    return has_more_events;
}

static void extract_blocks_from_merge_page(
    MonadTraceFileReader::MergePage const &merge_page,
    std::set<uint64_t> const &blocks,
    MonadTraceFileWriter &tf_writer)
{
    bool const have_filter = !empty(blocks); // Empty filter means everything
    auto i_next_block = begin(blocks);
    auto const end_block = end(blocks);

    // Because the execution engine handles one block at a time without any
    // inter-block pipelining, we can just iterate through the trace file and
    // use a dynamic section to handle incremental writing. If blocks were
    // interleaved, this would be more complex, since we would need to know the
    // full size of a (non-dynamic) section before writing it. Dynamic
    // sections are more flexible, but there can only be one of them at a time.

    monad_trace_merged_event const *merged_evt = nullptr;
    bool has_more_events = true;
    size_t block_count = 0;
    while (has_more_events && (!have_filter || i_next_block != end_block)) {
        // Find the start of the next block
        has_more_events = merge_page.next_event(&merged_evt);
        while (has_more_events &&
            merged_evt->trace_evt.type != MONAD_EVENT_BLOCK_START) {
            has_more_events = merge_page.next_event(&merged_evt);
        }
        if (!has_more_events) {
            break;
        }

        // A new block starts here. Run the filter logic
        if (have_filter) {
            MONAD_DEBUG_ASSERT(merged_evt->flow_type == MONAD_TRACE_FLOW_BLOCK);
            if (merged_evt->flow_id != *i_next_block) {
                // Skip over this block
                continue;
            }
            // Otherwise we'll allow this block; i_next_block
            ++i_next_block;
        }

        has_more_events =
            extract_single_block(merge_page, &merged_evt, tf_writer);
        if (++block_count % 1024 == 0) {
            // Occasionally print status
            std::print("\rextracted {} blocks", block_count);
            std::fflush(stdout);
        }
    }
    std::println("\rextracted {} blocks", block_count);
}

void extract_block_main(Options const *opts)
{
    fs::path const &input_file = opts->extract_block_options.input_file;
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

    MonadTraceFileReader const tf_reader =
        MonadTraceFileReader::load(std::move(*ex_mapped_file));

    for (auto domain : {MONAD_EVENT_DOMAIN_BLOCK, MONAD_EVENT_DOMAIN_TXN}) {
        if (!tf_reader.domain_static_data_matches_file(domain)) {
            errx_f(EX_DATAERR, "trace file {} metadata for domain `{}` does "
                "not match the program's static data; cannot continue",
                tf_reader.get_mapped_file().file_path,
                g_monad_event_domain_meta[domain].name);
        }
    }

    MonadTraceFileReader::MergePage merge_page{};
    MonadTraceFileReader::BlockPage block_page{};
    size_t merge_page_count = 0;
    size_t block_page_count = 0;
    while (tf_reader.next_merge_page(&merge_page)) {
        ++merge_page_count;
    }
    while (tf_reader.next_block_page(&block_page)) {
        ++block_page_count;
    }
    if (block_page_count == 0 && merge_page_count != 1) {
        errx_f(EX_DATAERR, "extract-block only works on trace files containing "
            "a single merge page; file {} contains {} merge pages", input_file,
            merge_page_count);
    }

    fs::path const output_file = opts->extract_block_options.output_file.empty()
        ? fs::path{input_file.filename().string() + ".block"}
        : opts->extract_block_options.output_file;

    auto ex_tf_writer = MonadTraceFileWriter::create(output_file);
    if (!ex_tf_writer) {
        errc_f(
            EX_OSERR,
            ex_tf_writer.error(),
            "unable to open output file {}",
            output_file);
    }

    try {
        // We need to copy over some of the sections from the original
        // file (e.g., the metadata sections). We might also copy the
        // original merge page over in its entirety, if this is a "combined"
        // block file.
        MonadTraceFileReader::SectionTableEntry sectab_entry{};
        while (tf_reader.next_section_table_entry(&sectab_entry)) {
            switch (sectab_entry.descriptor->type) {
            case MONAD_TRACE_SECTION_RECORDER_PAGE:
                [[fallthrough]]; // We always ignore these
            case MONAD_TRACE_SECTION_LINK:
                [[fallthrough]]; // Must ignore to not corrupt the section table
            case MONAD_TRACE_SECTION_BLOCK_PAGE:
                continue; // Block -> block copies are handled below

            case MONAD_TRACE_SECTION_MERGE_PAGE:
                if (!opts->extract_block_options.combined_block_file) {
                    continue; // Skip if it's not a combined file
                }
                [[fallthrough]]; // Otherwise fall through to also copy this

            default:
                ex_tf_writer->copy_section(tf_reader, sectab_entry.descriptor);
            }
        }

        std::set<uint64_t> blocks = opts->extract_block_options.blocks;
        if (merge_page_count > 0 && !opts->extract_block_options.always_try_prune) {
            // We have a merge page; try to pull the blocks from there
            extract_blocks_from_merge_page(merge_page, blocks, *ex_tf_writer);
        }
        else {
            // We either don't have a merge page, or for speed reasons we
            // only want to try copying block sections that already exist. We
            // don't need to scan through event content in this case, just copy
            // entire existing sections if they're in the filter
            std::print("copying {} blocks...", size(blocks));
            block_page = MonadTraceFileReader::BlockPage{};
            while (tf_reader.next_block_page(&block_page)) {
                uint64_t const block_number = block_page.get_block_count();
                if (blocks.contains(block_number)) {
                    ex_tf_writer->copy_section(tf_reader, block_page.sectab_entry.descriptor);
                    blocks.erase(block_number);
                }
            }
            std::println("done");

            if (!empty(blocks)) {
                std::print(stderr, "warning: {} block numbers not found in trace:", size(blocks));
                for (uint64_t b : blocks) {
                    std::print(stderr, " {}", b);
                }
                std::println(stderr);
            }
        }
    }
    catch (std::exception const &ex) {
        unlink(output_file.c_str());
        errx_f(EX_SOFTWARE, "error extracting blocks: ", ex.what());
    }
}
