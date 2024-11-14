#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <span>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sysexits.h>

#include <monad/core/assert.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/trace/trace_file.h>

#include "analysis.hpp"
#include "err_cxx.hpp"
#include "options.hpp"
#include "print.hpp"
#include "print_compat.hpp"
#include "trace_file_reader.hpp"

namespace fs = std::filesystem;

using thread_info_map_t =
    std::unordered_map<uint64_t, monad_event_thread_info const *>;

void print_monad_trace_file_header(
    monad_trace_file_header const &header, std::FILE *out)
{
    std::string_view const magic{header.magic, sizeof MONAD_TRACE_FILE_MAGIC};
    std::println(out, "magic:      {}", magic);
    std::println(out, "version:    {}", header.version);
    std::println(out, "sectab_off: {}", header.sectab_offset);
}

char const *monad_trace_file_section_type_name(monad_trace_section_type type)
{
    switch (type) {
    case MONAD_TRACE_SECTION_NONE:
        return "NONE";
    case MONAD_TRACE_SECTION_LINK:
        return "SEC_TAB_LINK";
    case MONAD_TRACE_SECTION_DOMAIN_INFO:
        return "DOMAIN_INFO";
    case MONAD_TRACE_SECTION_THREAD_INFO:
        return "THREAD_INFO";
    case MONAD_TRACE_SECTION_RECORDER_PAGE:
        return "RECORDER_PAGE";
    case MONAD_TRACE_SECTION_MERGE_PAGE:
        return "MERGE_PAGE";
    case MONAD_TRACE_SECTION_BLOCK_PAGE:
        return "BLOCK_PAGE";
    default:
        return "<invalid>";
    }
}

static void print_section_table_entry(
    MonadTraceFileReader::SectionTableEntry const &sectab_entry, std::FILE *out)
{
    monad_trace_section_desc const &sd = *sectab_entry.descriptor;
    auto const section_type = static_cast<monad_trace_section_type>(sd.type);

    if (sectab_entry.table_index == 0) {
        std::println(
            out,
            "{} section table at {}",
            sectab_entry.table_number == 0 ? "initial" : "linked",
            sectab_entry.table_offset);
        std::println(
            out,
            "{:3} {:3} {:16} {:>12} {:>12} {:>6}",
            "TAB",
            "ENT",
            "SECTION_TYPE",
            "OFFSET",
            "LENGTH",
            "INDEX");
    }
    std::print(
        out,
        "{:3} {:3} {:16} {:>12} {:>12} {:>6}",
        sectab_entry.table_number,
        sectab_entry.table_index,
        monad_trace_file_section_type_name(section_type),
        sd.offset,
        sd.length,
        sectab_entry.global_index);
    switch (section_type) {
    case MONAD_TRACE_SECTION_THREAD_INFO:
        std::println(
            out,
            "  #THR: {}",
            sd.thread_info.thread_count);
        break;

    case MONAD_TRACE_SECTION_DOMAIN_INFO:
        std::print(
            out,
            "  CODE: {:2}, #EVT: {:3}, KEC_24: ",
            sd.domain_info.code,
            sd.domain_info.num_events);
        for (uint8_t b : std::span{sd.domain_info.keccak_24}) {
          std::print(out, "{:02x}", b);
        }
        std::println(out);
        break;

    case MONAD_TRACE_SECTION_RECORDER_PAGE:
        std::println(
            out,
            "  #EVT: {}",
            sd.recorder_page.event_count);
        break;

    case MONAD_TRACE_SECTION_MERGE_PAGE:
        std::println(out,
            "  #EVT: {:9}, #B: {:7}, DUR: {:4}, #TXN: {:9}, G: {:12} ({:4} GPUS)",
            sd.merge_page.event_count,
            sd.merge_page.block_count,
            std::chrono::duration_cast<std::chrono::minutes>(
                std::chrono::nanoseconds{sd.merge_page.elapsed_nanos}),
            sd.merge_page.txn_count,
            sd.merge_page.total_gas,
            sd.merge_page.total_gas / (sd.merge_page.elapsed_nanos / 1000));
        break;

    case MONAD_TRACE_SECTION_BLOCK_PAGE:
        std::println(out,
        "  B: {:9}, #EVT: {:7}, DUR: {:6}us, #TXN: {:4}, G: {:8}  ({:4} GPUS)",
        sd.merge_page.block_count,
        sd.merge_page.event_count,
        sd.merge_page.elapsed_nanos / 1000,
        sd.merge_page.txn_count,
        sd.merge_page.total_gas,
        sd.merge_page.total_gas / (sd.merge_page.elapsed_nanos / 1000));
        break;

    default:
        std::println(out);
        break;
    }
}

static void print_domain_metadata_section(
    monad_event_domain_metadata const &domain_meta,
    MonadTraceFileReader::SectionTableEntry const &sectab_entry,
    bool matches_static_data,
    std::FILE *out)
{
    std::println(out, "name:        {}", domain_meta.name);
    std::println(out, "code:        {}", std::to_underlying(domain_meta.domain));
    std::println(out, "description: {}", domain_meta.description);
    std::print(out, "meta hash:   ");
    for (uint8_t b : std::span{sectab_entry.descriptor->domain_info.keccak_24}) {
        std::print(out, "{:02x}", b);
    }
    std::println(out);
    std::println(out, "sync_static: {:c}", matches_static_data ? 'Y' : 'N');
    std::println(out, "event list:");

    for (monad_event_metadata const &emd :
         std::span{domain_meta.event_meta, domain_meta.num_events}) {
        std::println(out);
        std::println(out, "  type:        {0} [{0:#x}]",
            std::to_underlying(emd.type));
        std::println(out, "  dr_code:     {}", MONAD_EVENT_DRCODE(emd.type));
        std::println(out, "  trace_flags: {:#x}", emd.trace_flags);
        std::println(out, "  c_symbol:    {}", emd.c_symbol);
        std::println(out, "  c_name:      {}", emd.c_name);
        std::println(out, "  camel_name:  {}", emd.camel_name);
        std::println(out, "  description: {}", emd.description);
    }
}

static void print_recorder_page(
    MonadTraceFileReader const &trace_file,
    MonadTraceFileReader::RecorderPage const &page, std::FILE *out)
{
    std::println(out, "page:        {}", page.page_number);
    std::println(out, "event_count: {}", page.get_event_count());

    auto const internal_domain_valid =
        trace_file.domain_static_data_matches_file(MONAD_EVENT_DOMAIN_INTERNAL);
    auto const perf_domain_valid =
        trace_file.domain_static_data_matches_file(MONAD_EVENT_DOMAIN_PERF);
    auto const ethereum_domains_valid =
        trace_file.domain_static_data_matches_file(MONAD_EVENT_DOMAIN_BLOCK) &
            trace_file.domain_static_data_matches_file(MONAD_EVENT_DOMAIN_TXN);

    monad_trace_event const *evt = nullptr;
    PrintEventOptions print_opts = {
        .context =
            {.event_index = 0,
             .prev_event_time = page.get_start_time(),
             .trace_file = &trace_file},
        .time_zone = std::chrono::current_zone(),
        .leading_new_line = true,
        .print_event_index = true,
        .print_thread_info = true,
        .print_fiber_switch_details = true};
    while (page.next_event(&evt)) {
        // For recorder pages, we usually don't know the thread_id, flow_id, or
        // fiber_id that is active in the current scope, since we don't track
        // scopes in the simple "show" command. The purpose of the show command
        // on a recorder page section is to show exactly what is in the file,
        // for debugging purposes, not to produce insight into what is
        // happening in the trace.
        //
        // We do show it for the events that push a new flow_id or fiber_id,
        // and explicitly clear it otherwise.
        if (ethereum_domains_valid) {
            print_opts.context.flow_type = annotate_flow_type(*evt);
            print_opts.context.flow_id =
                print_opts.context.flow_type != MONAD_TRACE_FLOW_NONE
                    ? *std::bit_cast<uint64_t const *>(evt + 1)
                    : 0;
        } else {
            print_opts.context.flow_type = MONAD_TRACE_FLOW_NONE;
            print_opts.context.flow_id = 0;
        }

        if (perf_domain_valid && evt->type == MONAD_EVENT_FIBER_SWITCH &&
            !evt->pop_scope) {
            print_opts.context.fiber_id = *std::bit_cast<uint32_t const *>(evt + 1);
        } else {
            print_opts.context.fiber_id = 0;
        }

        if (internal_domain_valid && evt->type == MONAD_EVENT_THREAD_CREATE) {
            print_opts.context.thread_info =
                std::bit_cast<monad_event_thread_info const *>(evt + 1);
        }
        else {
            print_opts.context.thread_info = nullptr;
        }
        print_trace_event(print_opts, *evt, out);
        ++print_opts.context.event_index;
        print_opts.context.prev_event_time =
            std::chrono::sys_time{std::chrono::nanoseconds{evt->epoch_nanos}};
    }
}

static void print_merge_page(
    ShowOptions const &so, MonadTraceFileReader const &trace_file,
    MonadTraceFileReader::MergePage const &page,
    thread_info_map_t const &thread_info_map, std::FILE *out)
{
    using scope_stacks_map_t =
        std::unordered_map<stack_key, std::vector<monad_trace_merged_event const *>>;
    (void)so, (void)trace_file;

    auto const elapsed_micros = page.get_elapsed_nanos() / 1000;
    char const *elapsed_unit;
    uint64_t elapsed_time;
    if (auto *const bp = page.as_block_page()) {
        // For a block page, the block "count" is instead the block number
        std::println(out, "block:       {}", bp->get_block_count());
        elapsed_time = elapsed_micros;
        elapsed_unit = "us";
    }
    else {
        elapsed_time = elapsed_micros / 1'000'000UL;
        elapsed_unit = "s";
        if (elapsed_time > 60 * 10) {
            elapsed_time /= 60;
            elapsed_unit = "m";
        }
    }
    auto const gpus = page.get_total_gas() / elapsed_micros;
    std::println(out, "page:        {}", page.page_number);
    std::println(out, "event_count: {}", page.get_event_count());
    if (!page.as_block_page()) {
        std::println(out, "block_count: {}", page.get_block_count());
    }
    std::println(out, "txn count:   {}", page.get_txn_count());
    std::println(out, "elapsed:     {} {}", elapsed_time, elapsed_unit);
    std::println(out, "total gas:   {}", page.get_total_gas());
    std::println(out, "efficiency:  {} g/us", gpus);

    monad_trace_merged_event const *merged_evt = nullptr;
    std::unordered_set<uint64_t> thread_id_filter;
    scope_stacks_map_t scope_stacks;

    PrintEventOptions print_opts = {
        .context =
            {.event_index = 0,
             .prev_event_time = page.get_start_time(),
             .trace_file = &trace_file},
        .leading_new_line = true,
        .print_event_index = true,
        .print_thread_info = true,
        .print_fiber_switch_details = true};
    for (auto const &thread_info : trace_file.get_thread_info()) {
        if (so.thread_filter.contains(thread_info.thread_name)) {
            thread_id_filter.insert(thread_info.thread_id);
        }
    }
    while (page.next_event(&merged_evt)) {
        monad_trace_merged_event const *open_scope = nullptr;
        if (merged_evt->scope_action == MONAD_TRACE_SCOPE_PUSH) {
            auto [i_scope, created] =
                    scope_stacks.try_emplace(make_stack_key(merged_evt->thread_id, merged_evt->fiber_id));
            i_scope->second.emplace_back(merged_evt);
        }
        else if (merged_evt->scope_action == MONAD_TRACE_SCOPE_POP) {
            auto [i_scope, created] =
                scope_stacks.try_emplace(make_stack_key(merged_evt->thread_id, merged_evt->fiber_id));
            MONAD_ASSERT(!empty(i_scope->second));
            open_scope = i_scope->second.back();
            i_scope->second.pop_back();
        }
        if (!empty(thread_id_filter) &&
            !thread_id_filter.contains(merged_evt->thread_id)) {
            continue;
        }
        auto i_thread = thread_info_map.find(merged_evt->thread_id);
        MONAD_ASSERT(i_thread != end(thread_info_map));
        print_opts.context.thread_info = i_thread->second;
        print_opts.context.flow_id = merged_evt->flow_id;
        print_opts.context.flow_type =
            static_cast<monad_trace_flow_type>(merged_evt->flow_type);
        print_opts.context.fiber_id = merged_evt->fiber_id;
        print_trace_event(print_opts, merged_evt->trace_evt, out);

        if (open_scope && !so.no_track_scopes) {
            // This event closes a scope that was previously open
            uint64_t const elapsed_nanos =
                merged_evt->trace_evt.epoch_nanos - open_scope->trace_evt.epoch_nanos;
            std::println(out, "  elapsed:{:{}}{} ns",
                "", 16 - strlen("elapsed"), elapsed_nanos);
            std::println(out, "  closes event:");
            i_thread = thread_info_map.find(open_scope->thread_id);
            MONAD_ASSERT(i_thread != end(thread_info_map));
            print_opts.context.thread_info = i_thread->second;
            print_opts.context.flow_id = open_scope->flow_id;
            print_opts.context.flow_type =
                static_cast<monad_trace_flow_type>(open_scope->flow_type);
            print_opts.context.fiber_id = open_scope->fiber_id;
            print_opts.context.prev_event_time = {};
            print_opts.leading_new_line = false;
            print_opts.print_event_index = false;
            print_opts.leading_indent = 2;
            print_trace_event(print_opts, open_scope->trace_evt, out);
            print_opts.leading_new_line = true;
            print_opts.print_event_index = true;
            print_opts.leading_indent = 0;
        }

        ++print_opts.context.event_index;
        print_opts.context.prev_event_time =
            std::chrono::sys_time{std::chrono::nanoseconds{merged_evt->trace_evt.epoch_nanos}};
    }
}

static void show_monad_trace_file(
    Options const *opts, MonadTraceFileReader tf_reader, std::FILE *out)
{
    ShowOptions const &so = opts->show_options;

    if (so.all || so.file_header) {
        // Print the file header
        std::println(out, "File Header:");
        print_monad_trace_file_header(tf_reader.get_header(), out);
        std::println(out);
    }

    if (so.all || so.section_tables) {
        // Print all the descriptors in the section table
        std::println(out, "Section Tables:");
        MonadTraceFileReader::SectionTableEntry sectab_entry{};
        while (tf_reader.next_section_table_entry(&sectab_entry)) {
            print_section_table_entry(sectab_entry, out);
        }
        std::println(out);
    }

    if (so.all || so.event_counts) {
        std::println(out, "Event Counts:");
        size_t recorder_page_count = 0;
        size_t recorder_page_event_count = 0;
        size_t merge_page_count = 0;
        size_t merge_page_event_count = 0;
        size_t block_page_count = 0;
        size_t block_page_event_count = 0;
        MonadTraceFileReader::SectionTableEntry sectab_entry{};
        while (tf_reader.next_section_table_entry(&sectab_entry)) {
            switch (sectab_entry.descriptor->type) {
            case MONAD_TRACE_SECTION_RECORDER_PAGE:
                ++recorder_page_count;
                recorder_page_event_count +=
                    sectab_entry.descriptor->recorder_page.event_count;
                break;
            case MONAD_TRACE_SECTION_MERGE_PAGE:
                ++merge_page_count;
                merge_page_event_count +=
                    sectab_entry.descriptor->merge_page.event_count;
                break;
            case MONAD_TRACE_SECTION_BLOCK_PAGE:
                ++block_page_count;
                block_page_event_count +=
                    sectab_entry.descriptor->merge_page.event_count;
                break;

            default:
                break; // Not a trace page
            }
        }
        std::println(out, "recorder pages: {} total events across {} pages",
            recorder_page_event_count, recorder_page_count);
        std::println(out, "merge pages: {} total events across {} pages",
            merge_page_event_count, merge_page_count);
        std::println(out, "block pages: {} total events across {} pages",
            block_page_event_count, block_page_count);
        std::println(out);
    }

    if (so.all || so.thread_list) {
        std::println(out, "Thread Directory:");
        size_t thread_count = 0;
        std::span const thread_info = tf_reader.get_thread_info();
        if (empty(thread_info)) {
            std::println("<not present>");
        }
        else {
            std::println(out, "## SRC {:>8} THR_NAME", "THR_ID");
            for (auto const &ti : thread_info) {
                std::println(
                    out,
                    "{:2} {:3} {:8} {}",
                    thread_count++,
                    ti.source_id,
                    ti.thread_id,
                    ti.thread_name);
            }
        }
        std::println(out);
    }

    if (so.all || so.domain_list) {
        // List all the domains in the metadata section
        std::println(out, "Domain Metadata Section List:");
        MonadTraceFileReader::SectionTableEntry sectab_entry{};
        monad_event_domain_metadata const *domain_meta;
        bool matches_static_data;
        bool all_metadata_matches = true;
        while (tf_reader.next_domain_metadata(&sectab_entry, &domain_meta,
            &matches_static_data)) {
            all_metadata_matches &= matches_static_data;
            char const *const no_match_qual = matches_static_data ? "" : "*";
            std::println(
                out,
                "{}. {}{:16} {}",
                std::to_underlying(domain_meta->domain),
                no_match_qual,
                domain_meta->name,
                domain_meta->description);
        }
        if (!all_metadata_matches) {
            std::println(out, "*file metadata does not match static metadata");
        }
        std::println(out);
    }

    if (so.all || so.domain_list > 1) {
        // Print all the domain metadata sections
        std::println(out, "Full Domain Metadata:");
        MonadTraceFileReader::SectionTableEntry sectab_entry{};
        monad_event_domain_metadata const *domain_meta;
        bool matches_static_data;
        while (tf_reader.next_domain_metadata(&sectab_entry, &domain_meta,
            &matches_static_data)) {
            if (!empty(so.domain_filter)) {
                // When domain filters are present, we skip a domain if it's
                // name is not in the filter
                if (!so.domain_filter.contains(domain_meta->name)) {
                    continue;
                }
            }
            print_domain_metadata_section(*domain_meta, sectab_entry,
                matches_static_data, out);
            std::println(out);
        }
    }

    if (so.all || so.dump_events) {
        thread_info_map_t thread_info_map;
        for (auto const &ti : tf_reader.get_thread_info()) {
            thread_info_map[ti.thread_id] = &ti;
        }
        monad_event_domain_metadata const *const mismatch_dm =
            find_first_domain_integrity_mismatch(tf_reader);

        // Print all recorder pages
        std::println(out, "Recorder Pages:");
        MonadTraceFileReader::RecorderPage recorder_page{};
        while (tf_reader.next_recorder_page(&recorder_page)) {
            print_recorder_page(tf_reader, recorder_page, out);
            std::println(out);
        }
        if (recorder_page.page_number == -1) {
            std::println(out, "<none>");
        }
        std::println(out);

        std::println(out, "Merge Pages:");
        MonadTraceFileReader::MergePage merge_page{};
        if (mismatch_dm) {
            std::println(out, "cannot print merge pages because `{}` domain "
                "metadata does not match this process' static data",
                mismatch_dm->name);
        }
        else while (tf_reader.next_merge_page(&merge_page)) {
            print_merge_page(so, tf_reader, merge_page, thread_info_map, out);
            std::println(out);
        }
        if (!mismatch_dm && merge_page.page_number == -1) {
            std::println(out, "<none>");
        }
        std::println(out);

        std::println(out, "Block Pages:");
        MonadTraceFileReader::BlockPage block_page{};
        bool const block_filter_enabled = !empty(so.blocks);
        if (mismatch_dm) {
            std::println(out, "cannot print block pages because `{}` domain "
                "metadata does not match this process' static data",
                mismatch_dm->name);
        } else while (tf_reader.next_block_page(&block_page)) {
            if (block_filter_enabled &&
                !so.blocks.contains(block_page.get_block_count())) {
                continue;
            }
            print_merge_page(so, tf_reader, block_page, thread_info_map, out);
            std::println(out);
        }
        if (!mismatch_dm && block_page.page_number == -1) {
            std::println(out, "<none>");
        }
        std::println(out);
    }
}

extern void show_main(Options const *opts)
{
    for (fs::path const &input_file : opts->input_files) {
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
            errx_f(
                EX_DATAERR, "input file `{}` has unknown format", input_file);
        }
        show_monad_trace_file(
            opts,
            MonadTraceFileReader::load(std::move(*ex_mapped_file)),
            stdout);
    }
}
