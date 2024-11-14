#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <queue>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sysexits.h>
#include <unistd.h>

#include <monad/core/assert.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_shmem.h>
#include <monad/trace/trace_file.h>

#include "analysis.hpp"
#include "err_cxx.hpp"
#include "options.hpp"
#include "print_compat.hpp"
#include "trace_file_reader.hpp"
#include "trace_file_writer.hpp"

namespace fs = std::filesystem;

extern void extract_block_main(Options const *);

class EventVisitor;

class EventSource
{
public:
    virtual ~EventSource() = default;

    virtual std::string get_description() const = 0;

    virtual size_t get_event_count() const = 0;

    virtual MonadTraceFileReader const *get_trace_file_reader() const
    {
        return nullptr;
    }

    virtual std::optional<uint64_t> next_timestamp() const = 0;

    virtual size_t next_merged_event_size() const = 0;

    virtual bool copy_next_event(monad_trace_merged_event *) = 0;
};

struct RecorderEventComparator
{
    bool operator()(monad_trace_event const *lhs, monad_trace_event const *rhs) const
    {
        // > because this is for use as a priority_queue comparator, and we
        // want earlier events first
        return lhs->epoch_nanos > rhs->epoch_nanos;
    }
};

class RecorderPageEventSource final : public EventSource
{
public:
    explicit RecorderPageEventSource(
        MonadTraceFileReader const *trace_file_reader,
        MonadTraceFileReader::RecorderPage const &page)
        : trace_file_reader_{trace_file_reader}
        , page_{page}
        , evt_next_{nullptr}
        , evt_count_{0}
    {
        constexpr size_t ReorderQueueSize = 1024;
        do {
            if (page_.next_event(&evt_next_)) {
                evt_queue_.emplace(evt_next_);
            }
        } while (size(evt_queue_) < ReorderQueueSize && evt_next_ != nullptr);
    }

    std::string get_description() const override
    {
        return std::format(
            "{}:RECORDER_PAGE:{} (section {} [{},{}])",
            trace_file_reader_->get_mapped_file().file_path,
            page_.page_number,
            page_.sectab_entry.global_index,
            page_.sectab_entry.table_number,
            page_.sectab_entry.table_index);
    }

    size_t get_event_count() const override
    {
        return evt_count_;
    }

    MonadTraceFileReader const *get_trace_file_reader() const override
    {
        return trace_file_reader_;
    }

    std::optional<uint64_t> next_timestamp() const override
    {
        if (empty(evt_queue_)) {
            return {};
        }
        return evt_queue_.top()->epoch_nanos;
    }

    size_t next_merged_event_size() const override
    {
        MONAD_ASSERT(!empty(evt_queue_));
        return sizeof(monad_trace_merged_event) + evt_queue_.top()->length;
    }

    bool copy_next_event(monad_trace_merged_event *merged) override
    {
        ++evt_count_;
        memset(merged, 0, sizeof *merged);
        monad_trace_event const *const next = evt_queue_.top();
        evt_queue_.pop();
        merged->trace_evt = *next;
        memcpy(merged + 1, next + 1, next->length);
        if (merged->trace_evt.pop_scope) {
            merged->scope_action = MONAD_TRACE_SCOPE_POP;
        }
        else {
            monad_event_domain_metadata const &domain_meta =
                g_monad_event_domain_meta[MONAD_EVENT_DOMAIN(next->type)];
            monad_event_metadata const &event_meta =
                domain_meta.event_meta[MONAD_EVENT_DRCODE(next->type)];
            merged->scope_action =
                event_meta.trace_flags & MONAD_EVENT_TRACE_PUSH_SCOPE
                ? MONAD_TRACE_SCOPE_PUSH
                : MONAD_TRACE_SCOPE_NONE;
        }
        if (evt_next_ != nullptr && page_.next_event(&evt_next_)) {
            evt_queue_.emplace(evt_next_);
        }
        return !empty(evt_queue_);
    }

private:
    MonadTraceFileReader const *trace_file_reader_;
    MonadTraceFileReader::RecorderPage page_;
    monad_trace_event const *evt_next_;
    std::priority_queue<
        monad_trace_event const *,
        std::vector<monad_trace_event const *>,
        RecorderEventComparator> evt_queue_;
    size_t evt_count_;
};

struct EventSourceCursor
{
    std::uint64_t timestamp;
    EventSource *event_source;
};

std::weak_ordering
operator<=>(EventSourceCursor const &lhs, EventSourceCursor const &rhs)
{
    return lhs.timestamp <=> rhs.timestamp;
}

static uint64_t merge_event_sections(
    MonadTraceFileWriter &tf_writer,
    std::span<MonadTraceFileReader const> tf_readers,
    std::vector<monad_event_thread_info> &merged_thread_info)
{
    // For all monad trace files, create an event source for every trace page
    std::vector<std::unique_ptr<EventSource>> event_sources;
    for (MonadTraceFileReader const &tf_reader : tf_readers) {
        MonadTraceFileReader::RecorderPage page{};
        while (tf_reader.next_recorder_page(&page)) {
            event_sources.emplace_back(
                std::make_unique<RecorderPageEventSource>(&tf_reader, page));
        }
    }

    // All sources are ordered by a priority queue which sorts them by the
    // time of their next event
    std::priority_queue<
        EventSourceCursor,
        std::vector<EventSourceCursor>,
        std::greater<>>
        cursor_queue;

    // Initially populate the cursor queue
    uint64_t start_time = std::numeric_limits<uint64_t>::max();
    uint64_t end_time = 0;
    for (std::unique_ptr<EventSource> &s : event_sources) {
        if (auto const ts = s->next_timestamp()) {
            cursor_queue.emplace(*ts, s.get());
            start_time = std::min(start_time, *ts);
        }
    }
    std::println("merge initialized with {} event sources", size(event_sources));

    using scope_map_t =
        std::unordered_map<stack_key, std::vector<monad_trace_merged_event>>;

    scope_map_t scope_stacks;
    std::unordered_map<uint8_t, monad_event_thread_info> source_id_map;
    std::unordered_map<uint64_t, uint32_t> active_fiber_map;

    size_t const total_event_sources = size(cursor_queue);
    size_t finished_event_sources = 0;
    uint64_t domain_presence_mask = 0;
    uint64_t events_written = 0;
    uint64_t block_count = 0;
    uint64_t txn_count = 0;
    uint64_t total_gas = 0;
    monad_trace_section_desc *section_desc;

    MonadTraceFileWriter::DynamicSectionWriter dyn_writer =
        tf_writer.open_dynamic_section(&section_desc);
    section_desc->type = MONAD_TRACE_SECTION_MERGE_PAGE;

    // N-way merge join all events from all sources
    while (!empty(cursor_queue)) {
        // Select the event source with the nearest timestamp
        auto const [_, event_source] = cursor_queue.top();
        cursor_queue.pop();

        // Get the full size of the next event and allocate space for it the
        // dynamic page buffer
        monad_trace_merged_event *const merged_evt =
            dyn_writer.alloc_event(event_source->next_merged_event_size());

        // Copy out the next event
        if (event_source->copy_next_event(merged_evt)) {
            cursor_queue.emplace(*event_source->next_timestamp(), event_source);
        } else if (isatty(STDOUT_FILENO)) {
            std::print(stdout, "\rmerged {}/{} event sources",
                ++finished_event_sources, total_event_sources);
            std::fflush(stdout);
        }
        monad_trace_event const &trace_evt = merged_evt->trace_evt;
        end_time = trace_evt.epoch_nanos;
        ++events_written;

        if (trace_evt.type == MONAD_EVENT_SYNC_EVENT_GAP ||
            trace_evt.type == MONAD_EVENT_TRACE_GAP) {
            char const *const what_kind =
                trace_evt.type == MONAD_EVENT_SYNC_EVENT_GAP
                    ? "sync thread"
                    : "trace thread";
            errx_f(EX_DATAERR, "malformed event source: {} gap event present at {} in {}",
                what_kind, event_source->get_event_count(),
                event_source->get_description());
        }

        // Keep track of which domains we've seen (we'll only copy metadata
        // for those that actually have events in the file)
        monad_event_domain const evt_domain = MONAD_EVENT_DOMAIN(trace_evt.type);
        domain_presence_mask |= MONAD_EVENT_DOMAIN_MASK(evt_domain);

        // Get the thread this source_id is associated with. First we check for
        // THREAD_CREATE events, which populate the source_id -> thread_info map
        if (trace_evt.type == MONAD_EVENT_THREAD_CREATE) {
            auto *const thread_info =
                std::bit_cast<monad_event_thread_info const *>(merged_evt + 1);
            source_id_map[trace_evt.source_id] = *thread_info;
            merged_thread_info.emplace_back(*thread_info);
        }
        auto const i_thread = source_id_map.find(trace_evt.source_id);
        if (i_thread == end(source_id_map)) {
            errx_f(EX_DATAERR, "malformed trace: missing thread info for "
                "source_id {} in {}", trace_evt.source_id,
                event_source->get_description());
        }
        merged_evt->thread_id = i_thread->second.thread_id;

        // If this is a fiber switch event, mark the thread as now running
        // that fiber. There is a bit of a misrepresentation here because when
        // the FIBER_SWITCH scope is initially pushed, we are not running on
        // the stack of the fiber, but are about to switch to it. Only the pop
        // scope event will actually run on the fiber stack itself. By putting
        // this in the map now, we mis-annotate the running context of the
        // start of the switch, but it makes balancing the push/pop stacks
        // easier.
        if (trace_evt.type == MONAD_EVENT_FIBER_SWITCH &&
            merged_evt->scope_action == MONAD_TRACE_SCOPE_PUSH) {
            uint32_t const fiber_id =
                *std::bit_cast<uint32_t const *>(merged_evt + 1);
            active_fiber_map[merged_evt->thread_id] = fiber_id;
        }

        // Annotate what fiber this event occurred on by querying the active
        // fiber of the thread (will remain 0 if on the original thread stack)
        auto const i_fiber = active_fiber_map.find(merged_evt->thread_id);
        if (i_fiber != end(active_fiber_map)) {
            merged_evt->fiber_id = i_fiber->second;
        }

        // Find the flow id of this event by looking at the most recent
        // enclosing scope, or directly from the event's value if its event
        // class starts a new flow
        auto [i_scope, created] =
            scope_stacks.try_emplace(make_stack_key(merged_evt->thread_id, merged_evt->fiber_id));
        std::vector<monad_trace_merged_event> &scope_stack = i_scope->second;

        if (auto const ft = annotate_flow_type(trace_evt);
            ft != MONAD_TRACE_FLOW_NONE) {
            // This event starts a new flow
            merged_evt->flow_id =
                *std::bit_cast<uint64_t const *>(merged_evt + 1);
            merged_evt->flow_type = ft;
        }
        else if (!empty(scope_stack)) {
            // Event does not start a new flow; take the flow information from
            // the nearest enclosing scope object
            merged_evt->flow_id = scope_stack.back().flow_id;
            merged_evt->flow_type = scope_stack.back().flow_type;
        }

        // Maintain the scope stack; we have to make a copy since merged_evt
        // is ephemeral
        if (merged_evt->scope_action == MONAD_TRACE_SCOPE_PUSH) {
            scope_stack.emplace_back(*merged_evt);
        }
        else if (merged_evt->scope_action == MONAD_TRACE_SCOPE_POP) {
            if (empty(scope_stack)) {
                throw std::runtime_error{std::format(
                    "unbalanced scopes: pop of empty stack for event #{} in "
                    "event source {}",
                    event_source->get_event_count() - 1,
                    event_source->get_description())};
            }
            monad_trace_merged_event const &open_event = scope_stack.back();
            if (!event_closes_scope(open_event.trace_evt, trace_evt)) {
                throw std::runtime_error{std::format(
                    "unbalanced scopes: pop of scope stack of a different "
                    "code than pushed")};
            }
            scope_stack.pop_back();
        }

        switch (trace_evt.type) {
        case MONAD_EVENT_THREAD_EXIT:
            source_id_map.erase(trace_evt.source_id);
            break;

        case MONAD_EVENT_BLOCK_END:
            ++block_count;
            break;

        case MONAD_EVENT_TXN_EXEC_END:
            ++txn_count;
            total_gas += *std::bit_cast<uint64_t const*>(merged_evt + 1);
            break;

        default:
            break; // No special processing for this event type
        }
    }
    section_desc->merge_page.event_count = events_written;
    section_desc->merge_page.block_count = block_count;
    section_desc->merge_page.elapsed_nanos = end_time - start_time;
    section_desc->merge_page.txn_count = txn_count;
    section_desc->merge_page.total_gas = total_gas;

    std::println(stdout);
    return domain_presence_mask;
}

static void copy_domain_metadata_sections(
    MonadTraceFileWriter &tf_writer,
    uint64_t domain_presence_mask)
{
    // Loop over all present domains, copying the domain metadata for them.
    // We can copy the metadata straight from the static data and don't need
    // to care about the sections in the original files, since we know it is
    // equal (see check_domain_integrity).
    while (domain_presence_mask != 0) {
        auto const domain =
            static_cast<monad_event_domain>(std::countr_zero(domain_presence_mask) + 1);
        tf_writer.write_domain_metadata(&g_monad_event_domain_meta[domain]);
        domain_presence_mask &= ~MONAD_EVENT_DOMAIN_MASK(domain);
    }
}

static void write_thread_info_section(
    MonadTraceFileWriter &tf_writer,
    std::span<monad_event_thread_info const> thread_info)
{
    monad_trace_section_desc thr_info_sd;
    thr_info_sd.type = MONAD_TRACE_SECTION_THREAD_INFO;
    thr_info_sd.thread_info.thread_count = size(thread_info);
    tf_writer.write_section(&thr_info_sd, as_bytes(thread_info));
}

static fs::path write_merge_file(
    std::span<fs::path const> input_files, MergeOptions const &merge_opts)
{
    std::vector<MonadTraceFileReader> tf_readers;

    for (fs::path const &input_file : input_files) {
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
                sizeof MONAD_TRACE_FILE_MAGIC) == 0) {
            MonadTraceFileReader const &tf_reader = tf_readers.emplace_back(
                MonadTraceFileReader::load(std::move(*ex_mapped_file)));

            // Ensure all the domain metadata in the file matches the
            // static data
            if (monad_event_domain_metadata const *mismatch_dm =
                find_first_domain_integrity_mismatch(tf_reader)) {
                errx_f(EX_DATAERR, "cannot merge trace file `{}` because file "
                    "domain `{}` does not match this process' static data",
                    tf_reader.get_mapped_file().file_path, mismatch_dm->name);
            }
            continue;
        }

        errx_f(EX_DATAERR, "input file `{}` has unknown format", input_file);
    }

    fs::path const merge_file = merge_opts.output_file.empty()
        ? fs::path{"monad.trace.merged"}
        : merge_opts.output_file;

    // Write the merge file
    auto ex_tf_writer = MonadTraceFileWriter::create(merge_file);
    if (!ex_tf_writer) {
        errc_f(
            EX_OSERR,
            ex_tf_writer.error(),
            "unable to create merge output file {}",
            merge_file);
    }

    try {
        std::vector<monad_event_thread_info> merged_thread_info;
        // Merge the event sections, and keep track of which domains are
        // actually used; we'll garbage-collect any that are unused
        uint64_t const domain_presence_mask =
            merge_event_sections(*ex_tf_writer, tf_readers, merged_thread_info);

        // Copy any domain metadata sections that were used at the end
        copy_domain_metadata_sections(*ex_tf_writer, domain_presence_mask);

        // Write a thread table with all the THREAD_CREATE event payloads
        // encountered during the merge
        write_thread_info_section(*ex_tf_writer, merged_thread_info);
    }
    catch (std::exception const &ex) {
        unlink(merge_file.c_str());
        errx_f(EX_SOFTWARE, "exception during merge: {}", ex.what());
    }

    return merge_file;
}

void merge_main(Options const *opts)
{
    bool const have_merge_file = !opts->merge_options.output_file.empty();
    bool const have_block_file = !opts->extract_block_options.output_file.empty();
    if (!have_merge_file && !have_block_file) {
        errx_f(EX_USAGE, "no output specified; nothing to do");
    }

    // Write the merge file; we do this even if they didn't specify the
    // -m option, since we need to do it as a temporary step when producing a
    // block file. If they don't want it, we'll unlink it at the end.
    fs::path const merge_file =
        write_merge_file(opts->input_files, opts->merge_options);

    if (have_block_file) {
        // Reuse the `extract-block` command implementation to do this
        Options opts_copy = *opts;
        opts_copy.extract_block_options.input_file = merge_file;
        extract_block_main(&opts_copy);
    }

    if (!have_merge_file) {
        // If they run with only -b, they don't want the merge file; remove it
        unlink(merge_file.c_str());
    }
}
