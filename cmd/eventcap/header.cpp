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

#include "eventcap.hpp"
#include "eventsource.hpp"
#include "options.hpp"
#include "stats.hpp"
#include "util.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <list>
#include <optional>
#include <print>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <time.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_ring.h>
#include <category/core/hex.hpp>
#include <category/execution/ethereum/event/blockcap.h>

using std::chrono::duration_cast, std::chrono::nanoseconds,
    std::chrono::system_clock, std::chrono::seconds;

namespace
{

struct RankStatistics
{
    std::vector<double> sample;
    TDigest t_digest;
};

struct EventRingControlData
{
    system_clock::time_point time;
    uint64_t last_seqno;
    uint64_t next_payload_buf;
};

struct EventRingState
{
    MappedEventRing *ring;
    std::vector<EventRingControlData> control_sample;
    std::pair<uint64_t, uint64_t> last_seqno_range;
    RankStatistics event_rate;
    RankStatistics payload_buf_alloc_rate;
    RankStatistics avg_payload_size;
};

constexpr std::size_t ControlSampleSize = 128;
constexpr nanoseconds ControlSamplePeriod =
    std::chrono::duration_cast<nanoseconds>(seconds{1}) / ControlSampleSize;

char const *describe(monad_evcap_section_compression c)
{
    switch (c) {
    case MONAD_EVCAP_COMPRESSION_NONE:
        return "*";
    case MONAD_EVCAP_COMPRESSION_ZSTD_SINGLE_PASS:
        return "Z1P";
    case MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING:
        return "ZST";
    default:
        return "?";
    }
}

std::vector<MappedEventRing *> create_samples(std::list<EventRingState> &states)
{
    std::vector<MappedEventRing *> finalized_rings;

    while (g_should_exit == 0 && !empty(states) &&
           size(states.front().control_sample) < ControlSampleSize) {
        auto i_state = begin(states);
        auto const i_end_state = end(states);

        auto const start_time = system_clock::now();
        while (i_state != i_end_state) {
            // Remember the current state, and advance `i_state` past it; we do
            // this to safely erase defunct event ring states from the list
            // without disturbing the loop iteration
            auto const i_current = i_state++;

            // Add a single data point to the control sample
            EventRingState &state = *i_current;
            monad_event_ring_header const *const h = state.ring->get_header();
            EventRingControlData const &last =
                state.control_sample.emplace_back(
                    system_clock::now(),
                    __atomic_load_n(&h->control.last_seqno, __ATOMIC_ACQUIRE),
                    __atomic_load_n(
                        &h->control.next_payload_byte, __ATOMIC_ACQUIRE));

            auto const i_prev = ++state.control_sample.rbegin();
            if (i_prev == state.control_sample.rend()) {
                // The sample has only one observation
                continue;
            }
            // The sample has more than one observation, check if zero events
            // were produced in this tick period and if so, further check if
            // the event ring is abandoned. If so, destroy its state
            EventRingControlData const &prev = *i_prev;
            if (last.last_seqno - prev.last_seqno == 0 &&
                state.ring->is_finalized()) {
                finalized_rings.push_back(state.ring);
                states.erase(i_current);
            }
        }

        // Sleep until it's time to gather another datapoint in the statistical
        // sample; although we would prefer std::this_thread::sleep_until here,
        // we need the sleep to be interruptable, so need nanosleep(2) here
        auto const sleep_ns = duration_cast<nanoseconds>(
            start_time + ControlSamplePeriod - system_clock::now());
        if (sleep_ns.count() > 0) {
            // nanosleep(2) needs the seconds and nanoseconds broken down,
            // otherwise it returns EINVAL
            seconds const sleep_s = std::chrono::floor<seconds>(sleep_ns);
            timespec const sleep_time = {
                .tv_sec = sleep_s.count(),
                .tv_nsec = (sleep_ns - sleep_s).count()};
            // If we wake up with EINTR, g_should_exit will be set, so we'll
            // fall through and print one last update
            // TODO(ken): EINTR wakeup only works if it's a thread-directed
            //   signal to this thread, which it won't be; what to do about
            //   this?
            (void)nanosleep(&sleep_time, nullptr);
        }
    }

    return finalized_rings;
}

void compute_rank_stats(EventRingState &state, bool discard_zero_samples)
{
    state.event_rate.sample.clear();
    state.payload_buf_alloc_rate.sample.clear();
    state.avg_payload_size.sample.clear();

    // Turn the ring control sample into rate-per-second sample data, e.g.,
    //
    //   (wr_seqno_{i} - wr_seqno_{i-1}) / (time_{i} - time_{i-1})
    //
    // Also compute the average payload sample
    auto i_prev = begin(state.control_sample);
    auto const i_end = end(state.control_sample);
    for (auto i = next(i_prev); i != i_end; ++i, ++i_prev) {
        double const elapsed_seconds =
            static_cast<double>((i->time - i_prev->time).count()) /
            system_clock::duration::period::den;

        double const new_event_count =
            static_cast<double>(i->last_seqno - i_prev->last_seqno);
        if (discard_zero_samples && new_event_count == 0) {
            continue;
        }

        double const new_payload_byte_count =
            static_cast<double>(i->next_payload_buf - i_prev->next_payload_buf);
        if (discard_zero_samples && new_payload_byte_count == 0) {
            continue;
        }

        double const avg_payload_size =
            new_event_count > 0 ? new_payload_byte_count / new_event_count : 0;

        state.event_rate.sample.push_back(new_event_count / elapsed_seconds);
        state.payload_buf_alloc_rate.sample.push_back(
            new_payload_byte_count / elapsed_seconds);
        state.avg_payload_size.sample.push_back(avg_payload_size);
    }

    // The only purpose of the control sample is to compute the derived sample;
    // clear the vector to reuse it next time, but save the seqno sample seqno
    // ranges, printed for debugging's sake
    state.last_seqno_range = {
        state.control_sample.front().last_seqno,
        state.control_sample.back().last_seqno};
    state.control_sample.clear();

    for (RankStatistics *r :
         {&state.event_rate,
          &state.payload_buf_alloc_rate,
          &state.avg_payload_size}) {
        std::ranges::sort(r->sample);
        r->t_digest.merge_sorted_points<double>(r->sample, nullptr);
    }
}

void print_update(EventRingState const &state, std::FILE *output)
{
    struct StatDescription
    {
        std::string_view name;
        std::string_view unit;
        double divisor;
        RankStatistics const *stats;
    } const StatsTable[] = {
        {.name = "Event rate",
         .unit = "Kev/s",
         .divisor = 1000,
         .stats = &state.event_rate},
        {.name = "Payload alloc",
         .unit = "MiB/s",
         .divisor = (1 << 20),
         .stats = &state.payload_buf_alloc_rate},
        {.name = "Avg. payload",
         .unit = "bytes",
         .divisor = 1,
         .stats = &state.avg_payload_size},
    };

    std::println(
        output,
        "stats for {} -- seqno range [{}, {}]",
        state.ring->describe(),
        state.last_seqno_range.first,
        state.last_seqno_range.second);
    // Format is
    // --            UNIT   <QUANTILES>
    // <stat name>   <un>
    //   Recent             <recent quantile data>
    //   T-Digest           <t-digest quantile estimates>
    double const quantiles[] = {
        0, 0.1, 0.25, 0.5, 0.75, .9, 0.95, 0.99, 0.999, 1.0};
    std::print(output, "{:16} {:>4}", "--", "UNIT");
    print_quantile_header(quantiles, 8, output);
    std::println(output, " {:>8}", "#CEN");
    for (StatDescription const &sd : StatsTable) {
        std::println(output, "{:16} {}", sd.name, sd.unit);

        // Print recent
        std::print(output, "{:21}", "  Recent");
        for (double const q : quantiles) {
            std::print(
                output,
                " {:8.1f}",
                compute_quantile_sorted(sd.stats->sample, q) / sd.divisor);
        }
        std::println(output, " {:>8}", "N/A");

        // Print t-digest
        std::print(output, "{:21}", "  T-Digest");
        for (double const q : quantiles) {
            std::print(
                output,
                " {:>8.1f}",
                sd.stats->t_digest.compute_quantile(q) / sd.divisor);
        }
        std::println(output, " {:>8}", sd.stats->t_digest.num_centroids());
    }
}

void print_event_ring_headers(
    std::span<MappedEventRing const *const> rings, std::FILE *out)
{
    // Print the event ring file header information:
    // <type-name> [<type-code>] <descriptor capacity> <descriptor byte size>
    //    <payload buf size> <context area size> <last write seqno>
    //    <next payload buf byte> <pbuf window start> <meta-hash> <file-name>
    std::println(
        out,
        "{:10} {:>9} {:>10} {:>10} {:>10} {:>12} {:>14} {:>14} {:14} {}",
        "TYPE",
        "DESC_CAP",
        "DESC_SZ",
        "PBUF_SZ",
        "CTX_SZ",
        "WR_SEQNO",
        "PBUF_NEXT",
        "PBUF_WIN",
        "METADATA_HASH",
        "FILE_NAME");
    for (MappedEventRing const *mr : rings) {
        using monad::as_hex;
        monad_event_ring_header const *const h = mr->get_header();
        std::println(
            out,
            "{:6} [{}] {:9} {:10} {:10} {:10} {:12} {:14} {:14} {:14} {}",
            g_monad_event_content_type_names[h->content_type],
            std::to_underlying(h->content_type),
            h->size.descriptor_capacity,
            h->size.descriptor_capacity * sizeof(monad_event_descriptor),
            h->size.payload_buf_size,
            h->size.context_area_size,
            __atomic_load_n(&h->control.last_seqno, __ATOMIC_ACQUIRE),
            __atomic_load_n(&h->control.next_payload_byte, __ATOMIC_ACQUIRE),
            __atomic_load_n(&h->control.buffer_window_start, __ATOMIC_ACQUIRE),
            as_hex(std::span{h->schema_hash}.first(6)),
            mr->describe());
    }
}

void print_event_capture_header(
    EventCaptureFile const *capture, bool print_full_section_table,
    std::FILE *out)
{
    std::println(out, "{} section table", capture->describe());

    monad_evcap_reader *const evcap_reader = capture->get_reader();
    monad_evcap_file_header const *const file_header =
        monad_evcap_reader_get_file_header(evcap_reader);
    std::byte const *const map_base = std::bit_cast<std::byte const *>(
        monad_evcap_reader_get_mmap_base(evcap_reader));
    monad_evcap_section_desc const *sd = nullptr;
    std::span<monad_blockcap_index_entry const> block_index_table;
    size_t sectab_index = 0;
    size_t table_number = 0;
    size_t entry_number = 0;

    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_NONE, &sd)) {
        if (sectab_index == 0) {
            // Print section table header
            // <index> [<tab>:<ent>] <section-type> <offset> <file-length>
            //    <compressed-length> <extra>
            std::println(
                out,
                "{:>6} {:>3}:{:<4} {:20} {:>12} {:>5} {:>12} {:>12} {:>12} {}",
                "INDEX",
                "TAB",
                "ENT",
                "SECTION_TYPE",
                "DESC_OFF",
                "COM",
                "CONTENT_OFF",
                "CONTENT_LEN",
                "FILE_LEN",
                "EXTRA");
        }
        std::print(
            out,
            "{:6} {:3}:{:<4} {:16} [{}] {:12} {:>5} {:12} {:12} {:12}",
            sectab_index,
            table_number,
            entry_number,
            g_monad_evcap_section_names[sd->type],
            std::to_underlying(sd->type),
            sd->descriptor_offset,
            describe(sd->compression),
            sd->content_offset,
            sd->content_length,
            sd->file_length);

        ++entry_number;
        if (sd->type == MONAD_EVCAP_SECTION_LINK) {
            ++table_number;
            entry_number = 0;
        }
        ++sectab_index;

        switch (sd->type) {
        case MONAD_EVCAP_SECTION_LINK:
            std::print(out, "   NEXT_TAB: {}", sd->content_offset);
            break;

        case MONAD_EVCAP_SECTION_SCHEMA:
            std::print(
                out,
                "   CONTENT_TYPE: {:6} [{}] HASH: {:{#}}",
                g_monad_event_content_type_names[sd->schema.content_type],
                std::to_underlying(sd->schema.content_type),
                monad::as_hex(std::span{sd->schema.schema_hash}));
            break;

        case MONAD_EVCAP_SECTION_EVENT_BUNDLE:
            if (sd->event_bundle.block_index_id == 0 ||
                empty(block_index_table)) {
                std::print(
                    out,
                    "   #EVT: {} SSEQ: {} SIDX_OFF: {}",
                    sd->event_bundle.event_count,
                    sd->event_bundle.start_seqno,
                    sd->event_bundle.seqno_index_desc_offset);
            }
            else {
                // We have a block index section descriptor (which usually
                // appears before event bundles because of how the writer
                // works)
                monad_blockcap_index_entry const &index_entry =
                    block_index_table[sd->event_bundle.block_index_id - 1];
                std::print(
                    out,
                    "   BLK: {:9} EVT: {:6} SIDX_OFF: {}",
                    index_entry.block_number,
                    sd->event_bundle.event_count,
                    sd->event_bundle.seqno_index_desc_offset);
            }
            break;

        case MONAD_EVCAP_SECTION_SEQNO_INDEX:
            std::print(
                out, "   EB_OFF: {}", sd->seqno_index.event_bundle_desc_offset);
            break;

        case MONAD_EVCAP_SECTION_BLOCK_INDEX:
            block_index_table = std::span{
                std::bit_cast<monad_blockcap_index_entry const *>(
                    map_base + sd->content_offset),
                sd->block_index.block_count};
            std::print(
                out,
                "   ACT: {:c} START: {} END: {} CAP: {}",
                __atomic_load_n(&sd->block_index.is_active, __ATOMIC_ACQUIRE)
                    ? 'Y'
                    : 'N',
                sd->block_index.start_block,
                sd->block_index.start_block +
                    __atomic_load_n(
                        &sd->block_index.block_count, __ATOMIC_ACQUIRE),
                sd->block_index.entry_capacity);
            break;

        case MONAD_EVCAP_SECTION_NONE:
            MONAD_ABORT("NONE section should not be returned by iterator");
        }
        std::println(out);

        if (!print_full_section_table && sectab_index > 10) {
            std::println(
                "skipping {} additional sections...",
                file_header->section_count - sectab_index - 1);
            break;
        }
    }
}

} // End of anonymous namespace

void print_event_source_headers(
    std::span<EventSource const *const> event_sources,
    bool print_full_section_table, std::FILE *out)
{
    auto const is_event_ring = [](EventSource const *es) {
        return es->get_type() == EventSource::Type::EventRing;
    };
    auto const cast_event_ring = [](EventSource const *es) {
        return static_cast<MappedEventRing const *>(es);
    };
    auto event_ring_range = event_sources | std::views::filter(is_event_ring) |
                            std::views::transform(cast_event_ring);

    std::vector<MappedEventRing const *> const rings{
        std::from_range, event_ring_range};
    if (!empty(rings)) {
        print_event_ring_headers(rings, out);
    }

    auto const is_capture_file = [](EventSource const *es) {
        return es->get_type() == EventSource::Type::CaptureFile;
    };
    for (EventSource const *es :
         event_sources | std::views::filter(is_capture_file)) {
        std::println(out, "Event capture files:");
        print_event_capture_header(
            static_cast<EventCaptureFile const *>(es),
            print_full_section_table,
            out);
    }
}

void header_stats_thread_main(std::span<Command *const> commands)
{
    std::list<EventRingState> states;

    MONAD_ASSERT(size(commands) == 1);
    Command *const command = commands[0];
    auto const *const options = command->get_options<HeaderCommandOptions>();

    for (EventSource *es : command->event_sources) {
        if (es->get_type() != EventSource::Type::EventRing ||
            static_cast<MappedEventRing *>(es)->get_initial_liveness() ==
                EventRingLiveness::Snapshot) {
            continue;
        }
        EventRingState &s =
            states.emplace_back(static_cast<MappedEventRing *>(es));
        s.control_sample.reserve(ControlSampleSize);
        for (RankStatistics *r :
             {&s.event_rate, &s.payload_buf_alloc_rate, &s.avg_payload_size}) {
            r->t_digest.set_compression(1000.0);
        }
    }

    uint32_t const print_threshold = *options->stats_interval;
    uint32_t n_samples_in_print_threshold = 0;
    size_t num_total_samples = 0;
    std::FILE *const out = command->output->file;
    bool const tty_control_codes =
        use_tty_control_codes(options->tui_mode, command->output);

    while (g_should_exit == 0 && !empty(states)) {
        ++num_total_samples;

        // Take a statistical sample for each event ring. A sample contains
        // `SampleSize` observations and takes about 1 second to gather (the
        // sampling rate is approximately `SampleSize` Hertz). If any event
        // rings become finalized (no longer written to), they are removed from
        // the state list and returned to us.
        std::vector<MappedEventRing *> const finalized_rings =
            create_samples(states);

        if (tty_control_codes) {
            if (num_total_samples == 1) {
                std::print(out, ANSI_ClearScreen);
            }
            std::print(out, "{}", ANSI_ResetCursor);
        }

        (void)num_total_samples; // XXX: display this later?
        for (MappedEventRing const *const mr : finalized_rings) {
            std::println(
                out, "no more writers for event ring {}", mr->describe());
        }

        for (EventRingState &s : states) {
            compute_rank_stats(s, options->discard_zero_samples);
        }
        if (++n_samples_in_print_threshold == print_threshold) {
            // We've accumulated the number of samples needed to print a
            // statistics line
            for (EventRingState const &s : states) {
                print_update(s, out);
            }
            n_samples_in_print_threshold = 0;
            if (tty_control_codes) {
                std::print(out, "{}", ANSI_FinishUpdate);
            }
        }
    }
}
