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

#include "recordtrace.hpp"
#include "err_cxx.hpp"
#include "eventcap.hpp"
#include "file.hpp"
#include "iterator.hpp"
#include "options.hpp"
#include "util.hpp"

#include <cstddef>
#include <cstdint>
#include <format>
#include <latch>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/event_def.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

namespace
{

inline void BC_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "bcap library error -- {}",
            monad_bcap_get_last_error());
    }
}

struct vbuf_segment_pool
{
    monad_vbuf_segment_allocator allocator;
    pthread_spinlock_t lock;
    TAILQ_HEAD(, monad_vbuf_segment) free_list;
    std::unique_ptr<monad_vbuf_segment[]> segments;
    size_t segment_count;
    size_t free_list_length;
};

int vbuf_segment_pool_allocate(
    monad_vbuf_segment_allocator *a, monad_vbuf_segment **vs_p)
{
    auto *const pool = reinterpret_cast<vbuf_segment_pool *>(a);
    pthread_spin_lock(&pool->lock);
    *vs_p = TAILQ_FIRST(&pool->free_list);
    if (*vs_p == nullptr) {
        pthread_spin_unlock(&pool->lock);
        return ENOBUFS;
    }
    TAILQ_REMOVE(&pool->free_list, *vs_p, entry);
    --pool->free_list_length;
    pthread_spin_unlock(&pool->lock);
    (*vs_p)->written = 0;
    return 0;
}

void vbuf_segment_pool_free(
    monad_vbuf_segment_allocator *a, monad_vbuf_segment *vs)
{
    auto *const pool = reinterpret_cast<vbuf_segment_pool *>(a);
    pthread_spin_lock(&pool->lock);
    TAILQ_INSERT_HEAD(&pool->free_list, vs, entry);
    ++pool->free_list_length;
    pthread_spin_unlock(&pool->lock);
}

monad_vbuf_segment_alloc_ops vbuf_segment_pool_ops = {
    .allocate = vbuf_segment_pool_allocate,
    .free = vbuf_segment_pool_free,
    .activate = nullptr,
    .deactivate = nullptr,
};

void init_vbuf_segment_pool(
    vbuf_segment_pool *pool, uint8_t segment_shift, uint8_t count_shift,
    bool map_hugetlb)
{
    int const extra_mmap_flags = map_hugetlb ? MAP_HUGETLB : 0;
    pool->allocator.ops = &vbuf_segment_pool_ops;
    pthread_spin_init(&pool->lock, PTHREAD_PROCESS_PRIVATE);
    TAILQ_INIT(&pool->free_list);
    pool->segment_count = 1UL << count_shift;
    pool->segments = std::make_unique_for_overwrite<monad_vbuf_segment[]>(
        pool->segment_count);
    if (pool->segments.get() == nullptr) {
        err_f(
            EX_OSERR,
            "alloc of {} vbuf segments for pool failed",
            pool->segment_count);
    }
    for (monad_vbuf_segment &vs :
         std::span{pool->segments.get(), pool->segment_count}) {
        memset(&vs, 0, sizeof vs);
        vs.capacity = 1UL << segment_shift;
        vs.allocator = &pool->allocator;
        vs.map_base = static_cast<uint8_t *>(mmap(
            nullptr,
            vs.capacity,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | extra_mmap_flags,
            -1,
            0));
        if (vs.map_base == MAP_FAILED) {
            err_f(EX_OSERR, "mmap of vbuf {} failed", pool->free_list_length);
        }
        TAILQ_INSERT_TAIL(&pool->free_list, &vs, entry);
        ++pool->free_list_length;
    }
}

void cleanup_vbuf_segment_pool(vbuf_segment_pool *pool)
{
    for (monad_vbuf_segment const &vs :
         std::span{pool->segments.get(), pool->segment_count}) {
        munmap(vs.map_base, vs.capacity);
    }
    pthread_spin_destroy(&pool->lock);
}

} // End of anonymous namespace

bool RecordTraceState::release_hold(TracedProposal *const tp)
{
    if (__atomic_fetch_sub(&tp->hold_count, 1, __ATOMIC_RELAXED) != 1) {
        return false;
    }

    pthread_spin_lock(&pending_proposal_lock);
    TAILQ_REMOVE(&pending_proposal_queue, tp, entry);
    pthread_spin_unlock(&pending_proposal_lock);

    pthread_spin_lock(&sync_proposal_lock);
    TAILQ_INSERT_TAIL(&sync_proposal_queue, tp, entry);
    pthread_spin_unlock(&sync_proposal_lock);

    return true;
}

void recordtrace_thread_main(std::span<Command *const> commands)
{
    std::vector<std::jthread> threads;
    EventIterator iter;

    MONAD_ASSERT(size(commands) == 1);
    Command *const command = commands[0];
    EventSourceSpec &exec_event_source = command->event_sources[0];
    auto const *const options =
        command->get_options<RecordTraceCommandOptions>();
    std::string const &output_spec = options->common_options.output_spec;

    size_t const thread_count =
        command->event_sources.size() + options->worker_thread_count;
    alignas(64) std::latch start_latch{static_cast<long>(thread_count)};

    RecordTraceSettings settings = {
        .exec_iterator = &iter,
        .output_fd = -1,
        .output_spec = output_spec,
        .options = options};

    // Output is underneath a top-level archive directory which must
    // already exist
    settings.output_fd = open(output_spec.c_str(), O_DIRECTORY | O_PATH);
    if (settings.output_fd == -1) {
        err_f(
            EX_OSERR,
            "unable to open block archive directory `{}`",
            output_spec.c_str());
    }

    RecordTraceState rts{};
    pthread_spin_init(&rts.pending_proposal_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&rts.sync_proposal_lock, PTHREAD_PROCESS_PRIVATE);
    TAILQ_INIT(&rts.pending_proposal_queue);
    TAILQ_INIT(&rts.sync_proposal_queue);
    rts.start_latch = &start_latch;

    vbuf_segment_pool vbuf_big_segpool;
    vbuf_segment_pool vbuf_small_segpool;

    init_vbuf_segment_pool(
        &vbuf_big_segpool,
        options->big_pool_size.segment_size_shift,
        options->big_pool_size.segment_count_shift,
        options->big_pool_size.use_hugetlb);

    init_vbuf_segment_pool(
        &vbuf_small_segpool,
        options->small_pool_size.segment_size_shift,
        options->small_pool_size.segment_count_shift,
        options->small_pool_size.use_hugetlb);

    uint64_t const hold_count = command->event_sources.size();
    std::span const trace_sources =
        std::span{command->event_sources}.subspan(1);
    // XXX: hack for now
    bool has_evm_trace_source = false;
    for (EventSourceSpec const &spec : trace_sources) {
        monad_event_content_type_t const content_type = spec.get_content_type();
        vbuf_segment_pool *const segpool =
            content_type == MONAD_EVENT_CONTENT_TYPE_EVMT ? &vbuf_big_segpool
                                                          : &vbuf_small_segpool;
        threads.emplace_back(
            recordtrace_drain, &spec, &segpool->allocator, &settings, &rts);
        auto const thread_name = std::format(
            "rt_drain_{}", g_monad_event_content_type_names[content_type]);
        pthread_setname_np(threads.back().native_handle(), thread_name.c_str());
        has_evm_trace_source |= content_type == MONAD_EVENT_CONTENT_TYPE_EVMT;
    }

    for (unsigned i = 0; i < options->worker_thread_count; ++i) {
        threads.emplace_back(recordtrace_sync, &settings, &rts);
        std::string const thread_name = std::format("rt_sync_{:02}", i);
        pthread_setname_np(threads.back().native_handle(), thread_name.c_str());
    }

    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    BC_CHECK(monad_bcap_builder_create(
        &block_builder,
        &vbuf_small_segpool.allocator,
        &vbuf_small_segpool.allocator));
    BC_CHECK(monad_bcap_finalize_tracker_create(&finalize_tracker));

    // For recordtrace, if no explicit start sequence number is specified, we
    // set it to most recently executed proposed block
    auto &opt_begin_seqno = exec_event_source.opt_begin_seqno;
    if (!opt_begin_seqno &&
        exec_event_source.source_file->get_type() ==
            EventSourceFile::Type::EventRing &&
        exec_event_source.source_file->is_interactive()) {
        opt_begin_seqno = SequenceNumberSpec{
            .type = SequenceNumberSpec::Type::ConsensusEvent,
            .consensus_event = {.consensus_type = MONAD_EXEC_BLOCK_START}};
    }

    start_latch.arrive_and_wait();
    exec_event_source.init_iterator(&iter);
    size_t not_ready_count = 0;
    bool exec_ring_is_live = true;
    while (g_should_exit == 0 && exec_ring_is_live) {
        using enum EventIteratorResult;

        monad_event_descriptor event;
        std::byte const *payload;
        switch (iter.next(&event, &payload)) {
        case Error:
            errx_f(
                EX_SOFTWARE,
                "EventIterator::next error {} -- {}",
                iter.error_code,
                iter.last_error_msg);

        case AfterBegin:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after begin seqno {};"
                "events missing",
                event.seqno,
                *iter.begin_seqno);

        case AfterEnd:
            errx_f(
                EX_SOFTWARE,
                "event seqno {} occurs after end seqno {}; "
                "did a gap occur?",
                event.seqno,
                *iter.end_seqno);

        case End:
            exec_ring_is_live = false;
            continue;

        case NotReady:
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                exec_ring_is_live =
                    !exec_event_source.source_file->is_finalized();
            }
            [[fallthrough]];
        case Skipped:
            continue;

        case Gap:
            // TODO(ken): finalize the writer
            errx_f(
                EX_SOFTWARE,
                "ERROR: exec event gap from {} -> {}, record is destroyed",
                iter.get_last_read_seqno(),
                iter.get_last_written_seqno());

        case Success:
            // TODO(ken): failure cases are the same for gap; they don't
            //   exit, do prepare and/or recover
            // Handled in the main body of the loop
            not_ready_count = 0;
            break;
        }

        monad_bcap_append_result_t append_result;
        monad_bcap_proposal *proposal;

        // Try to append the event to the block builder; we must always call
        // this function even for events we know aren't recorded, since the
        // block builder checks for sequence number gaps internally
        BC_CHECK(monad_bcap_builder_append_event(
            block_builder, &event, payload, &append_result, &proposal));

        if (event.event_type == MONAD_EXEC_BLOCK_START) {
            MONAD_ASSERT(proposal != nullptr);
            TracedProposal *const tp =
                new (std::align_val_t(64)) TracedProposal{};
            tp->proposal = proposal;
            proposal->user = tp;
            tp->hold_count = hold_count;

            // XXX: extend this to be generic (will need to modify execution
            // BLOCK_START definition)
            if (has_evm_trace_source) {
                BlockTrace *const bt = new BlockTrace{
                    .traced_proposal = tp,
                    .trace_type = MONAD_EVENT_CONTENT_TYPE_EVMT,
                    .initial_seqno =
                        event.content_ext[MONAD_FLOW_ACCOUNT_INDEX]};
                monad_vbuf_chain_init(&bt->event_vbufs);
                monad_vbuf_chain_init(&bt->seqno_vbufs);
                tp->trace_map.emplace(bt->trace_type, bt);
            }

            pthread_spin_lock(&rts.pending_proposal_lock);
            TAILQ_INSERT_TAIL(&rts.pending_proposal_queue, tp, entry);
            pthread_spin_unlock(&rts.pending_proposal_lock);
            std::println(
                stderr,
                "E: created traced proposal {}",
                tp->proposal->block_tag.block_number);
        }

        if (event.event_type == MONAD_EXEC_BLOCK_FINALIZED) {
            monad_bcap_proposal_list abandon_chain;
            auto const block_tag =
                *reinterpret_cast<monad_exec_block_tag const *>(payload);
            if (!iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload expired for event {}", event.seqno);
            }
            BC_CHECK(monad_bcap_finalize_tracker_update(
                finalize_tracker, &block_tag, &proposal, &abandon_chain));
            if (proposal == nullptr) {
                // Finalization for a block tag whose proposal we never saw;
                // this is near the beginning of the sequence
                continue;
            }
            auto *tp = static_cast<TracedProposal *>(proposal->user);
            MONAD_ASSERT(tp != nullptr);
            rts.release_hold(tp);
            while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
                TAILQ_REMOVE(&abandon_chain, proposal, entry);
                tp = static_cast<TracedProposal *>(proposal->user);
                MONAD_ASSERT(tp != nullptr);
                rts.release_hold(tp);
            }
            continue;
        }

        if (append_result == MONAD_BCAP_OUTSIDE_BLOCK_SCOPE) {
            continue;
        }

        if (!iter.check_payload(&event)) {
            errx_f(
                EX_SOFTWARE, "payload expired for exec event {}", event.seqno);
        }

        if (append_result == MONAD_BCAP_PROPOSAL_ABORTED) {
            if (event.event_type == MONAD_EXEC_BLOCK_REJECT) {
                continue;
            }
            MONAD_ASSERT_PRINTF(
                event.event_type == MONAD_EXEC_EVM_ERROR,
                "proposal aborted on unexpected event type %s [%hu]",
                g_monad_exec_event_metadata[event.event_type].c_name,
                event.event_type);
            uint32_t const code = *reinterpret_cast<uint32_t const *>(payload);
            errx_f(EX_SOFTWARE, "cannot record after EVM error {}", code);
        }

        if (append_result == MONAD_BCAP_PROPOSAL_FINISHED) {
            MONAD_ASSERT(proposal != nullptr);
            monad_bcap_finalize_tracker_add_proposal(
                finalize_tracker, proposal);
        }
    }

    for (std::jthread &t : threads) {
        t.request_stop();
    }
    for (std::jthread &t : threads) {
        t.join();
    }

    monad_bcap_builder_destroy(block_builder);
    monad_bcap_finalize_tracker_destroy(finalize_tracker);
    cleanup_vbuf_segment_pool(&vbuf_big_segpool);
    cleanup_vbuf_segment_pool(&vbuf_small_segpool);
    (void)close(settings.output_fd);
}
