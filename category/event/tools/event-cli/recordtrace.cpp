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
#include "command.hpp"
#include "file.hpp"
#include "iterator.hpp"
#include "options.hpp"
#include "stream.hpp"

#include <cstddef>
#include <cstdint>
#include <format>
#include <latch>
#include <memory>
#include <new>
#include <optional>
#include <print>
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

[[nodiscard]] std::string init_vbuf_segment_pool(
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
        return std::format(
            "alloc of {} vbuf segments for pool failed", pool->segment_count);
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
            return std::format(
                "mmap of vbuf {} failed: {} [{}]",
                pool->free_list_length,
                strerror(errno),
                errno);
        }
        TAILQ_INSERT_TAIL(&pool->free_list, &vs, entry);
        ++pool->free_list_length;
    }
    return {};
}

void cleanup_vbuf_segment_pool(vbuf_segment_pool *pool)
{
    for (monad_vbuf_segment const &vs :
         std::span{pool->segments.get(), pool->segment_count}) {
        munmap(vs.map_base, vs.capacity);
    }
    pthread_spin_destroy(&pool->lock);
}

struct State
{
    ~State() noexcept;

    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    RecordTraceState trace_state;
    RecordTraceContext trace_context;
    uint64_t initial_hold_count;
    vbuf_segment_pool vbuf_big_segpool;
    vbuf_segment_pool vbuf_small_segpool;
    std::vector<std::jthread> threads;
    bool has_evm_trace_source;
};

State::~State() noexcept
{
    monad_bcap_builder_destroy(block_builder);
    monad_bcap_finalize_tracker_destroy(finalize_tracker);
    cleanup_vbuf_segment_pool(&vbuf_big_segpool);
    cleanup_vbuf_segment_pool(&vbuf_small_segpool);
}

std::string recordtrace_init(StreamObserver *so)
{
    std::unique_ptr state = std::make_unique<State>();

    RecordTraceContext &ctx = state->trace_context;
    ctx.options = so->command->get_options<RecordTraceCommandOptions>();
    ctx.output_fd = -1;
    ctx.output_spec = ctx.options->common_options.output_spec;

    size_t const thread_count =
        so->command->event_sources.size() + ctx.options->worker_thread_count;
    alignas(64) std::latch start_latch{static_cast<long>(thread_count)};

    // Output is underneath a top-level archive directory which must
    // already exist
    state->trace_context.output_fd =
        open(state->trace_context.output_spec.c_str(), O_DIRECTORY);
    if (ctx.output_fd == -1) {
        return std::format(
            "unable to open block archive directory `{}`",
            ctx.output_spec.c_str());
    }

    RecordTraceState &rts = state->trace_state;
    pthread_spin_init(&rts.pending_proposal_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&rts.sync_proposal_lock, PTHREAD_PROCESS_PRIVATE);
    TAILQ_INIT(&rts.pending_proposal_queue);
    TAILQ_INIT(&rts.sync_proposal_queue);
    rts.start_latch = &start_latch;

    std::string err;

    err = init_vbuf_segment_pool(
        &state->vbuf_big_segpool,
        ctx.options->big_pool_size.segment_size_shift,
        ctx.options->big_pool_size.segment_count_shift,
        ctx.options->big_pool_size.use_hugetlb);
    if (!err.empty()) {
        return err;
    }

    err = init_vbuf_segment_pool(
        &state->vbuf_small_segpool,
        ctx.options->small_pool_size.segment_size_shift,
        ctx.options->small_pool_size.segment_count_shift,
        ctx.options->small_pool_size.use_hugetlb);
    if (!err.empty()) {
        return err;
    }

    state->initial_hold_count = so->command->event_sources.size();
    std::span const trace_sources =
        std::span{so->command->event_sources}.subspan(1);
    // XXX: hack for now, need EventSourceSpec::get_content_type!
    for (EventSourceSpec const &spec : trace_sources) {
        monad_event_content_type_t const content_type =
            spec.source_file->get_type() == EventSourceFile::Type::EventRing
                ? static_cast<MappedEventRing const *>(spec.source_file)
                      ->get_header()
                      ->content_type
                : MONAD_EVENT_CONTENT_TYPE_NONE;
        vbuf_segment_pool *const segpool =
            content_type == MONAD_EVENT_CONTENT_TYPE_EVMT
                ? &state->vbuf_big_segpool
                : &state->vbuf_small_segpool;
        state->threads.emplace_back(
            recordtrace_drain, &spec, &segpool->allocator, &ctx, &rts);
        auto const thread_name = std::format(
            "rt_drain_{}", g_monad_event_content_type_names[content_type]);
#if !defined(__APPLE__)
        pthread_setname_np(
            state->threads.back().native_handle(), thread_name.c_str());
#endif
        state->has_evm_trace_source |=
            content_type == MONAD_EVENT_CONTENT_TYPE_EVMT;
    }

    for (unsigned i = 0; i < ctx.options->worker_thread_count; ++i) {
        state->threads.emplace_back(recordtrace_sync, &ctx, &rts);
        std::string const thread_name = std::format("rt_sync_{:02}", i);
#if !defined(__APPLE__)
        pthread_setname_np(
            state->threads.back().native_handle(), thread_name.c_str());
#endif
    }

    BCAP_CHECK_INIT(monad_bcap_builder_create(
        &state->block_builder,
        &state->vbuf_small_segpool.allocator,
        &state->vbuf_small_segpool.allocator));
    BCAP_CHECK_INIT(
        monad_bcap_finalize_tracker_create(&state->finalize_tracker));

    start_latch.arrive_and_wait();
    so->state = state.release();
    return {};
}

std::string recordtrace_iter_init(StreamObserver *so, EventIterator *iter)
{
    return rewind_to_block_boundary(so, iter);
}

StreamUpdateResult
recordtrace_update(StreamObserver *so, EventIterator *iter, StreamEvent *e)
{
    if (e->iter_result != EventIteratorResult::Success) {
        return StreamUpdateResult::Abort;
    }

    monad_bcap_append_result_t append_result;
    monad_bcap_proposal *proposal;
    State *const state = so->get_state<State>();

    // Try to append the event to the block builder; we must always call
    // this function even for events we know aren't recorded, since the
    // block builder checks for sequence number gaps internally
    BCAP_CHECK_UPDATE(monad_bcap_builder_append_event(
        state->block_builder,
        &e->event,
        e->payload,
        &append_result,
        &proposal));

    if (e->event.event_type == MONAD_EXEC_BLOCK_START) {
        MONAD_ASSERT(proposal != nullptr);
        TracedProposal *const tp = new (std::align_val_t(64)) TracedProposal{};
        tp->proposal = proposal;
        proposal->user = tp;
        tp->hold_count = state->initial_hold_count;

        // XXX: extend this to be generic (will need to modify execution
        // BLOCK_START definition)
        if (state->has_evm_trace_source) {
            BlockTrace *const bt = new BlockTrace{
                .traced_proposal = tp,
                .trace_type = MONAD_EVENT_CONTENT_TYPE_EVMT,
                .initial_seqno =
                    e->event.content_ext[MONAD_FLOW_ACCOUNT_INDEX]};
            monad_vbuf_chain_init(&bt->event_vbufs);
            monad_vbuf_chain_init(&bt->seqno_vbufs);
            tp->trace_map.emplace(bt->trace_type, bt);
        }

        pthread_spin_lock(&state->trace_state.pending_proposal_lock);
        TAILQ_INSERT_TAIL(
            &state->trace_state.pending_proposal_queue, tp, entry);
        pthread_spin_unlock(&state->trace_state.pending_proposal_lock);
        std::println(
            stderr,
            "E: created traced proposal {}",
            tp->proposal->block_tag.block_number);
    }

    if (e->event.event_type == MONAD_EXEC_BLOCK_FINALIZED) {
        monad_bcap_proposal_list abandon_chain;
        auto const block_tag =
            *reinterpret_cast<monad_exec_block_tag const *>(e->payload);
        if (!iter->check_payload(&e->event)) {
            stream_warnx_f(
                so,
                "event {} payload lost! OFFSET: {}, WINDOW_START: {}",
                e->event.seqno,
                e->event.payload_buf_offset,
                iter->ring.mapped_event_ring->get_buffer_window_start());
            return StreamUpdateResult::Abort;
        }
        BCAP_CHECK_UPDATE(monad_bcap_finalize_tracker_update(
            state->finalize_tracker, &block_tag, &proposal, &abandon_chain));
        if (proposal == nullptr) {
            // Finalization for a block tag whose proposal we never saw;
            // this is near the beginning of the sequence
            return StreamUpdateResult::Ok;
        }
        auto *tp = static_cast<TracedProposal *>(proposal->user);
        MONAD_ASSERT(tp != nullptr);
        state->trace_state.release_hold(tp);
        while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
            TAILQ_REMOVE(&abandon_chain, proposal, entry);
            tp = static_cast<TracedProposal *>(proposal->user);
            MONAD_ASSERT(tp != nullptr);
            state->trace_state.release_hold(tp);
        }
        return StreamUpdateResult::Ok;
    }

    if (append_result == MONAD_BCAP_OUTSIDE_BLOCK_SCOPE) {
        return StreamUpdateResult::Ok;
    }

    if (!iter->check_payload(&e->event)) {
        stream_warnx_f(
            so,
            "event {} payload lost! OFFSET: {}, WINDOW_START: {}",
            e->event.seqno,
            e->event.payload_buf_offset,
            iter->ring.mapped_event_ring->get_buffer_window_start());
        return StreamUpdateResult::Abort;
    }

    if (append_result == MONAD_BCAP_PROPOSAL_ABORTED) {
        if (e->event.event_type == MONAD_EXEC_BLOCK_REJECT) {
            return StreamUpdateResult::Ok;
        }
        MONAD_ASSERT_PRINTF(
            e->event.event_type == MONAD_EXEC_EVM_ERROR,
            "proposal aborted on unexpected event type %s [%hu]",
            g_monad_exec_event_metadata[e->event.event_type].c_name,
            e->event.event_type);
        uint32_t const code = *reinterpret_cast<uint32_t const *>(e->payload);
        stream_warnx_f(so, "cannot record after EVM error {}", code);
        return StreamUpdateResult::Abort;
    }

    if (append_result == MONAD_BCAP_PROPOSAL_FINISHED) {
        MONAD_ASSERT(proposal != nullptr);
        monad_bcap_finalize_tracker_add_proposal(
            state->finalize_tracker, proposal);
    }

    return StreamUpdateResult::Ok;
}

void recordtrace_finish(
    StreamObserver *so, StreamUpdateResult last_update_result)
{
    State *const state = so->get_state<State>();

    for (std::jthread &t : state->threads) {
        t.request_stop();
    }
    for (std::jthread &t : state->threads) {
        t.join();
    }
    (void)close(state->trace_context.output_fd);

    // XXX: what to do with this?
    (void)last_update_result;

    delete state;
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

StreamObserverOps const recordtrace_ops = {
    .init = recordtrace_init,
    .iter_init = recordtrace_iter_init,
    .update = recordtrace_update,
    .finish = recordtrace_finish,
};
