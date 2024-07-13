#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/queue.h>

#include <ck_ring.h>

#include <monad-c/support/result.h>
#include <monad-c/support/thread.h>

struct mex_exec_fiber;
struct mex_exec_thread;

/// A concurrent FIFO queue (using an SPSC ring buffer) that is used to pass
/// fiber objects between the block VM and the scheduler thread
struct mex_fiber_queue {
    ck_ring_t ring_ctl;
    ck_ring_buffer_t *ring_buf;
};

/// A priority queue, implemented using a min-heap; used to pick the highest
/// priority fiber to schedule next. For reference, see
/// [CLRS 6.5: Priority Queues]
struct mex_fiber_prio_queue {
    struct mex_exec_fiber **fibers;
    unsigned size;
    unsigned capacity;
};

struct mex_scheduler_stats {
    uint64_t scheduler_invoked;  ///< Number of calls to try_schedule_fibers
    uint64_t fibers_scheduled;   ///< Total number of fibers scheduled
    uint64_t priority_swaps;     ///< Replaced next-to-run fiber w/ better prio
};

struct mex_scheduler {
    alignas(64) atomic_ulong event_mask; ///< Bits indicate what is ready
    alignas(64) struct mex_fiber_queue fiber_input_queue; ///< To be scheduled
    alignas(64) struct mex_exec_thread *exec_threads; ///< Cached thread array
    size_t num_exec_threads;            ///< Number of available exec threads
    struct mex_fiber_prio_queue prio_queue; ///< Track fibers by priority
    struct mex_block_vm *block_vm;      ///< Block VM that owns us
    struct mex_scheduler_stats stats;   ///< Fiber scheduling statistics
    pthread_t thread;                   ///< Handle to our system thread
    long thread_id;                     ///< System ID of scheduler's thread
};

/*
 * Scheduler interface to the block VM
 */

void *mex_sched_main(struct mex_scheduler *sched);

monad_result mex_sched_enqueue_fiber(struct mex_scheduler *sched,
                                     struct mex_exec_fiber *fiber);

void mex_sched_stop(struct mex_scheduler *sched);

/*
 * Concurrent fiber queue utility functions, public because they are also used
 * by the block VM
 */

monad_result mex_fiber_queue_create(struct mex_fiber_queue *q, unsigned size);

void mex_fiber_queue_destroy(struct mex_fiber_queue *q);

static inline bool mex_fiber_queue_push(struct mex_fiber_queue *q,
                                        struct mex_exec_fiber *fiber) {
    return ck_ring_enqueue_spsc(&q->ring_ctl, q->ring_buf, fiber);
}

static inline struct mex_exec_fiber*
mex_fiber_queue_pop(struct mex_fiber_queue *q) {
    struct mex_exec_fiber *fiber;
    return ck_ring_dequeue_spsc(&q->ring_ctl, q->ring_buf, &fiber)
        ? fiber : nullptr;
}