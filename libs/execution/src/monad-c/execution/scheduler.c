#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/queue.h>
#include <umem.h>

#include <monad-c/support/assert.h>
#include <monad-c/support/bit.h>
#include <monad-c/support/result.h>
#include <monad-c/execution/block_vm_impl.h>
#include <monad-c/execution/exec_thread.h>
#include <monad-c/execution/scheduler.h>

constexpr unsigned FIBER_INPUT_RING_SIZE = 512;

enum scheduler_event : uint8_t {
    SCHED_EVENT_SHUTDOWN,      ///< Scheduler is told to exit
    SCHED_EVENT_INPUT_QUEUE,   ///< Input queue has a new fiber to schedule
};

static void prio_queue_alloc(struct mex_fiber_prio_queue *q,
                             unsigned num_fibers) {
    const size_t page_size = sysconf(_SC_PAGESIZE);
    q->size = 0;
    q->capacity = num_fibers;
    q->fibers =
        umem_alloc_align(sizeof(struct mex_fiber_queue*) * num_fibers,
                         page_size, UMEM_DEFAULT);
    /// XXX: panic if q->fibers == nullptr here?
}

static void prio_queue_free(struct mex_fiber_prio_queue *q) {
    umem_free(q->fibers, sizeof(struct mex_exec_fiber*) * q->capacity);
    q->fibers = nullptr;
}

#define PQ_PARENT_IDX(i) ((i - 1) / 2)
#define PQ_LEFT_CHILD_IDX(i) (2*i + 1)
#define PQ_RIGHT_CHILD_IDX(i) (2*i + 2)

static inline void swap(void *p1, void *p2) {
    void *const t = p2;
    p2 = p1;
    p1 = t;
}

static inline void prio_queue_min_heapify(struct mex_fiber_prio_queue *q,
                                          unsigned parent_idx) {
HeapifyNextLevel:
    unsigned smallest_idx = parent_idx;
    unsigned left_idx = PQ_LEFT_CHILD_IDX(parent_idx);
    unsigned right_idx = PQ_RIGHT_CHILD_IDX(parent_idx);

    if (left_idx < q->size && q->fibers[left_idx]->priority <
        q->fibers[smallest_idx]->priority)
        smallest_idx = left_idx;

    if (right_idx < q->size && q->fibers[right_idx]->priority <
        q->fibers[smallest_idx]->priority)
        smallest_idx = right_idx;

    if (smallest_idx == parent_idx)
        return;

    swap(&q->fibers[parent_idx], &q->fibers[smallest_idx]);
    parent_idx = smallest_idx;
    goto HeapifyNextLevel;
}

inline static struct mex_exec_fiber*
prio_queue_pop(struct mex_fiber_prio_queue *q) {
    struct mex_exec_fiber *min;
    if (q->size == 0)
        return nullptr;
    min = q->fibers[0];
    --q->size;
    if (q->size > 0) {
        swap(&q->fibers[0], &q->fibers[q->size]);
        prio_queue_min_heapify(q, 0);
    }
    return min;
}

inline static void prio_queue_insert(struct mex_fiber_prio_queue *q,
                                     struct mex_exec_fiber *fiber) {
    unsigned idx;
    MONAD_ASSERT(q->size < q->capacity);
    idx = q->size++;
    q->fibers[idx] = fiber;

    while (idx != 0 && q->fibers[idx]->priority < q->fibers[PQ_PARENT_IDX(idx)]->priority) {
        swap(&q->fibers[idx], &q->fibers[PQ_PARENT_IDX(idx)]);
        idx = PQ_PARENT_IDX(idx);
    }
}

static inline void add_event_mask_bits(atomic_ulong *event_mask,
                                       unsigned long bits) {
    unsigned long rmask;
    do {
        rmask = atomic_load_explicit(event_mask, memory_order_relaxed);
    } while (!atomic_compare_exchange_strong(event_mask, &rmask, rmask | bits));
}

static void init_thread(struct mex_scheduler *sched) {
    monad_result mr;
    unsigned num_fibers;

    mr = mcl_thread_get_id();
    sched->thread_id = monad_is_error(mr) ? -1 : monad_value(mr);
    (void)mcl_thread_set_name("sched");

    mr = mex_fiber_queue_create(&sched->fiber_input_queue,
                                FIBER_INPUT_RING_SIZE);
    // XXX: error handling if alloc fails

    prio_queue_alloc(&sched->prio_queue,
                     sched->block_vm->create_opts.num_exec_fibers);

    // XXX: barrier stuff so we don't run until all init is finished
}

static void cleanup_thread(struct mex_scheduler *sched) {
    prio_queue_free(&sched->prio_queue);
    mex_fiber_queue_destroy(&sched->fiber_input_queue);
}

static unsigned try_schedule_fibers(struct mex_scheduler *sched) {
    struct mex_exec_fiber *prio_queue_fiber;
    struct mex_exec_fiber *swapped_fiber;
    struct mex_exec_thread *exec_thread;
    bool fiber_scheduled;
    const uint64_t init_fibers_scheduled = sched->stats.fibers_scheduled;

    sched->stats.scheduler_invoked;
    if (sched->prio_queue.size == 0)
        return 0;

    do {
        // Try scheduling the highest priority fiber, which is the first element
        // in the priority queue. We only peek at this for now, because we may
        // not end up popping it from the queue if it's lower priority than
        // everything else that's about to run.
        prio_queue_fiber = sched->prio_queue.fibers[0];

        // We are allowed to pop multiple fibers from the priority queue during
        // this call, but each linear scan of the execution threads must
        // schedule a fiber. That is, if we complete a full linear scan and
        // we don't successfully schedule anything (because the existing stuff
        // is higher priority), then we return to the event polling loop to
        // look for other scheduling inputs.
        fiber_scheduled = false;

        // Pick the best executor thread to run this fiber. For now the
        // algorithm is simple: do a linear scan of the exec threads and call
        // mex_exec_thread_try_schedule on each. This function tries to place
        // the fiber in the "next-to-run" slot for the thread, if the fiber's
        // priority is higher than what is already there. When that happens,
        // it also returns the old fiber that was previously scheduled.
        for (size_t t = 0; t < sched->num_exec_threads; ++t) {
            exec_thread = &sched->exec_threads[t];
            fiber_scheduled = mex_exec_thread_try_schedule(exec_thread, prio_queue_fiber, &swapped_fiber);
            if (!fiber_scheduled)
                continue;

            (void)prio_queue_pop(&sched->prio_queue);
            if (swapped_fiber != nullptr) {
                prio_queue_insert(&sched->prio_queue, swapped_fiber);
                ++sched->stats.priority_swaps;
            }
            ++sched->stats.fibers_scheduled;
            break; // No need to look at other threads, we're done
        }
    } while (fiber_scheduled && sched->prio_queue.size > 0);

    return sched->stats.fibers_scheduled - init_fibers_scheduled;
}

static void dequeue_new_fiber(struct mex_scheduler *sched) {
    struct mex_exec_fiber *new_fiber;

    // Pop the next fiber from the input queue, place in into priority queue,
    // and run the scheduler
    new_fiber = mex_fiber_queue_pop(&sched->fiber_input_queue);
    MONAD_ASSERT(new_fiber != nullptr);
    prio_queue_insert(&sched->prio_queue, new_fiber);
    try_schedule_fibers(sched);
}

static void *poll_scheduler_events(struct mex_scheduler *sched) {
    int index;

PollAgain:
    unsigned long ready_events = 0;
    ready_events = atomic_exchange(&sched->event_mask, 0);

    while (ready_events != 0) {
        index = stdc_trailing_zeros_ul(ready_events);
        ready_events &= ~(1UL << index);
        switch (index) {
        case SCHED_EVENT_SHUTDOWN:
            return nullptr;

        case SCHED_EVENT_INPUT_QUEUE:
            dequeue_new_fiber(sched);
            break;

        default:
            // XXX: what kind of event is this?
            break;
        }
    }

    goto PollAgain;
}

void *mex_sched_main(struct mex_scheduler *sched) {
    void *ret;
    init_thread(sched);
    ret = poll_scheduler_events(sched);
    cleanup_thread(sched);
    return ret;
}

monad_result mex_sched_enqueue_fiber(struct mex_scheduler *sched,
                                     struct mex_exec_fiber *fiber) {
    if (!mex_fiber_queue_push(&sched->fiber_input_queue, fiber))
        return monad_make_sys_error(EAGAIN);
    add_event_mask_bits(&sched->event_mask, 1UL << SCHED_EVENT_INPUT_QUEUE);
    return monad_ok(0);
}

void mex_sched_stop(struct mex_scheduler *sched) {
    add_event_mask_bits(&sched->event_mask, 1UL << SCHED_EVENT_SHUTDOWN);
}

monad_result mex_fiber_queue_create(struct mex_fiber_queue *q, unsigned size) {
    MONAD_ASSERT(stdc_has_single_bit_ui(size));
    ck_ring_init(&q->ring_ctl, size);
    q->ring_buf = umem_alloc(sizeof(struct mex_exec_fiber*) * size,
                             UMEM_DEFAULT);
    if (q->ring_buf == nullptr)
        return monad_make_sys_error(ENOMEM);
    return monad_ok(0);
}

void mex_fiber_queue_destroy(struct mex_fiber_queue *q) {
    const size_t ring_bytes = sizeof(struct mex_exec_fiber*) *
                              ck_ring_capacity(&q->ring_ctl);
    MONAD_ASSERT(q != nullptr);
    umem_free(q->ring_buf, ring_bytes);
}