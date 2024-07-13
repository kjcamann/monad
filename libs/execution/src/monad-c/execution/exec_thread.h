#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>

#include <monad-c/execution/exec_fiber.h>

struct mex_exec_thread_stats {
    uint64_t fibers_run;                ///< Number of fibers run
};

/// Describes what an execution thread is currently doing
enum mex_exec_thread_state {
    MEX_THREAD_STATE_IDLE,         ///< Waiting for a fiber to be scheduled
    MEX_THREAD_STATE_RUN_FIBER,    ///< Running a fiber
    MEX_THREAD_STATE_RETIRE_FIBER, ///< Retiring a completed fiber
    MEX_THREAD_STATE_EXIT          ///< Thread cleanup
};

struct mex_exec_thread_status {
    enum mex_exec_thread_state state; ///< State
    struct mex_exec_fiber *fiber;     ///< Current fiber, if {RUN,RETIRE}_FIBER
};

struct mex_exec_thread {
    alignas(64) atomic_uintptr_t next_run; ///< Address of next-to-run item
    alignas(64) atomic_uintptr_t cur_run;  ///< What we're currently running
    struct mex_block_vm *block_vm;         ///< Block VM that owns us
    unsigned worker_id;                    ///< Serial id of worker, range [0,n)
    pthread_t thread;                      ///< Handle to our system thread
    long thread_id;                        ///< System ID of this exec thread
    struct mex_exec_thread_stats stats;    ///< Statistics for exec thread
};

void *mex_exec_thread_main(struct mex_exec_thread *exec_thread);

void mex_exec_thread_get_status(const struct mex_exec_thread *exec_thread,
                                struct mex_exec_thread_status *status);

static inline bool
mex_exec_thread_try_schedule(struct mex_exec_thread *thr,
                             struct mex_exec_fiber *new_fiber,
                             struct mex_exec_fiber **swapped_fiber) {
    uintptr_t run_slot;
    mex_priority_t run_slot_prio;
    struct mex_exec_fiber *run_slot_fiber;

    *swapped_fiber = nullptr;
    run_slot = atomic_load_explicit(&thr->next_run, memory_order_seq_cst);
    if (run_slot & 0b1) {
        // This means the worker thread has been told to exit
        return false;
    }
    run_slot_fiber = (struct mex_exec_fiber *)run_slot;
    run_slot_prio = run_slot_fiber != nullptr
                        ? run_slot_fiber->priority
                        : MEX_MIN_PRIORITY;
    if (run_slot_prio <= new_fiber->priority)
        return false;

    // Our new fiber is higher priority than the existing fiber in the run
    // slot; swap them. By the time the swap happens the fiber in the run slot
    // may have changed (it may have started running already) so the result
    // of the swap might be nullptr.
    *swapped_fiber = (struct mex_exec_fiber *)atomic_exchange(&thr->next_run, (uintptr_t)new_fiber);
    return true;
}