#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#include <monad-c/support/result.h>
#include <monad-c/execution/block_vm_impl.h>
#include <monad-c/execution/scheduler.h>

static void init_thread(struct mex_exec_thread *exec_thread) {
    char thr_name[8];
    monad_result mr;

    mr = mcl_thread_get_id();
    exec_thread->thread_id = monad_is_error(mr) ? -1 : monad_value(mr);
    (void)snprintf(thr_name, sizeof thr_name, "exec%02u",
                   exec_thread->worker_id);
    (void)mcl_thread_set_name(thr_name);
    atomic_store(&exec_thread->cur_run, 0);
}

inline static uintptr_t wait_for_event(struct mex_exec_thread *exec_thread) {
    uintptr_t run_slot = atomic_load(&exec_thread->next_run);
    if (run_slot == 0) {
        // XXX: stats: store the start time of our wait
        atomic_store(&exec_thread->cur_run, 0);
        while ((run_slot = atomic_load(&exec_thread->next_run)) == 0);
        // XXX: update stats
    }
    return run_slot;
}

static void run_fiber(struct mex_exec_thread *exec_thread,
                      struct mex_exec_fiber *fiber) {
    struct mex_block_vm *bvm;

    fiber->cur_thread = exec_thread;
    atomic_store(&exec_thread->cur_run, (uintptr_t)exec_thread);
    // XXX: simulates running the fiber, when done we return to here to retire
    // it
    fprintf(stdout, "fiber %p is running txn: %llu:%u on worker %u\n", fiber,
            fiber->txn_state->block_state->block_number,
            fiber->txn_state->txn_number, exec_thread->worker_id);

    // Fiber is done running, retire it
    atomic_store(&exec_thread->cur_run, (uintptr_t)exec_thread | 0b1);
    bvm = fiber->txn_state->block_state->block_vm;
    mex_block_vm_retire_fiber(bvm, fiber);
}

void *mex_exec_thread_main(struct mex_exec_thread *exec_thread) {
    init_thread(exec_thread);
    uintptr_t run_slot;
    struct mex_exec_fiber *run_slot_fiber;

    while (true) {
        run_slot = wait_for_event(exec_thread);
        while (!atomic_compare_exchange_strong(&exec_thread->next_run, &run_slot, 0));
        if (run_slot & 0b1) {
            atomic_store(&exec_thread->cur_run, 0b1);
            break;
        }
        run_fiber(exec_thread, (struct mex_exec_fiber *)run_slot);
    }

    return nullptr;
}

void mex_exec_thread_get_status(const struct mex_exec_thread *exec_thread,
                                struct mex_exec_thread_status *status) {
    const uintptr_t cur_run =
        atomic_load_explicit(&exec_thread->cur_run, memory_order_relaxed);
    if (cur_run == 0) {
        status->state = MEX_THREAD_STATE_IDLE;
        status->fiber = nullptr;
    } else if (cur_run == 0b1) {
        status->state = MEX_THREAD_STATE_EXIT;
        status->fiber = nullptr;
    } else {
        status->state = (cur_run & 0b1)
            ? MEX_THREAD_STATE_RETIRE_FIBER
            : MEX_THREAD_STATE_RUN_FIBER;
        status->fiber = (struct mex_exec_fiber *)(cur_run & ~0b1ULL);
    }
}