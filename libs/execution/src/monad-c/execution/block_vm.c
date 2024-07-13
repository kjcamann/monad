#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <umem.h>

#include <monad-c/ethereum/block.h>
#include <monad-c/ethereum/transaction.h>
#include <monad-c/execution/block_vm_impl.h>
#include <monad-c/execution/exec_fiber.h>
#include <monad-c/execution/exec_thread.h>
#include <monad-c/execution/scheduler.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/bit.h>
#include <monad-c/support/result.h>

constexpr unsigned FIBER_OUTPUT_RING_SIZE = 512;

/// Holds both the public API type and the internal execution state object
/// for a particular block
struct block_user_handle {
    struct mex_block_exec_output exec_output;
    struct mex_block_exec_state exec_state;
};

static monad_result bvm_create_mempools(struct mex_block_vm *bvm) {
    bvm->mempools[BVM_MEMPOOL_BLOCK_USER_HANDLE] =
        umem_cache_create("user handle", sizeof(struct block_user_handle),
                          alignof(struct block_user_handle), nullptr, nullptr,
                          nullptr, nullptr, nullptr, 0);
    bvm->mempools[BVM_MEMPOOL_TXN_EXEC_STATE] =
        umem_cache_create("txn exec state", sizeof(struct mex_txn_exec_state),
                          alignof(struct mex_txn_exec_state), nullptr, nullptr,
                          nullptr, nullptr, nullptr, 0);
    return monad_ok(BVM_MEMPOOL_COUNT);
}

static void bvm_destroy_mempools(struct mex_block_vm *bvm) {
    for (unsigned i = 0; i < BVM_MEMPOOL_COUNT; ++i) {
        if (bvm->mempools[i] != nullptr)
            umem_cache_destroy(bvm->mempools[i]);
    }
}

static monad_result bvm_create_scheduler_objects(struct mex_block_vm *bvm) {
    struct mex_exec_thread *exec_thread;
    int rc;

    for (size_t t = 0; t < bvm->create_opts.num_exec_threads; ++t) {
        exec_thread = bvm->exec_threads + t;
        exec_thread->next_run = 0;
        exec_thread->block_vm = bvm;
        exec_thread->worker_id = (unsigned)t;
        // XXX: need affinity set here
        rc = pthread_create(&exec_thread->thread, nullptr,
                            (void *(*)(void *))mex_exec_thread_main,
                            exec_thread);
        if (rc != 0)
            return monad_make_sys_error(rc);
    }

    rc = pthread_create(&bvm->scheduler.thread, nullptr,
                        (void *(*)(void *))mex_sched_main, &bvm->scheduler);
    if (rc != 0)
        return monad_make_sys_error(rc);
    bvm->scheduler.exec_threads = bvm->exec_threads;
    bvm->scheduler.num_exec_threads = bvm->create_opts.num_exec_threads;
    bvm->scheduler.block_vm = bvm;

    return monad_ok(bvm->create_opts.num_exec_threads);
}

static void bvm_destroy_scheduler_objects(struct mex_block_vm *bvm) {
    int rc;
    void *thr_exit;

    // Check if the scheduler thread exists and if it does, tell it to stop.
    rc = pthread_kill(bvm->scheduler.thread, 0);
    if (rc != ESRCH) {
        mex_sched_stop(&bvm->scheduler);
        rc = pthread_join(bvm->scheduler.thread, &thr_exit);
        if (rc != 0) {
            // XXX: do something here?
        }
    }

    // Stop all the execution threads
    for (size_t t = 0; t < bvm->create_opts.num_exec_threads; ++t) {
        rc = pthread_kill(bvm->exec_threads[t].thread, 0);
        if (rc != ESRCH)
            atomic_store(&bvm->exec_threads[t].next_run, 0b1);
        rc = pthread_join(bvm->exec_threads[t].thread, &thr_exit);
        if (rc != 0) {
            // XXX: do something here
        }
    }
}

static monad_result bvm_alloc_exec_output(struct mex_block_vm *bvm,
                                          struct mex_block_exec_output **output) {
    struct block_user_handle *const uh =
        umem_cache_alloc(bvm->mempools[BVM_MEMPOOL_BLOCK_USER_HANDLE], UMEM_DEFAULT);
    if (uh == nullptr)
        return monad_make_sys_error(errno);
    memset(uh, 0, sizeof *uh);
    uh->exec_output.block_vm = bvm;
    uh->exec_output.exec_state = &uh->exec_state;
    uh->exec_state.block_vm = bvm;
    (*output) = &uh->exec_output;
    return monad_ok(0);
}

static void bvm_free_exec_output(struct mex_block_vm *bvm,
                                         struct mex_block_exec_output *output) {
    umem_cache_free(bvm->mempools[BVM_MEMPOOL_BLOCK_USER_HANDLE], output);
}

static monad_result bvm_alloc_txn_exec_state(struct mex_block_exec_state *bes,
                                             struct mex_txn_exec_state **tes) {
    *tes = umem_cache_alloc(bes->block_vm->mempools[BVM_MEMPOOL_TXN_EXEC_STATE],
                            UMEM_DEFAULT);
    if (*tes == nullptr)
        return monad_make_sys_error(errno);
    memset(*tes, 0, sizeof **tes);
    return monad_ok(0);
}

static monad_result bvm_free_txn_exec_state(struct mex_txn_exec_state *tes) {
    struct mex_block_vm *bvm = tes->block_state->block_vm;
    umem_cache_free(bvm->mempools[BVM_MEMPOOL_TXN_EXEC_STATE], tes);
    return monad_ok(0);
}

static monad_result bvm_start_block(struct mex_block_exec_state *bes,
                                    rlp_buf_t block_rlp_buf,
                                    struct rlp_iterator *block_iter) {
    monad_result mr;
    struct rlp_value block_sequence;
    struct rlp_value block_item;

    // Decode the top-level RLP value (the block sequence) and open a sequence
    // iterator to it.
    mr = rlp_value_decode(block_rlp_buf, &block_sequence);
    if (monad_is_error(mr))
        return mr;
    mr = rlp_sequence_open_iter(&block_sequence, block_iter);
    if (monad_is_error(mr))
        return mr;

    // Get the next item in the block sequence, which should be the header,
    // and decode it.
    mr = rlp_sequence_next(block_iter, &block_item);
    if (monad_is_error(mr))
        return mr;
    mr = mel_decode_block_header(&block_item, &bes->block_header);
    if (monad_is_error(mr))
        return mr;
    bes->block_number = be64toh(bes->block_header.number.value);

    // Initialize the transaction list.
    TAILQ_INIT(&bes->txns);
    bes->txn_count = 0;

    return monad_ok(0);
}

static monad_result bvm_prepare_txn(struct mex_txn_exec_state *tes) {
    struct mex_block_vm *bvm;
    monad_result mr;

    bvm = tes->block_state->block_vm;
    mr = mex_exec_fiber_pool_alloc(&bvm->fiber_pool, &tes->fiber);
    if (monad_is_error(mr)) {
        // TODO(ken): if ENOBUFS we need to block here, waiting for txns to
        //   finish and give up their fibers
        return monad_make_sys_error(ENOSYS);
    }

    tes->fiber->priority = tes->txn_number;
    tes->fiber->txn_state = tes;
    tes->fiber->cur_thread = nullptr;

    // TODO(ken): in a real implementation, we visit the access list and try
    //   to warm up all the resources known to be used by the transaction
    (void)tes->txn.access_list_iter;

    return monad_ok(0);
}

static monad_result bvm_submit_txn(struct mex_txn_exec_state *tes) {
    struct mex_block_vm *bvm;
    monad_result mr;

    bvm = tes->block_state->block_vm;
    mr = mex_sched_enqueue_fiber(&bvm->scheduler, tes->fiber);
    if (monad_is_error(mr))
        return mr;

    return monad_ok(0);
}

static monad_result bvm_exec_block_txns(struct mex_block_exec_state *bes,
                                        struct rlp_iterator *block_iter) {
    monad_result mr;
    struct rlp_value txn_sequence;
    struct rlp_value txn_rlp;
    struct rlp_iterator txn_iter;
    struct mex_txn_exec_state *tes;

    // Get the next item in the block, which should be the transaction sequence,
    // an open an iterator it.
    mr = rlp_sequence_next(block_iter, &txn_sequence);
    if (monad_is_error(mr))
        return mr;
    mr = rlp_sequence_open_iter(&txn_sequence, &txn_iter);
    if (monad_is_error(mr))
        return mr;

    while (rlp_sequence_has_next(&txn_iter)) {
        /*
         * For each transaction in the transaction sequence:
         *
         *   1. Allocate a mex_txn_exec_state object to track the execution
         *      state of the transaction
         *
         *   2. Decode the transaction parameters from the RLP encoding
         *
         *   3. Link the mex_txn_state object into the list of all open
         *      transactions (headed by the mex_block_exec_state object)
         *
         *   4. Call bvm_prepare_txn to allocate all resources needed for
         *      execution
         *
         *   5. Call bvm_submit_txn to submit the transaction to the global
         *      fiber scheduler
         */
        mr = rlp_sequence_next(&txn_iter, &txn_rlp);
        if (monad_is_error(mr))
            goto Error;

        mr = bvm_alloc_txn_exec_state(bes, &tes);
        tes->block_state = bes;
        if (monad_is_error(mr))
            goto Error;

        mr = mel_decode_transaction(&txn_rlp, &tes->txn);
        if (monad_is_error(mr)) {
            bvm_free_txn_exec_state(tes);
            goto Error;
        }
        TAILQ_INSERT_TAIL(&bes->txns, tes, link);
        tes->txn_number = (uint32_t)bes->txn_count++;

        mr = bvm_prepare_txn(tes);
        if (monad_is_error(mr)) {
            bvm_free_txn_exec_state(tes);
            goto Error;
        }

        mr = bvm_submit_txn(tes);
        if (monad_is_error(mr)) {
            0;
        }
    }

    return monad_ok(0);

Error:
    // Cleanup!
    return mr;
}

monad_result mex_block_vm_create(const struct mex_block_vm_options *opts,
                                 const struct mdb_trie_db *trie_db,
                                 struct mex_block_vm **pbvm) {
    monad_result mr;
    struct mex_block_vm *bvm;
    size_t block_vm_size;

    if (opts == nullptr || pbvm == nullptr)
        return monad_make_sys_error(EFAULT);
    *pbvm = nullptr;

    if (opts->num_exec_threads == 0 ||
        opts->num_exec_threads > MEX_BLOCK_VM_MAX_THREADS ||
        opts->num_exec_fibers == 0 ||
        opts->num_exec_fibers > MEX_BLOCK_VM_MAX_FIBERS)
        return monad_make_sys_error(EINVAL);

    block_vm_size = sizeof *bvm + sizeof(struct mex_exec_thread) *
                                      (opts->num_exec_threads - 1);
    bvm = umem_alloc(block_vm_size, UMEM_DEFAULT);
    if (bvm == nullptr)
        return monad_make_sys_error(ENOMEM);
    memset(bvm, 0, block_vm_size);
    bvm->alloc_size = block_vm_size;
    bvm->create_opts = *opts;

    // Create memory pools for block VM's own dynamic objects
    mr = bvm_create_mempools(bvm);
    if (monad_is_error(mr))
        goto Error;

    // Create the pool of mex_exec_fiber objects
    mr = mex_exec_fiber_pool_create(&bvm->fiber_pool,
                                    bvm->create_opts.num_exec_fibers, nullptr,
                                    UMEM_DEFAULT);
    if (monad_is_error(mr))
        goto Error;

    // Create the fiber output ring, used to pass fibers which have finished
    // executing back to us
    mr = mex_fiber_queue_create(&bvm->fiber_output_queue,
                                FIBER_OUTPUT_RING_SIZE);
    if (monad_is_error(mr))
        goto Error;

    // Create the execution threads and the scheduler thread
    mr = bvm_create_scheduler_objects(bvm);
    if (monad_is_error(mr))
        goto Error;

    *pbvm = bvm;
    return monad_ok(0);

Error:
    mex_block_vm_destroy(bvm, /*force=*/true);
    return mr;
}

monad_result mex_block_vm_exec(struct mex_block_vm *bvm,
                               struct mcl_cbyte_range block_rlp_buf,
                               struct mex_block_exec_output **output) {
    monad_result mr;
    struct rlp_iterator block_iter;
    struct mex_block_exec_state *bes;

    if (bvm == nullptr || block_rlp_buf.begin == nullptr ||
        block_rlp_buf.end == nullptr || output == nullptr)
        return monad_make_sys_error(EFAULT);

    *output = nullptr;
    mr = bvm_alloc_exec_output(bvm, output);
    if (monad_is_error(mr))
        return mr;
    bes = (*output)->exec_state;
    mr = bvm_start_block(bes, block_rlp_buf, &block_iter);
    if (monad_is_error(mr))
        return mr;

    return bvm_exec_block_txns(bes, &block_iter);
}

monad_result mex_block_vm_wait(const struct mex_block_exec_output *output,
                               const struct timespec *timeout) {
    if (output == nullptr)
        return monad_make_sys_error(EFAULT);
    ++output->block_vm->stats.num_blocks; // FIXME: not really done here
    return monad_ok(0);
}

monad_result mex_block_vm_release(struct mex_block_exec_output *output) {
    if (output == nullptr)
        return monad_make_sys_error(EFAULT);
    bvm_free_exec_output(output->block_vm, output);
    return monad_ok(0);
}

monad_result mex_block_vm_destroy(struct mex_block_vm *bvm, bool force) {
    // This is also called internally by mex_block_vm_create to clean up
    // partially-constructed block VMs, so we need to check if it's safe to
    // call some of the destroy routines.
    bvm_destroy_scheduler_objects(bvm);
    if (bvm->fiber_output_queue.ring_buf != nullptr)
        mex_fiber_queue_destroy(&bvm->fiber_output_queue);
    if (bvm->fiber_pool.fibers != nullptr)
        mex_exec_fiber_pool_destroy(&bvm->fiber_pool);
    bvm_destroy_mempools(bvm);
    umem_free(bvm, bvm->alloc_size);
    return monad_ok(0);
}

const struct mex_block_vm_stats *
mex_block_vm_get_stats(const struct mex_block_vm *bvm) {
    return &bvm->stats;
}

void mex_block_vm_retire_fiber(struct mex_block_vm *bvm,
                               struct mex_exec_fiber *fiber) {
    // When called, we're still running on the execution thread. We cannot
    // fail here, so we must spin until there is output space.
    fiber->cur_thread = nullptr;
    if (!mex_fiber_queue_push(&bvm->fiber_output_queue, fiber)) {
        ++bvm->stats.fiber_output_queue_stalls;
        while (!mex_fiber_queue_push(&bvm->fiber_output_queue, fiber));
    }
}