#pragma once

#include <stddef.h>
#include <stdint.h>

#include <umem.h>
#include <sys/queue.h>

#include <monad-c/ethereum/block.h>
#include <monad-c/ethereum/transaction.h>
#include <monad-c/execution/block_vm.h>
#include <monad-c/execution/exec_fiber.h>
#include <monad-c/execution/exec_thread.h>
#include <monad-c/execution/scheduler.h>

struct mex_exec_fiber;

/// Holds all transaction-level state for execution
struct mex_txn_exec_state {
    struct mex_block_exec_state *block_state; ///< Exec state for block we're in
    TAILQ_ENTRY(mex_txn_exec_state) link;     ///< All txn exec states in block
    struct mel_transaction txn;               ///< Decoded transaction params
    struct mex_exec_fiber *fiber;             ///< Fiber for execution
    uint32_t txn_number;                      ///< Transaction number in block
};

/// Holds all block-level state for execution
struct mex_block_exec_state {
    struct mex_block_vm *block_vm;         ///< Block VM evaluating us
    struct mel_block_header block_header;  ///< Decoded block header
    uint64_t block_number;                 ///< Block number, from header
    TAILQ_HEAD(, mex_txn_exec_state) txns; ///< List of all txn exec states
    _Atomic(size_t) txn_count;             ///< Number of txns created
};

enum mex_block_vm_memory_pool {
    BVM_MEMPOOL_BLOCK_USER_HANDLE,
    BVM_MEMPOOL_TXN_EXEC_STATE,
    BVM_MEMPOOL_COUNT
};

struct mex_block_vm {
    size_t alloc_size;                           ///< Our size + trailing data
    umem_cache_t *mempools[BVM_MEMPOOL_COUNT];   ///< All block VM memory pools
    struct mex_exec_fiber_pool fiber_pool;       ///< Source of mex_exec_fiber
    struct mex_fiber_queue fiber_output_queue;   ///< FIFO for completed fibers
    struct mex_block_vm_stats stats;             ///< Statistics
    struct mex_block_vm_options create_opts;     ///< Options at creation
    struct mex_scheduler scheduler;              ///< Scheduler instance
    struct mex_exec_thread exec_threads[1];      ///< Exec threads (trailing array)
};

void mex_block_vm_retire_fiber(struct mex_block_vm *bvm,
                               struct mex_exec_fiber *fiber);