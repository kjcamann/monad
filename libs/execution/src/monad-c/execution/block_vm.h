#pragma once

#include <stddef.h>
#include <stdint.h>
#include <monad-c/support/result.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mdb_trie_db;
struct mcl_cbyte_range;
struct timespec;

constexpr unsigned MEX_BLOCK_VM_MAX_THREADS = 32;
constexpr unsigned MEX_BLOCK_VM_MAX_FIBERS = 1024;

constexpr unsigned MEX_MIN_FIBER_STACK_SIZE = (1 << 16);
constexpr unsigned MEX_DEFAULT_FIBER_STACK_SIZE = (1 << 21);

struct mex_block_vm_options {
    unsigned num_exec_threads;  ///< # of threads for txn execution
    unsigned num_exec_fibers;   ///< # of fibers across all threads
    uint32_t fiber_stack_size;  ///< Fiber stack size
};

struct mex_block_exec_output;
struct mex_block_vm;
struct mex_block_vm_stats;

monad_result mex_block_vm_create(const struct mex_block_vm_options *opts,
                                 const struct mdb_trie_db *trie_db,
                                 struct mex_block_vm **bvm);

monad_result mex_block_vm_destroy(struct mex_block_vm *bvm, bool force);

monad_result mex_block_vm_exec(struct mex_block_vm *bvm,
                               struct mcl_cbyte_range block_rlp_buf,
                               struct mex_block_exec_output **output);

monad_result mex_block_vm_wait(const struct mex_block_exec_output *output,
                               const struct timespec *timeout);

monad_result mex_block_vm_release(struct mex_block_exec_output *output);

const struct mex_block_vm_stats *
mex_block_vm_get_stats(const struct mex_block_vm *bvm);

struct mex_block_exec_state;

struct mex_block_exec_output {
    struct mex_block_vm *block_vm;           ///< Block VM owning us
    struct mex_block_exec_state *exec_state; ///< Opaque exec state, used by BVM
};

struct mex_block_vm_stats {
    size_t num_blocks;                ///< Number of blocks processed
    size_t fiber_output_queue_stalls; ///< Blocked on fiber output queue push
};

#ifdef __cplusplus
} // extern "C"
#endif
