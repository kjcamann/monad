#pragma once

#include <stdint.h>
#include <umem.h>

#include <sys/queue.h>

#include <monad-c/support/result.h>

struct mex_exec_thread;
struct mex_txn_exec_state;

typedef uint32_t mex_priority_t;
constexpr uint32_t MEX_MIN_PRIORITY = UINT32_MAX;

struct mex_exec_fiber {
    mex_priority_t priority;              ///< Priority (smaller ints -> higher)
    uint64_t fiber_id;                    ///< Serial id of fiber, starting at 0
    TAILQ_ENTRY(mex_exec_fiber) linkage;  ///< Linkage for list we're on
    struct mex_txn_exec_state *txn_state; ///< Exec. state for txn we're running
    struct mex_exec_thread *cur_thread;   ///< Exec. thread currently running us
};

struct mex_exec_fiber_pool {
    TAILQ_HEAD(, mex_exec_fiber) freelist; ///< Constructed but free objects
    size_t num_fibers;                     ///< Total constructed fibers
    uint64_t next_fiber_id;                ///< Next ID for a constructed fiber
    umem_cache_t *fibers;                  ///< Pool of constructed fibers
    size_t max_num_fibers;                 ///< Maximum allowed number of fibers
};

monad_result mex_exec_fiber_pool_create(struct mex_exec_fiber_pool *pool,
                                        size_t max_num_fibers, vmem_t *vmp,
                                        int flags);

void mex_exec_fiber_pool_destroy(struct mex_exec_fiber_pool *pool);

monad_result
mex_exec_fiber_pool_alloc(struct mex_exec_fiber_pool *pool,
                          struct mex_exec_fiber **fiber);

void mex_exec_fiber_pool_free(struct mex_exec_fiber_pool *pool,
                              struct mex_exec_fiber *fiber);