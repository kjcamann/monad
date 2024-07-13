#include <errno.h>
#include <string.h>
#include <monad-c/execution/exec_fiber.h>
#include <monad-c/support/assert.h>
#include <monad-c/support/result.h>

#include <umem.h>

static int mex_exec_fiber_ctor(struct mex_exec_fiber *fiber,
                               struct mex_exec_fiber_pool *pool, int flags) {
    MONAD_ASSERT(pool->num_fibers != pool->max_num_fibers);
    memset(fiber, 0, sizeof *fiber);
    pool->num_fibers++;
    fiber->fiber_id = pool->next_fiber_id++;
    // XXX: need stacks, etc.
    return 0;
}

static void mex_exec_fiber_dtor(struct mex_exec_fiber *fiber,
                                struct mex_exec_fiber_pool *pool) {
    TAILQ_REMOVE(&pool->freelist, fiber, linkage);
    --pool->num_fibers;
}

monad_result mex_exec_fiber_pool_create(struct mex_exec_fiber_pool *pool,
                                        size_t max_num_fibers, vmem_t *vmp,
                                        int flags) {
    TAILQ_INIT(&pool->freelist);
    pool->fibers = umem_cache_create("exec fiber", sizeof(struct mex_exec_fiber),
                                     alignof(struct mex_exec_fiber),
                                     (umem_constructor_t*)mex_exec_fiber_ctor,
                                     (umem_destructor_t*)mex_exec_fiber_dtor,
                                     nullptr, pool, vmp, flags);
    if (pool->fibers == nullptr)
        return monad_make_sys_error(ENOMEM);
    pool->max_num_fibers = max_num_fibers;
    return monad_ok(0);
}

void mex_exec_fiber_pool_destroy(struct mex_exec_fiber_pool *pool) {
    // TODO(ken): some kind of EBUSY mechanism?
    umem_cache_destroy(pool->fibers);
}

monad_result mex_exec_fiber_pool_alloc(struct mex_exec_fiber_pool *pool,
                                       struct mex_exec_fiber **fiber) {
    if (TAILQ_EMPTY(&pool->freelist)) {
        // Nothing on the freelist, check if we can allocate more fibers.
        if (pool->num_fibers == pool->max_num_fibers)
            return monad_make_sys_error(ENOBUFS);
        *fiber = umem_cache_alloc(pool->fibers, UMEM_DEFAULT);
        return monad_ok(0);
    }
    *fiber = TAILQ_FIRST(&pool->freelist);
    TAILQ_REMOVE(&pool->freelist, *fiber, linkage);
    return monad_ok(0);
}

void mex_exec_fiber_pool_free(struct mex_exec_fiber_pool *pool,
                              struct mex_exec_fiber *fiber) {
    // Put in on the freelist, then mark it freed in cache. If the cache
    // decides to free the backing slab back, the destructor will be called,
    // which will remove it from the freelist.
    TAILQ_INSERT_HEAD(&pool->freelist, fiber, linkage);
    umem_cache_free(pool->fibers, fiber);
}