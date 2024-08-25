#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include <monad/core/likely.h>
#include <monad/mem/align.h>
#include <monad/mem/cma/cma_alloc.h>
#include <monad/mem/cma/cma_bump_alloc.h>

static int bump_alloc(
    struct monad_cma_bump_alloc *ma, size_t size, size_t align,
    monad_memblk_t *blk)
{
    uintptr_t next;
    uintptr_t space;
    bool done = false;

    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    memset(blk, 0, sizeof *blk);
    if (MONAD_UNLIKELY(align == 0)) {
        return EINVAL;
    }

    // Speculatively assume that the next byte address, suitably rounded, will
    // start our new allocation. The atomic cmpxchg takes care of other threads
    // racing against us trying to take the same address. We'll either succeed
    // eventually or run out of memory.
    next = atomic_load_explicit(&ma->next, memory_order_relaxed);
    do {
        space = (uintptr_t)ma->end - next;
        next = monad_align(align, size, next, &space);
        if (MONAD_UNLIKELY(next == 0)) {
            return ENOMEM;
        }
        done = atomic_compare_exchange_weak_explicit(
            &ma->next,
            &next,
            next + size,
            memory_order_acq_rel,
            memory_order_acquire);
    }
    while (!done);

    blk->ptr = (void *)next;
    blk->size = size;
    ma->last = *blk;
    return 0;
}

static void bump_dealloc(struct monad_cma_bump_alloc *ma, monad_memblk_t blk)
{
    uintptr_t old_next = (uintptr_t)blk.ptr + blk.size;
    MONAD_DEBUG_ASSERT(ma != nullptr);
    // Try to put the block back, if it was the most recent one. If not, the
    // memory won't really be freed
    do {
        (void)atomic_compare_exchange_strong_explicit(
            &ma->next,
            &old_next,
            old_next - blk.size,
            memory_order_acq_rel,
            memory_order_acquire);
    }
    while (old_next == (uintptr_t)blk.ptr);
}

static bool bump_owns(struct monad_cma_bump_alloc *ma, monad_memblk_t blk)
{
    if (MONAD_UNLIKELY(ma == nullptr)) {
        return EFAULT;
    }
    return blk.ptr >= (void *)ma->end && blk.ptr + blk.size <= (void *)ma->end;
}

static struct monad_allocator_ops g_bump_alloc_ops = {
    .alloc = (monad_cma_alloc_fn *)bump_alloc,
    .dealloc = (monad_cma_dealloc_fn *)bump_dealloc,
    .owns = (monad_cma_owns_fn *)bump_owns};

int monad_cma_bump_alloc_init(
    struct monad_cma_bump_alloc *ma, monad_memblk_t blk)
{
    if (MONAD_UNLIKELY(ma == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(blk.ptr == nullptr)) {
        return EINVAL;
    }
    memset(ma, 0, sizeof *ma);
    ma->self.vtable = &g_bump_alloc_ops;
    ma->begin = blk.ptr;
    ma->end = ma->begin + blk.size;
    atomic_store_explicit(
        &ma->next, (uintptr_t)ma->begin, memory_order_release);
    return 0;
}
