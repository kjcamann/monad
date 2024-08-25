#include <errno.h>
#include <stdatomic.h>
#include <stdbit.h>
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
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
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
    return 0;
}

// A helper function called when realloc cannot resize and must allocate
// a new block and move the old one
static int realloc_move(
    struct monad_cma_bump_alloc *ma, size_t size, size_t align,
    monad_memblk_t *blk)
{
    int rc;
    monad_memblk_t new_blk;
    rc = bump_alloc(ma, size, align, &new_blk);
    if (rc != 0) {
        return rc;
    }
    memcpy(new_blk.ptr, blk->ptr, size > blk->size ? size : blk->size);
    *blk = new_blk;
    return 0;
}

static int bump_realloc(
    struct monad_cma_bump_alloc *ma, size_t size, size_t align,
    monad_memblk_t *blk)
{
    uintptr_t next;

    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
        return EINVAL;
    }
    if (blk->ptr == nullptr) {
        // realloc(nullptr) behaves like alloc
        return bump_alloc(ma, size, align, blk);
    }
    if ((uint8_t const *)blk->ptr + size > ma->end) {
        // There isn't enough memory available to fulfill this request in
        // any case
        return ENOMEM;
    }
    if (MONAD_UNLIKELY(((uintptr_t)blk->ptr & (align - 1)) != 0)) {
        // The original address is no longer suitably aligned (the realloc
        // wants to increase the alignment) so we have to no choice but to copy
        return realloc_move(ma, size, align, blk);
    }
    next = atomic_load_explicit(&ma->next, memory_order_relaxed);
    if ((uintptr_t)(blk->ptr + blk->size) != next) {
        // blk is no longer the last allocation and cannot be resized.
        // If the block wants to shrink, do nothing and announce that it is
        // now smaller, otherwise copy to a new block
        if (size <= blk->size) {
            blk->size = size;
            return 0;
        }
        return realloc_move(ma, size, align, blk);
    }

    // blk is the last allocation; resize it as long as the new size can
    // fit and no other thread has changed `ma->next` from underneath us
    if (atomic_compare_exchange_strong_explicit(
            &ma->next,
            &next,
            (uintptr_t)blk->ptr + size,
            memory_order_acq_rel,
            memory_order_relaxed)) {
        // Our block size was changed, we're done
        blk->size = size;
        return 0;
    }

    // ma->next was changed by another thread; opportunity to resize is gone
    return realloc_move(ma, size, align, blk);
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
    .realloc = (monad_cma_realloc_fn *)bump_realloc,
    .dealloc = (monad_cma_dealloc_fn *)bump_dealloc,
    .owns = (monad_cma_owns_fn *)bump_owns};

int monad_cma_bump_alloc_init(
    struct monad_cma_bump_alloc *bump_alloc, monad_memblk_t blk,
    monad_allocator_t **ma)
{
    if (MONAD_UNLIKELY(bump_alloc == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(blk.ptr == nullptr)) {
        return EINVAL;
    }
    memset(bump_alloc, 0, sizeof *bump_alloc);
    bump_alloc->self.vtable = &g_bump_alloc_ops;
    bump_alloc->begin = blk.ptr;
    bump_alloc->end = bump_alloc->begin + blk.size;
    atomic_store_explicit(
        &bump_alloc->next, (uintptr_t)bump_alloc->begin, memory_order_release);
    if (ma != nullptr) {
        *ma = &bump_alloc->self;
    }
    return 0;
}
