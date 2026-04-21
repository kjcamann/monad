#include <errno.h>
#include <stdbit.h>
#include <stdint.h>
#include <string.h>

#include <category/core/likely.h>
#include <category/core/mem/align.h>
#include <category/core/mem/cma/cma_alloc.h>
#include <category/core/mem/cma/cma_bump.h>

[[gnu::always_inline]] static inline uintptr_t
align_ptr(size_t align, size_t size, uintptr_t addr, size_t *space)
{
    uintptr_t const aligned_addr = monad_round_size_to_align(addr, align);
    size_t const used = aligned_addr - addr + size;
    if (MONAD_UNLIKELY(used > *space)) {
        return (uintptr_t)(void *)nullptr;
    }
    *space -= used;
    return aligned_addr;
}

static int bump_alloc(
    struct monad_cma_bump *bump, size_t size, size_t align,
    struct monad_memblk *blk)
{
    uintptr_t next;
    size_t space;
    bool done = false;

    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    __builtin_memset(blk, 0, sizeof *blk);
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
        return EINVAL;
    }

#if MONAD_CMA_NO_ATOMICS
    (void)done;

    next = bump->next;
    space = (size_t)((uintptr_t)bump->end - next);
    next = align_ptr(align, size, next, &space);
    if (MONAD_UNLIKELY(next == 0)) {
        return ENOMEM;
    }
#else
    // Speculatively assume that the next byte address, suitably rounded, will
    // start our new allocation. The atomic cmpxchg takes care of other threads
    // racing against us trying to take the same address. We'll either succeed
    // eventually or run out of memory.
    next = __atomic_load_n(&bump->next, __ATOMIC_RELAXED);
    do {
        space = (size_t)((uintptr_t)bump->end - next);
        next = align_ptr(align, size, next, &space);
        if (MONAD_UNLIKELY(next == 0)) {
            return ENOMEM;
        }
        done = __atomic_compare_exchange_n(
            &bump->next,
            &next,
            next + size,
            /*weak=*/true,
            __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);
    }
    while (!done);
#endif

    blk->ptr = (void *)next;
    blk->size = size;
    return 0;
}

// A helper function called when realloc cannot resize and must allocate
// a new block and move the old one
static int realloc_move(
    struct monad_cma_bump *bump, size_t size, size_t align,
    struct monad_memblk *blk)
{
    int rc;
    struct monad_memblk new_blk;

    rc = bump_alloc(bump, size, align, &new_blk);
    if (rc != 0) {
        return rc;
    }
    memcpy(new_blk.ptr, blk->ptr, size > blk->size ? size : blk->size);
    *blk = new_blk;
    return 0;
}

static int bump_realloc(
    struct monad_cma_bump *bump, size_t size, size_t align,
    struct monad_memblk *blk)
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
        return bump_alloc(bump, size, align, blk);
    }
    if (MONAD_UNLIKELY(((uintptr_t)blk->ptr & (align - 1)) != 0)) {
        // The original address is no longer suitably aligned (the realloc
        // wants to increase the alignment) so we have to no choice but to copy
        return realloc_move(bump, size, align, blk);
    }

#if MONAD_CMA_NO_ATOMICS
    next = bump->next;
#else
    next = __atomic_load_n(&bump->next, __ATOMIC_RELAXED);
#endif
    if ((uintptr_t)(blk->ptr + blk->size) != next) {
        // blk is no longer the last allocation and cannot be resized.
        // If the block wants to shrink, do nothing and announce that it is
        // now smaller, otherwise try to copy to a new block
        if (size <= blk->size) {
            blk->size = size;
            return 0;
        }
        return realloc_move(bump, size, align, blk);
    }

    if ((uint8_t const *)blk->ptr + size > bump->end) {
        return ENOMEM;
    }

#if MONAD_CMA_NO_ATOMICS
    bump->next = (uintptr_t)blk->ptr + size;
    blk->size = size;
    return 0;
#else
    // Change `bump->next` as long as no thread is racing against us
    if (__atomic_compare_exchange_n(
            &bump->next,
            &next,
            (uintptr_t)blk->ptr + size,
            /*weak=*/false,
            __ATOMIC_ACQ_REL,
            __ATOMIC_RELAXED)) {
        // Success, we're done
        blk->size = size;
        return 0;
    }

    // bump->next was changed by another thread; opportunity to resize is gone
    return realloc_move(bump, size, align, blk);
#endif
}

static void bump_dealloc(struct monad_cma_bump *bump, struct monad_memblk blk)
{
    uintptr_t old_next = (uintptr_t)blk.ptr + blk.size;
    MONAD_ASSERT(bump != nullptr);
    // Try to put the block back, if it was the most recent one. If not, the
    // memory won't really be freed
#if MONAD_CMA_NO_ATOMICS
    if (bump->next == old_next) {
        bump->next = (uintptr_t)blk.ptr;
    }
#else
    do {
        (void)__atomic_compare_exchange_n(
            &bump->next,
            &old_next,
            old_next - blk.size,
            /*weak=*/false,
            __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);
    }
    while (old_next == (uintptr_t)blk.ptr);
#endif
}

static bool bump_owns(struct monad_cma_bump *bump, struct monad_memblk blk)
{
    if (MONAD_UNLIKELY(bump == nullptr)) {
        return EFAULT;
    }
    return blk.ptr >= (void *)bump->end &&
           blk.ptr + blk.size <= (void *)bump->end;
}

static struct monad_allocator_ops g_bump_ops = {
    .alloc = (monad_cma_alloc_fn *)bump_alloc,
    .realloc = (monad_cma_realloc_fn *)bump_realloc,
    .dealloc = (monad_cma_dealloc_fn *)bump_dealloc,
    .owns = (monad_cma_owns_fn *)bump_owns};

int monad_cma_bump_init(
    struct monad_cma_bump *bump, struct monad_memblk blk,
    struct monad_allocator **ma)
{
    if (MONAD_UNLIKELY(bump == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(blk.ptr == nullptr)) {
        return EINVAL;
    }
    __builtin_memset(bump, 0, sizeof *bump);
    bump->self.vtable = &g_bump_ops;
    bump->begin = blk.ptr;
    bump->end = bump->begin + blk.size;
    bump->next = (uintptr_t)bump->begin;
    if (ma != nullptr) {
        *ma = &bump->self;
    }
    return 0;
}
