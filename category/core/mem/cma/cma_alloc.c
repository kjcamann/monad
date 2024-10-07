#include <errno.h>
#include <stdatomic.h>
#include <stdbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <monad/core/assert.h>
#include <monad/core/likely.h>
#include <monad/mem/align.h>
#include <monad/mem/cma/cma_alloc.h>

static atomic_uintptr_t g_global_allocator;

/*
 * Null allocator
 */

static monad_cma_alloc_fn null_alloc;
static monad_cma_realloc_fn null_realloc;
static monad_cma_dealloc_fn null_dealloc;
static monad_cma_owns_fn null_owns;

static struct monad_allocator_ops g_null_allocator_ops = {
    .alloc = null_alloc,
    .realloc = null_realloc,
    .dealloc = null_dealloc,
    .owns = null_owns};

static monad_allocator_t g_null_allocator = {.vtable = &g_null_allocator_ops};

static int
null_alloc(monad_allocator_t *ma, size_t, size_t, monad_memblk_t *blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_null_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    blk->ptr = nullptr;
    blk->size = 0;
    return 0;
}

static int null_realloc(
    monad_allocator_t *ma, size_t, size_t, [[maybe_unused]] monad_memblk_t *blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_null_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    MONAD_ASSERT(blk->ptr == nullptr);
    return ENOMEM;
}

static void
null_dealloc(monad_allocator_t *ma, [[maybe_unused]] monad_memblk_t blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_null_allocator);
    MONAD_ASSERT(blk.ptr == nullptr);
}

static bool null_owns(monad_allocator_t *ma, monad_memblk_t /*unused*/)
{
    MONAD_DEBUG_ASSERT(ma == &g_null_allocator);
    return false;
}

monad_allocator_t *monad_cma_get_null_allocator()
{
    return &g_null_allocator;
}

/*
 * malloc allocator (uses C11 aligned_alloc instead of malloc)
 */

static monad_cma_alloc_fn malloc_alloc;
static monad_cma_realloc_fn malloc_realloc;
static monad_cma_dealloc_fn malloc_dealloc;

static struct monad_allocator_ops g_malloc_allocator_ops = {
    .alloc = malloc_alloc,
    .realloc = malloc_realloc,
    .dealloc = malloc_dealloc,
    .owns = nullptr};

static monad_allocator_t g_malloc_allocator = {
    .vtable = &g_malloc_allocator_ops};

static int malloc_alloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_malloc_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
        return EINVAL;
    }
    size = monad_round_size_to_align(size, align);
    blk->ptr = aligned_alloc(align, size);
    if (MONAD_UNLIKELY(blk->ptr == nullptr)) {
        blk->size = 0;
        return errno;
    }
    blk->size = size;
    return 0;
}

static int malloc_realloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk)
{
    void *new_mem;
    MONAD_DEBUG_ASSERT(ma == &g_malloc_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
        return EINVAL;
    }
    size = monad_round_size_to_align(size, align);
    if (MONAD_UNLIKELY(align > alignof(max_align_t))) {
        // As of 2024, only Microsoft's libc has an interface for reallocation
        // that allows the caller to also request over-alignment. Thus we need
        // to always move the memory block. We could speculatively realloc(3)
        // an already-suitably-aligned block and hope it grows, maintaining the
        // original alignment. But if it moves our memory and mis-aligns it,
        // we can't guarantee we'll be able to move it back, breaking the
        // contract that we do nothing if the realloc can't succeed. Thus we
        // have to pessimize it this way.
        new_mem = aligned_alloc(align, size);
        if (new_mem == nullptr) {
            return errno;
        }
        memcpy(new_mem, blk->ptr, size > blk->size ? size : blk->size);
        free(blk->ptr);
        blk->ptr = new_mem;
        blk->size = size;
        return 0;
    }
    new_mem = realloc(blk->ptr, size);
    if (MONAD_UNLIKELY(new_mem == nullptr)) {
        // Could not resize; we do nothing here.
        return errno;
    }
    blk->ptr = new_mem;
    blk->size = size;
    return 0;
}

static void malloc_dealloc(monad_allocator_t *ma, monad_memblk_t blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_malloc_allocator);
    free(blk.ptr);
}

monad_allocator_t *monad_cma_get_malloc_allocator()
{
    return &g_malloc_allocator;
}

monad_allocator_t *monad_cma_get_default_allocator()
{
    uintptr_t malloc_addr;
    uintptr_t default_alloc_addr =
        atomic_load_explicit(&g_global_allocator, memory_order_relaxed);
    if (MONAD_UNLIKELY(default_alloc_addr == 0)) {
        malloc_addr = (uintptr_t)monad_cma_get_malloc_allocator();
        if (atomic_compare_exchange_strong(
                &g_global_allocator, &default_alloc_addr, malloc_addr)) {
            default_alloc_addr = malloc_addr;
        }
    }
    return (monad_allocator_t *)default_alloc_addr;
}

monad_allocator_t *
monad_cma_set_default_allocator(monad_allocator_t *new_default)
{
    return (monad_allocator_t *)atomic_exchange_explicit(
        &g_global_allocator, (uintptr_t)new_default, memory_order_acq_rel);
}
