#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

#include <monad/core/assert.h>
#include <monad/core/likely.h>
#include <monad/mem/align.h>
#include <monad/mem/cma/cma_alloc.h>

static atomic_uintptr_t g_global_allocator;

/*
 * Null allocator
 */

static monad_cma_alloc_fn null_alloc;
static monad_cma_dealloc_fn null_dealloc;
static monad_cma_owns_fn null_owns;

static struct monad_allocator_ops g_null_allocator_ops = {
    .alloc = null_alloc, .dealloc = null_dealloc, .owns = null_owns};

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
static monad_cma_dealloc_fn malloc_dealloc;

static struct monad_allocator_ops g_malloc_allocator_ops = {
    .alloc = malloc_alloc, .dealloc = malloc_dealloc, .owns = nullptr};

static monad_allocator_t g_malloc_allocator = {
    .vtable = &g_malloc_allocator_ops};

static int malloc_alloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk)
{
    MONAD_DEBUG_ASSERT(ma == &g_malloc_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
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
