#include <errno.h>
#include <stdbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <category/core/assert.h>
#include <category/core/likely.h>
#include <category/core/mem/align.h>
#include <category/core/mem/cma/cma_alloc.h>

static struct monad_allocator *g_global_allocator;

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

static struct monad_allocator g_null_allocator = {
    .vtable = &g_null_allocator_ops};

static int
null_alloc(struct monad_allocator *ma, size_t, size_t, struct monad_memblk *blk)
{
    MONAD_ASSERT(ma == &g_null_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    blk->ptr = nullptr;
    blk->size = 0;
    return 0;
}

static int null_realloc(
    struct monad_allocator *ma, size_t, size_t, struct monad_memblk *blk)
{
    MONAD_ASSERT(ma == &g_null_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    MONAD_ASSERT(blk->ptr == nullptr);
    return ENOMEM;
}

static void null_dealloc(struct monad_allocator *ma, struct monad_memblk blk)
{
    MONAD_ASSERT(ma == &g_null_allocator);
    MONAD_ASSERT(blk.ptr == nullptr);
}

static bool
null_owns(struct monad_allocator *ma, struct monad_memblk /*unused*/)
{
    MONAD_ASSERT(ma == &g_null_allocator);
    return false;
}

struct monad_allocator *monad_cma_get_null_allocator()
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

static struct monad_allocator g_malloc_allocator = {
    .vtable = &g_malloc_allocator_ops};

static int malloc_alloc(
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk)
{
    MONAD_ASSERT(ma == &g_malloc_allocator);
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    __builtin_memset(blk, 0, sizeof *blk);
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
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk)
{
    void *new_mem;
    MONAD_ASSERT(ma == &g_malloc_allocator);
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

static void malloc_dealloc(struct monad_allocator *ma, struct monad_memblk blk)
{
    MONAD_ASSERT(ma == &g_malloc_allocator);
    free(blk.ptr);
}

struct monad_allocator *monad_cma_get_malloc_allocator()
{
    return &g_malloc_allocator;
}

#if MONAD_CMA_NO_ATOMICS
struct monad_allocator *monad_cma_get_default_allocator()
{
    return g_global_allocator;
}

struct monad_allocator *
monad_cma_set_default_allocator(struct monad_allocator *new_default)
{
    struct monad_allocator *const last_allocator = g_global_allocator;
    g_global_allocator = new_default;
    return last_allocator;
}
#else
struct monad_allocator *monad_cma_get_default_allocator()
{
    struct monad_allocator *ma_malloc;
    struct monad_allocator *ma_default =
        __atomic_load_n(&g_global_allocator, __ATOMIC_RELAXED);
    if (MONAD_UNLIKELY(ma_default == nullptr)) {
        // No default allocator was set; set the default to the malloc allocator
        // ourselves if it's still unset (it could be changed by another thread
        // at any time)
        ma_malloc = monad_cma_get_malloc_allocator();
        if (__atomic_compare_exchange_n(
                &g_global_allocator,
                &ma_default,
                ma_malloc,
                /*weak*/ false,
                __ATOMIC_RELAXED,
                __ATOMIC_RELAXED)) {
            ma_default = ma_malloc;
        }
    }
    return ma_default;
}

struct monad_allocator *
monad_cma_set_default_allocator(struct monad_allocator *new_default)
{
    return __atomic_exchange_n(
        &g_global_allocator, new_default, __ATOMIC_ACQ_REL);
}

#endif
