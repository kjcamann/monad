#pragma once

/**
 * @file
 *
 * This file defines an interface for dynamic memory allocation that internal
 * monad library code can use, to avoid hard-coding a particular memory
 * allocation strategy such as malloc(3). See the documentation file `cma.md`
 * for details.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_allocator;
struct monad_memblk;

constexpr size_t MONAD_CMA_DEFAULT_ALIGN = alignof(max_align_t);

/// The result of allocating memory is both the allocated address and the
/// allocated size, which may be different than the size requested
struct monad_memblk
{
    void *ptr;
    size_t size;
};

typedef enum monad_cma_owns_result
{
    MONAD_CMA_OWNS_FALSE,
    MONAD_CMA_OWNS_TRUE,
    MONAD_CMA_OWNS_NOT_SUPPORTED
} monad_cma_owns_result_t;

typedef int(monad_cma_alloc_fn)(
    struct monad_allocator *, size_t, size_t, struct monad_memblk *);

typedef int(monad_cma_realloc_fn)(
    struct monad_allocator *, size_t, size_t, struct monad_memblk *);

typedef void(monad_cma_dealloc_fn)(
    struct monad_allocator *, struct monad_memblk);

typedef bool(monad_cma_owns_fn)(struct monad_allocator *, struct monad_memblk);

struct monad_allocator_ops
{
    monad_cma_alloc_fn *alloc;
    monad_cma_alloc_fn *realloc;
    monad_cma_dealloc_fn *dealloc;
    monad_cma_owns_fn *owns;
};

/// Base class of the allocator, and the first field of any derived allocator
/// in C-style inheritance; can be used directly for stateless allocators
struct monad_allocator
{
    struct monad_allocator_ops const *vtable;
};

/// Returns the global stateless null allocator
struct monad_allocator *monad_cma_get_null_allocator();

/// Returns the global stateless malloc(3) allocator
struct monad_allocator *monad_cma_get_malloc_allocator();

/// Returns the process-wide default allocator
struct monad_allocator *monad_cma_get_default_allocator();

/// Sets the process-wide default allocator to the provided one, and returns
/// the previous default allocator
struct monad_allocator *
monad_cma_set_default_allocator(struct monad_allocator *next);

/// Allocate a block of memory with the given size and alignment; if
/// successful the block info will be copied into `blk`; upon failure, this
/// returns an errno(3) domain code
static int monad_cma_alloc(
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk);

/// Allocate an array of `count` items with the given size and alignment;
/// similar to the libc `calloc(3)` function
static int monad_cma_calloc(
    struct monad_allocator *ma, size_t count, size_t size, size_t align,
    struct monad_memblk *blk);

/// Changes the size of a memory block previous obtained from monad_cma_alloc,
/// growing an existing allocation if possible; if `blk->ptr == nullptr`, this
/// behaves like monad_cma_alloc; if this fails, the existing block is unchanged
static int monad_cma_realloc(
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk);

/// Combines the semantics of calloc and realloc, similar to the OpenBSD
/// libc function reallocarray(3)
static int monad_cma_reallocarray(
    struct monad_allocator *ma, size_t count, size_t size, size_t align,
    struct monad_memblk *blk);

/// Deallocate a block of memory previously allocated by the given allocator
static void
monad_cma_dealloc(struct monad_allocator *ma, struct monad_memblk blk);

/// Query if the given memory block was allocated by the given allocator; the
/// allocator may not support ownership queries, in which case
/// MONAD_CMA_OWNS_NOT_SUPPORTED will be returned
static monad_cma_owns_result_t
monad_cma_owns(struct monad_allocator *ma, struct monad_memblk blk);

/*
 * Inline definitions
 */

[[gnu::always_inline]] inline int monad_cma_alloc(
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    return ma->vtable->alloc(ma, size, align, blk);
}

[[gnu::always_inline]] inline int monad_cma_calloc(
    struct monad_allocator *ma, size_t count, size_t size, size_t align,
    struct monad_memblk *blk)
{
    int rc;
    if (SIZE_MAX / count < size) {
        return ENOMEM; // Product of `count * size` would overflow
    }
    rc = monad_cma_alloc(ma, count * size, align, blk);
    __builtin_memset(blk->ptr, 0, blk->size);
    return rc;
}

[[gnu::always_inline]] inline int monad_cma_realloc(
    struct monad_allocator *ma, size_t size, size_t align,
    struct monad_memblk *blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    return ma->vtable->realloc(ma, size, align, blk);
}

[[gnu::always_inline]] inline int monad_cma_reallocarray(
    struct monad_allocator *ma, size_t count, size_t size, size_t align,
    struct monad_memblk *blk)
{
    if (SIZE_MAX / count < size) {
        return ENOMEM; // Product of `count * size` would overflow
    }
    return monad_cma_realloc(ma, count * size, align, blk);
}

[[gnu::always_inline]] inline void
monad_cma_dealloc(struct monad_allocator *ma, struct monad_memblk blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    ma->vtable->dealloc(ma, blk);
}

[[gnu::always_inline]] inline monad_cma_owns_result_t
monad_cma_owns(struct monad_allocator *ma, struct monad_memblk blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    if (ma->vtable->owns == nullptr) {
        return MONAD_CMA_OWNS_NOT_SUPPORTED;
    }
    return ma->vtable->owns(ma, blk) ? MONAD_CMA_OWNS_TRUE
                                     : MONAD_CMA_OWNS_FALSE;
}

#ifdef __cplusplus
} // extern "C"
#endif
