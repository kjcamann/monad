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

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct monad_memblk monad_memblk_t;
typedef struct monad_allocator monad_allocator_t;

#define MONAD_DEFAULT_ALIGN (alignof(max_align_t))

/// The result of allocating memory is both the allocated address and the
/// allocated size, which may be different than the size requested
struct monad_memblk
{
    void *ptr;
    size_t size;
};

enum monad_cma_owns_result
{
    MONAD_CMA_OWNS_FALSE,
    MONAD_CMA_OWNS_TRUE,
    MONAD_CMA_OWNS_NOT_SUPPORTED
};

typedef int(monad_cma_alloc_fn)(
    monad_allocator_t *, size_t, size_t, monad_memblk_t *);

typedef int(monad_cma_realloc_fn)(
    monad_allocator_t *, size_t, size_t, monad_memblk_t *);

typedef void(monad_cma_dealloc_fn)(monad_allocator_t *, monad_memblk_t);

typedef bool(monad_cma_owns_fn)(monad_allocator_t *, monad_memblk_t);

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

/// Returns the global, stateless null allocator
monad_allocator_t *monad_cme_get_null_allocator();

/// Returns the global, stateless malloc(3) allocator
monad_allocator_t *monad_cma_get_malloc_allocator();

/// Returns the process-wide default allocator
monad_allocator_t *monad_cma_get_default_allocator();

/// Sets the process-wide default allocator to the provided one, and returns
/// the previous default allocator
monad_allocator_t *monad_cma_set_default_allocator(monad_allocator_t *next);

/// Allocate a block of memory with the given size and alignment; if
/// successful the block info will be copied into `blk`; upon failure, this
/// returns an errno(3) domain error
static int monad_cma_alloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk);

/// Allocate an array of `count` items with the given size and alignment;
/// similar to the libc `calloc(3)` function
static int monad_cma_calloc(
    monad_allocator_t *ma, size_t count, size_t size, size_t align,
    monad_memblk_t *blk);

/// Changes the size of a memory block previous obtained from monad_cma_alloc,
/// growing an existing allocation if possible; if `blk->ptr == nullptr`, this
/// behaves like monad_cma_alloc; if this fails, the existing block is unchanged
static int monad_cma_realloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk);

/// Combines the semantics of calloc and realloc, similar to the OpenBSD
/// function of the same name
static int monad_cma_reallocarray(
    monad_allocator_t *ma, size_t count, size_t size, size_t align,
    monad_memblk_t *blk);

/// Deallocate a block of memory previously allocated by the given allocator
static void monad_cma_dealloc(monad_allocator_t *ma, monad_memblk_t blk);

/// Query if the given memory block was allocated by the given allocator; the
/// allocator may not support ownership queries, in which case
/// MONAD_CMA_OWNS_NOT_SUPPORTED will be returned
static enum monad_cma_owns_result
monad_cma_owns(struct monad_allocator *ma, monad_memblk_t blk);

/*
 * Inline definitions
 */

inline int monad_cma_alloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    return ma->vtable->alloc(ma, size, align, blk);
}

inline int monad_cma_calloc(
    monad_allocator_t *ma, size_t count, size_t size, size_t align,
    monad_memblk_t *blk)
{
    if (SIZE_MAX / count < size) {
        return ENOMEM; // Product of `count * size` would overflow
    }
    return monad_cma_alloc(ma, count * size, align, blk);
}

inline int monad_cma_realloc(
    monad_allocator_t *ma, size_t size, size_t align, monad_memblk_t *blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    return ma->vtable->realloc(ma, size, align, blk);
}

inline int monad_cma_reallocarray(
    monad_allocator_t *ma, size_t count, size_t size, size_t align,
    monad_memblk_t *blk)
{
    if (SIZE_MAX / count < size) {
        return ENOMEM; // Product of `count * size` would overflow
    }
    return monad_cma_realloc(ma, count * size, align, blk);
}

inline void monad_cma_dealloc(monad_allocator_t *ma, monad_memblk_t blk)
{
    if (ma == nullptr) {
        ma = monad_cma_get_default_allocator();
    }
    ma->vtable->dealloc(ma, blk);
}

inline enum monad_cma_owns_result
monad_cma_owns(monad_allocator_t *ma, monad_memblk_t blk)
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
