#pragma once

#include <stdatomic.h>
#include <stdint.h>

#include <monad/mem/cma/cma_alloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_cma_bump_alloc
{
    monad_allocator_t self;
    atomic_uintptr_t next;
    uint8_t const *begin;
    uint8_t const *end;
};

/// Initialize a "bump pointer allocator", which allocates from a fixed-size
/// pre-allocated block by incrementing a pointer; called "stack allocator"
/// in Alexandrescu's design, since the block is usually on the stack
int monad_cma_bump_alloc_init(
    struct monad_cma_bump_alloc *bump_alloc, monad_memblk_t blk,
    monad_allocator_t **ma);

#ifdef __cplusplus
} // extern "C"
#endif
