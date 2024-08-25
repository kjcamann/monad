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
    uint8_t *begin;
    uint8_t *end;
    monad_memblk_t last;
};

/// Initialize a "bump pointer allocator", which allocates from a fixed-size
/// pre-allocated block by incrementing a pointer; called "stack allocator"
/// in Alexandrescu's design, since the block is usually on the stack
int monad_cma_bump_alloc_init(
    struct monad_cma_bump_alloc *ma, monad_memblk_t blk);

#ifdef __cplusplus
} // extern "C"
#endif
