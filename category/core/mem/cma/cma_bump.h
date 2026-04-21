#pragma once

#include <stdint.h>

#include <category/core/mem/cma/cma_alloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_cma_bump
{
    struct monad_allocator self;
    uintptr_t next;
    uint8_t const *begin;
    uint8_t const *end;
};

/// Initialize a "bump pointer allocator", which allocates from a fixed-size
/// pre-allocated block by incrementing a pointer; this is called "stack
/// allocator" in Alexandrescu's design, since the block is usually on the stack
int monad_cma_bump_init(
    struct monad_cma_bump *bump, struct monad_memblk blk,
    struct monad_allocator **ma);

#ifdef __cplusplus
} // extern "C"
#endif
