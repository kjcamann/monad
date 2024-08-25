#pragma once

#include <monad/mem/cma/cma_alloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_cma_fallback_alloc
{
    monad_allocator_t self;
    monad_allocator_t *primary;
    monad_allocator_t *secondary;
};

int monad_cma_fallback_alloc_init(
    struct monad_cma_fallback_alloc *ma, monad_allocator_t *primary,
    monad_allocator_t *secondary);

#ifdef __cplusplus
} // extern "C"
#endif
