#pragma once

#include <category/core/mem/cma/cma_alloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_cma_fallback
{
    struct monad_allocator self;
    struct monad_allocator *primary;
    struct monad_allocator *secondary;
};

int monad_cma_fallback_init(
    struct monad_cma_fallback *fallback, struct monad_allocator *primary,
    struct monad_allocator *secondary, struct monad_allocator **ma);

#ifdef __cplusplus
} // extern "C"
#endif
