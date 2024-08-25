#pragma once

/**
 * @file
 *
 * Provides a C version of the C++11 std::align
 */

#include <stddef.h>

#include <monad/core/assert.h>
#include <monad/core/likely.h>

static inline uintptr_t
monad_align(size_t align, size_t size, uintptr_t addr, size_t *space)
{
    uintptr_t const aligned_addr = (addr + (align - 1)) & ~(align - 1);
    size_t const used = aligned_addr - addr + size;
    MONAD_DEBUG_ASSERT(space != nullptr);
    if (MONAD_UNLIKELY(used > *space)) {
        return (uintptr_t)(void *)nullptr;
    }
    *space -= used;
    return aligned_addr;
}

static inline size_t monad_round_size_to_align(size_t size, size_t align)
{
    return (size + (align - 1)) & ~(align - 1);
}
