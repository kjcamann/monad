#pragma once

/**
 * @file
 *
 * Provides a C version of the C++11 std::align
 */

#include <stdbit.h>
#include <stddef.h>

#include <monad/core/assert.h>
#include <monad/core/bit_util.h>
#include <monad/core/likely.h>

[[gnu::always_inline]] static inline size_t
monad_round_size_to_align(size_t size, size_t align)
{
    // Round size up to the nearest multiple of align. bit_round_up does this,
    // provided that align has the form 2^b and is expressed as `b`. `b` (which
    // is `log_2 align`) is computed efficiently using stdc_trailing_zeros,
    // an intrinsic operation on many platforms (e.g., TZCNT).
    MONAD_DEBUG_ASSERT(stdc_has_single_bit(align));
    return bit_round_up(size, stdc_trailing_zeros(align));
}

static inline uintptr_t
monad_align(size_t align, size_t size, uintptr_t addr, size_t *space)
{
    uintptr_t const aligned_addr = monad_round_size_to_align(addr, align);
    size_t const used = aligned_addr - addr + size;
    MONAD_DEBUG_ASSERT(space != nullptr);
    if (MONAD_UNLIKELY(used > *space)) {
        return (uintptr_t)(void *)nullptr;
    }
    *space -= used;
    return aligned_addr;
}
