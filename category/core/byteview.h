#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_bv
{
    uint8_t const *begin;
    uint8_t const *end;
};

constexpr struct monad_bv MONAD_BV_EMPTY = {};

constexpr size_t MONAD_BV_ALL = (size_t)-1UL;

[[gnu::always_inline]] static inline struct monad_bv
monad_bv_from_size(void const *p, size_t s)
{
    return (struct monad_bv){(uint8_t const *)p, (uint8_t const *)p + s};
}

[[gnu::always_inline]] static inline struct monad_bv
monad_bv_from_pair(void const *b, void const *e)
{
    return (struct monad_bv){(uint8_t const *)b, (uint8_t const *)e};
}

[[gnu::always_inline]] static inline size_t monad_bv_len(struct monad_bv bv)
{
    return (size_t)(bv.end - bv.begin);
}

[[gnu::always_inline]] static inline bool monad_bv_empty(struct monad_bv bv)
{
    return bv.begin == bv.end;
}

[[gnu::always_inline]] static inline struct monad_bv
monad_bv_sub(struct monad_bv bv, size_t offset, size_t count)
{
    // Do we need/want bounds checking?
    uint8_t const *const new_begin = bv.begin + offset;
    return count == MONAD_BV_ALL
               ? (struct monad_bv){new_begin, bv.end}
               : (struct monad_bv){new_begin, new_begin + count};
}

#ifdef __cplusplus
} // extern "C"
#endif
