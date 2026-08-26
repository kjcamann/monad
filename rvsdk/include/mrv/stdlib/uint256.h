#pragma once

#include <endian.h>
#include <stdint.h>

#include <category/core/assert.h>
#include <category/core/bytes32.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct mrv_uint256
{
    uint64_t limbs[4];
} mrv_uint256_t;

constexpr mrv_uint256_t MRV_UINT256_ZERO = {};

constexpr mrv_uint256_t MRV_UINT256_MAX = {
    UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};

mrv_uint256_t *mrv_uint256_add(mrv_uint256_t *lhs, mrv_uint256_t const *rhs);

mrv_uint256_t *mrv_uint256_sub(mrv_uint256_t *lhs, mrv_uint256_t const *rhs);

mrv_uint256_t *mrv_uint256_div(mrv_uint256_t *lhs, mrv_uint256_t const *rhs);

mrv_uint256_t *mrv_uint256_exp(mrv_uint256_t *base, mrv_uint256_t const *exp);

bool mrv_uint256_lt(mrv_uint256_t const *lhs, mrv_uint256_t const *rhs);

bool mrv_uint256_trunc_u64(mrv_uint256_t const *, uint64_t *);

[[gnu::always_inline]] static inline mrv_uint256_t *mrv_uint256_from_u64(
    mrv_uint256_t *const i, uint64_t u)
{
    i->limbs[0] = u;
    i->limbs[1] = i->limbs[2] = i->limbs[3] = 0;
    return i;
}

[[gnu::always_inline]] static inline mrv_uint256_t *mrv_uint256_from_evm_word(
    mrv_uint256_t *const i, struct monad_bytes32 const *const b)
{
    MONAD_ASSERT(
        (void *)i != (void const *)b, "inplace conversion not allowed");
    uint64_t const *const eth_word_limbs = (uint64_t const *)b->bytes;
    i->limbs[3] = be64toh(eth_word_limbs[0]);
    i->limbs[2] = be64toh(eth_word_limbs[1]);
    i->limbs[1] = be64toh(eth_word_limbs[2]);
    i->limbs[0] = be64toh(eth_word_limbs[3]);
    return i;
}

[[gnu::always_inline]] static inline struct monad_bytes32 *
mrv_uint256_to_evm_word(
    mrv_uint256_t const *const i, struct monad_bytes32 *const b)
{
    MONAD_ASSERT(
        (void *)i != (void const *)b, "inplace conversion not allowed");
    uint64_t *const eth_word_limbs = (uint64_t *)b->bytes;
    eth_word_limbs[3] = htobe64(i->limbs[0]);
    eth_word_limbs[2] = htobe64(i->limbs[1]);
    eth_word_limbs[1] = htobe64(i->limbs[2]);
    eth_word_limbs[0] = htobe64(i->limbs[3]);
    return b;
}

#ifdef __cplusplus
} // extern "C"
#endif
