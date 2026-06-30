#pragma once

#include <endian.h>
#include <errno.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/endian.h>
#include <category/core/likely.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_bytes32
{
    uint8_t bytes[32];
};

constexpr struct monad_bytes32 MONAD_BYTES32_ZERO = {};

// clang-format off

constexpr struct monad_bytes32 MONAD_BYTES32_EMPTY_KECCAK = {
  0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
  0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
  0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
  0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
};

// clang-format on

typedef struct monad_bytes32 monad_uint256_be;

[[gnu::always_inline]] static inline int monad_bytes32_cmp(
    struct monad_bytes32 const *lhs, struct monad_bytes32 const *rhs)
{
    return __builtin_memcmp(lhs, rhs, sizeof *lhs);
}

[[gnu::always_inline]] static inline bool monad_bytes32_eq(
    struct monad_bytes32 const *lhs, struct monad_bytes32 const *rhs)
{
    return monad_bytes32_cmp(lhs, rhs) == 0;
}

[[gnu::always_inline]] static inline struct monad_bytes32
monad_bytes32_bswap(struct monad_bytes32 in)
{
    struct monad_bytes32 out;
    __uint128_t lo;
    __uint128_t hi;

    __builtin_memcpy(&hi, in.bytes, sizeof hi);
    __builtin_memcpy(&lo, in.bytes + 16, sizeof lo);
    hi = bswap_128(hi);
    lo = bswap_128(lo);
    __builtin_memcpy(out.bytes, &lo, sizeof lo);
    __builtin_memcpy(out.bytes + 16, &hi, sizeof hi);
    return out;
}

static inline int monad_uint256_be_from_he(
    monad_uint256_be *u256_be, size_t uint_bytes, void const *h)
{
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    __uint128_t u128;

    if (uint_bytes > 32) {
        return EINVAL;
    }
    __attribute__((assume(uint_bytes <= 32)));
    if (u256_be == h) {
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
        *(struct monad_bytes32 *)h = monad_bytes32_bswap(*u256_be);
#endif
        return 0;
    }

    // XXX: because we copy extra bytes below, need to make sure that for
    // non-power-of-2 sizes, we check for leading zeros

    switch (uint_bytes) {
    case 1:
        __builtin_memcpy(&u256_be->bytes[31], h, 1);
        return 0;

    case 2:
        u16 = htobe16(*(uint16_t const *)h);
        __builtin_memcpy(&u256_be->bytes[30], &u16, sizeof u16);
        return 0;

    case 3 ... 4:
        u32 = htobe32(*(uint32_t const *)h);
        __builtin_memcpy(&u256_be->bytes[28], &u32, sizeof u32);
        return 0;

    case 5 ... 8:
        u64 = htobe64(*(uint64_t const *)h);
        __builtin_memcpy(&u256_be->bytes[24], &u64, sizeof u64);
        return 0;

    case 9 ... 16:
        u128 = htobe128(*(__uint128_t const *)h);
        __builtin_memcpy(&u256_be->bytes[16], &u128, sizeof u128);
        return 0;

    case 17 ... 32:
        u128 = htobe128(*(__uint128_t const *)h);
        __builtin_memcpy(&u256_be->bytes[16], &u128, sizeof u128);
        u128 = htobe128(*((__uint128_t const *)h + 1));
        __builtin_memcpy(&u256_be->bytes[0], &u128, sizeof u128);
        return 0;

    default:
        __builtin_unreachable();
    }
}

static inline int monad_uint256_be_to_he(
    monad_uint256_be const *u256_be, size_t uint_bytes, void *h)
{
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    __uint128_t u128;

    if (uint_bytes > 32) {
        return EINVAL;
    }
    __attribute__((assume(uint_bytes <= 32)));
    if (u256_be == h) {
        __uint128_t hi;
        __uint128_t lo;

        __builtin_memcpy(&hi, u256_be->bytes, sizeof hi);
        __builtin_memcpy(&lo, u256_be->bytes + 16, sizeof lo);
        hi = be128toh(hi);
        lo = be128toh(lo);
        __builtin_memcpy(h, &lo, sizeof lo);
        __builtin_memcpy((uint8_t *)h + 16, &hi, sizeof hi);
        return 0;
    }

    if (MONAD_UNLIKELY(
            __builtin_memcmp(
                u256_be, &MONAD_BYTES32_ZERO, sizeof *u256_be - uint_bytes) !=
            0)) {
        return EOVERFLOW;
    }

    // `h` is assumed to be suitably aligned and the memory space allocated
    // for `*h` is also power-of-two sized; no alignment for `u256_be` is
    // assumed
    switch (uint_bytes) {
    case 1:
        *(uint8_t *)h = u256_be->bytes[31];
        return 0;

    case 2:
        __builtin_memcpy(&u16, &u256_be->bytes[30], sizeof u16);
        *(uint16_t *)h = be16toh(u16);
        return 0;

    case 3 ... 4:
        __builtin_memcpy(&u32, &u256_be->bytes[28], sizeof u32);
        *(uint32_t *)h = be32toh(u32);
        return 0;

    case 5 ... 8:
        __builtin_memcpy(&u64, &u256_be->bytes[24], sizeof u64);
        *(uint64_t *)h = be64toh(u64);
        return 0;

    case 9 ... 16:
        __builtin_memcpy(&u128, &u256_be->bytes[16], sizeof u128);
        *(__uint128_t *)h = be128toh(u128);
        return 0;

    case 17 ... 32:
        __builtin_memcpy(&u128, &u256_be->bytes[16], sizeof u128);
        ((__uint128_t *)h)[0] = be128toh(u128);
        __builtin_memcpy(&u128, &u256_be->bytes[0], sizeof u128);
        ((__uint128_t *)h)[1] = be128toh(u128);
        return 0;

    default:
        __builtin_unreachable();
    }
}

[[gnu::always_inline]] static inline uint32_t
monad_uint256_be_to_u32_unchecked(monad_uint256_be const *u256_be)
{
    uint32_t u32;
    __builtin_memcpy(
        &u32, (uint8_t const *)(u256_be + 1) - sizeof u32, sizeof u32);
    return be32toh(u32);
}

[[gnu::always_inline]] static inline uint64_t
monad_uint256_be_to_u64_unchecked(monad_uint256_be const *u256_be)
{
    uint64_t u64;
    __builtin_memcpy(
        &u64, (uint8_t const *)(u256_be + 1) - sizeof u64, sizeof u64);
    return be64toh(u64);
}

[[gnu::always_inline]] static inline int
monad_uint256_be_to_u32(monad_uint256_be const *u256_be, uint32_t *u32)
{
    if (MONAD_UNLIKELY(
            __builtin_memcmp(u256_be->bytes, MONAD_BYTES32_ZERO.bytes, 30) !=
            0)) {
        return EOVERFLOW;
    }
    *u32 = monad_uint256_be_to_u32_unchecked(u256_be);
    return 0;
}

[[gnu::always_inline]] static inline int
monad_uint256_be_to_u64(monad_uint256_be const *u256_be, uint64_t *u64)
{
    if (MONAD_UNLIKELY(
            __builtin_memcmp(u256_be->bytes, MONAD_BYTES32_ZERO.bytes, 24) !=
            0)) {
        return EOVERFLOW;
    }
    *u64 = monad_uint256_be_to_u64_unchecked(u256_be);
    return 0;
}

[[gnu::always_inline]] static inline monad_uint256_be *
monad_uint256_be_from_u64(monad_uint256_be *u256_be, uint64_t u64)
{
    size_t const u64_offset = (size_t)(sizeof *u256_be - sizeof u64);

    u64 = htobe64(u64);
    __builtin_memset(u256_be->bytes, 0, u64_offset);
    __builtin_memcpy(u256_be->bytes + u64_offset, &u64, sizeof u64);
    return u256_be;
}

#ifdef __cplusplus
} // extern "C"
#endif
