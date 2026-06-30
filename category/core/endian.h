#pragma once

#if !__has_builtin(__builtin_bswap64)
    #include <byteswap.h>
#endif

#include <endian.h>
#include <stdint.h>

[[gnu::always_inline]] static inline __uint128_t bswap_128(__uint128_t b)
{
#if __has_builtin(__builtin_bswap128)
    return __builtin_bswap128(b);
#elif __has_builtin(__builtin_bswap64)
    uint64_t const lo = __builtin_bswap64((uint64_t)b);
    uint64_t const hi = __builtin_bswap64((uint64_t)(b >> 64));
    return ((__uint128_t)lo << 64) | hi;
#else
    uint64_t const lo = bswap_64((uint64_t)b);
    uint64_t const hi = bswap_64((uint64_t)(b >> 64));
    return ((__uint128_t)lo << 64) | hi;
#endif
}

[[gnu::always_inline]] static inline __uint128_t be128toh(__uint128_t b)
{
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
    return b;
#else
    return bswap_128(b);
#endif
}

[[gnu::always_inline]] static inline __uint128_t htobe128(__uint128_t h)
{
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
    return h;
#else
    return bswap_128(h);
#endif
}
