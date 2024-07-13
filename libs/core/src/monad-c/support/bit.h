#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @file
 *
 * This file provides useful bit/byte/endian utilities, including the missing
 * pieces of the C23 <stdbit.h> header and the glibc <endian.h> header for the
 * platforms which do not have them.
 */

#if defined(__GNUC__)
#define MONAD_BSWAP64(X) __builtin_bswap64(X)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be64toh(X) MONAD_BSWAP64((X))
#else
#define be64toh(X) (X)
#endif

// XXX: need to only define these only if we don't have stdbit.h
static inline int stdc_trailing_zeros_ul(unsigned long x) {
    return __builtin_ctz(x);
}

static inline bool stdc_has_single_bit_ui(unsigned int x) {
    return (x ^ (x - 1)) > x - 1;
}

/// Copy a big-endian unsigned integer into a buffer of equal or larger size.
///
/// The semantics are
///
///   - If the buffer is too small to hold the integer, no copying occurs and
///     nullptr is returned
///
///   - If the buffer is large enough to hold the integer, it is copied into
///     the appropriate location so that it would yield the same value if the
///     buffer were interpreted as a big-endian unsigned integer. For example,
///     if the two byte value 0x2030 (8240) is copied into a 4 byte buffer, the
///     result would be 0x00002030. Any leading bytes are set to zero and the
///     address of the destination buffer is returned
static inline void *mcl_copy_uint_be(void *dst, size_t dst_size,
                                     const uint8_t *src_uint_be,
                                     size_t src_uint_be_size) {
    const ptrdiff_t leading_zero_byte_count =
        (ptrdiff_t)dst_size - (ptrdiff_t)src_uint_be_size;
    if (leading_zero_byte_count < 0)
        return nullptr;
    memset(dst, 0, leading_zero_byte_count);
    memcpy((uint8_t *)dst + leading_zero_byte_count, src_uint_be,
           src_uint_be_size);
    return dst;
}

#endif