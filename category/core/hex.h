#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/likely.h>
#include <category/core/strview.h>

#ifdef __cplusplus
extern "C"
{
#endif

constexpr char MONAD_HEX_LOWER_DIGITS[] = "0123456789abcdef";
constexpr char MONAD_HEX_UPPER_DIGITS[] = "0123456789ABCDEF";

// A lookup table for fast parsing of hex strings; for the ASCII hex
// character `c`, the value of MONAD_NIBBLE_TABLE[c] is the binary value of the
// corresponding nibble, plus one. For example, MONAD_NIBBLE_TABLE['A'] is
// 0xB. One is added to detect invalid hex digits, which have value 0x0
constexpr uint8_t MONAD_NIBBLE_TABLE[255] = {
    ['0'] = 0x1,  ['1'] = 0x2,  ['2'] = 0x3, ['3'] = 0x4, ['4'] = 0x5,
    ['5'] = 0x6,  ['6'] = 0x7,  ['7'] = 0x8, ['8'] = 0x9, ['9'] = 0xA,
    ['a'] = 0xB,  ['b'] = 0xC,  ['c'] = 0xD, ['d'] = 0xE, ['e'] = 0xF,
    ['f'] = 0x10, ['A'] = 0xB,  ['B'] = 0xC, ['C'] = 0xD, ['D'] = 0xE,
    ['E'] = 0xF,  ['F'] = 0x10,
};

// clang-format off

enum monad_format_hex_flag : uint8_t
{
    MONAD_HEX_DEFAULT = 0b000, // Default: lowercase, no 0x, no ending '\0'
    MONAD_HEX_0X      = 0b001, // Prefix string with "0x"
    MONAD_HEX_UPPER   = 0b010, // Use uppercase hex digits
    MONAD_HEX_NULL    = 0b100, // Append a trailing '\0'
    MONAD_HEX_MASK    = 0b111, // Mask of all valid flags
};

// clang-format on

static int monad_format_hex(
    void const *data, size_t datalen, char *buf, size_t buflen, unsigned flags);

static int
monad_parse_hex(char const *str, size_t strlen, void *buf, size_t *buflen);

/*
 * Inline implementations
 *
 * These are inline because we usually parse short hex strings (representing
 * addresses of uint256 values) and the size will be known during optimization,
 * causing the formatting / parsing loops to be unrolled, and typically also
 * vectorized
 */

inline int monad_format_hex(
    void const *const data, size_t const datalen, char *buf,
    size_t const buflen, unsigned const flags)
{
    size_t required_len = datalen * 2;
    bool const prefix_0x = flags & MONAD_HEX_0X;
    bool const null_terminate = flags & MONAD_HEX_NULL;
    uint8_t const *const bytes = (uint8_t const *)data;
    char const *const digit_table = (flags & MONAD_HEX_UPPER)
                                        ? MONAD_HEX_UPPER_DIGITS
                                        : MONAD_HEX_LOWER_DIGITS;

    required_len += prefix_0x ? 2 : 0;
    required_len += null_terminate ? 1 : 0;
    if (MONAD_UNLIKELY(buflen < required_len)) {
        return ERANGE;
    }
    if (MONAD_UNLIKELY(flags & ~(unsigned)MONAD_HEX_MASK)) {
        return EINVAL;
    }

    if (prefix_0x) {
        buf[0] = '0';
        buf[1] = 'x';
        buf += 2;
    }
    for (size_t i = 0; i < datalen; ++i) {
        buf[2 * i] = digit_table[bytes[i] >> 4];
        buf[2 * i + 1] = digit_table[bytes[i] & 0xF];
    }
    if (null_terminate) {
        buf[2 * datalen] = '\0';
    }

    return 0;
}

inline int
monad_parse_hex(char const *str, size_t strlen, void *buf, size_t *buflen)
{
    size_t byte_count = strlen / 2;
    char const *start = str;

    if (strlen >= 2 && start[0] == '0' && start[1] == 'x' | start[1] == 'X') {
        start += 2;
        strlen -= 2;
        byte_count -= 1;
    }
    if (strlen & 0b1) {
        return EINVAL;
    }
    if (*buflen < byte_count) {
        return ERANGE;
    }

    for (size_t i = 0; i < byte_count; ++i) {
        uint8_t const hi = MONAD_NIBBLE_TABLE[start[2 * i]];
        uint8_t const lo = MONAD_NIBBLE_TABLE[start[2 * i + 1]];
        // XXX: check if the optimizer is smart enough to hoist this for 32
        // byte values of buflen
        if (MONAD_UNLIKELY(hi == 0 | lo == 0)) {
            return EINVAL;
        }
        ((uint8_t *)buf)[i] = (hi - 1) << 4 | (lo - 1);
    }

    *buflen = byte_count;
    return 0;
}

[[gnu::always_inline]] static inline int
monad_parse_hex_sv(struct monad_sv sv, void *buf, size_t *buflen)
{
    return monad_parse_hex(sv.begin, monad_sv_len(sv), buf, buflen);
}

#ifdef __cplusplus
} // extern "C"
#endif
