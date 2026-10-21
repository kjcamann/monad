// Copyright (C) 2025-26 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/likely.h>

#ifdef __cplusplus

    // In C++, hexadecimal string formatting and parsing are constexpr
    #define MONAD_HEX_COMPILE_TIME constexpr

extern "C"
{

#else // __cplusplus

    // In C, the best we can do is inline and hope the optimizer can perform
    // enough constant folding to achieve the same result as C++ constexpr
    #define MONAD_HEX_COMPILE_TIME static inline

#endif

constexpr char MONAD_HEX_LOWER_DIGITS[] = "0123456789abcdef";
constexpr char MONAD_HEX_UPPER_DIGITS[] = "0123456789ABCDEF";

#ifndef __cplusplus

// A lookup table for fast parsing of hex strings; for the ASCII hexadecimal
// character `c`, the value of MONAD_HEX_TO_NIBBLE_TABLE[c] is the binary value
// of the corresponding nibble, plus 1. Example: MONAD_HEX_TO_NIBBLE_TABLE['A']
// is 0xB. +1 bias is added to detect invalid hex digits, which have value 0x0
constexpr uint8_t MONAD_HEX_TO_NIBBLE_TABLE[256] = {
    ['0'] = 0x1,  ['1'] = 0x2,  ['2'] = 0x3, ['3'] = 0x4, ['4'] = 0x5,
    ['5'] = 0x6,  ['6'] = 0x7,  ['7'] = 0x8, ['8'] = 0x9, ['9'] = 0xA,
    ['A'] = 0xB,  ['B'] = 0xC,  ['C'] = 0xD, ['D'] = 0xE, ['E'] = 0xF,
    ['F'] = 0x10, ['a'] = 0xB,  ['b'] = 0xC, ['c'] = 0xD, ['d'] = 0xE,
    ['e'] = 0xF,  ['f'] = 0x10,
};

#else

// clang-format off

// TODO(ken): this less-readable version of the table above is needed until C++
//   allows designated initializers with as much freedom as C does (see P3405)
constexpr uint8_t MONAD_HEX_TO_NIBBLE_TABLE[256] = {
    //         _0   _1   _2   _3   _4   _5   _6   _7   _8   _9   _A   _B   _C   _D   _E   _F
    /* 0x0_ */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* 0x1_ */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* 0x2_ */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* 0x3_ */ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0,   0,   0,   0,   0,   0,   // '0'-'9'
    /* 0x4_ */ 0,   0xB, 0xC, 0xD, 0xE, 0xF, 0x10,0,   0,   0,   0,   0,   0,   0,   0,   0,   // 'A'-'F'
    /* 0x5_ */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* 0x6_ */ 0,   0xB, 0xC, 0xD, 0xE, 0xF, 0x10,                                             // 'a'-'f'
    // 0x67-0xFF are implicitly 0
};

// clang-format on

#endif

// clang-format off

/// Format option bit flags used with the `monad_format_hex` function
enum monad_format_hex_flag : uint8_t
{
    MONAD_HEX_DEFAULT = 0b000, // Default: lowercase, no 0x, no ending '\0'
    MONAD_HEX_0X      = 0b001, // Prefix string with "0x"
    MONAD_HEX_UPPER   = 0b010, // Use uppercase hex digits
    MONAD_HEX_NULL    = 0b100, // Append a trailing '\0'
    MONAD_HEX_MASK    = 0b111, // Mask of all valid flags
};

// clang-format on

/// Format a hexadecimal string representation of the `datalen` bytes pointed
/// to by `data` into `buf` (with capacity `buflen`); format options are
/// specified via `flags`, which holds bit values from `monad_format_hex_flag`;
/// returns 0 on success, ERANGE if `buflen` is too small, EINVAL for bad flags
MONAD_HEX_COMPILE_TIME int monad_format_hex(
    void const *data, size_t datalen, char *buf, size_t buflen, unsigned flags);

/// Parse the hexadecimal string `str` into the byte buffer `buf`; a 0x or 0X
/// prefix will be ignored; initially `buflen` specifies the length available in
/// `buf`, and after a successful call it contains the parsed length; returns 0
/// on success, ERANGE if `*buflen` is too small, and EINVAL if the string input
/// is bad (is an odd number of characters or contains non-hex-digit characters)
MONAD_HEX_COMPILE_TIME int
monad_parse_hex(char const *str, size_t strlen, void *buf, size_t *buflen);

/*
 * Inline implementations
 */

MONAD_HEX_COMPILE_TIME int monad_format_hex(
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

MONAD_HEX_COMPILE_TIME int monad_parse_hex(
    char const *const str, size_t strlen, void *const buf, size_t *const buflen)
{
    size_t byte_count = strlen / 2;
    char const *start = str;

    if (strlen >= 2 && start[0] == '0' &&
        (start[1] == 'x') | (start[1] == 'X')) {
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
        uint8_t const hi = MONAD_HEX_TO_NIBBLE_TABLE[(uint8_t)start[2 * i]];
        uint8_t const lo = MONAD_HEX_TO_NIBBLE_TABLE[(uint8_t)start[2 * i + 1]];
        if (MONAD_UNLIKELY((hi == 0) | (lo == 0))) {
            return EINVAL;
        }
        ((uint8_t *)buf)[i] = (uint8_t)((hi - 1) << 4 | (lo - 1));
    }

    *buflen = byte_count;
    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
