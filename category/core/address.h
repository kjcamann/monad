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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/// Vocabulary type for C APIs that work with Ethereum account addresses; an
/// Ethereum account address is the last 20 bytes of the keccak hash of the
/// account's public key
typedef struct monad_address
{
    uint8_t bytes[20];
} monad_address;

constexpr monad_address MONAD_ADDRESS_ZERO = {};

/// Write the hexidecimal string representation of the address to the provided
/// buffer, without a leading `0x` and without a null-terminator; returns the
/// errno(3)-domain code E2BIG if the buffer is not large enough to hold the
/// all the characters, otherwise returns 0
int monad_address_to_hex(
    monad_address const *, char *buf, size_t buflen);

/// Similar to `monad_address_to_hex` but no buffer size check is performed
static void
monad_address_to_hex_unchecked(monad_address const *, char *buf);

/// Similar to `monad_address_to_hex` but uses a thread_local static buffer
/// and the string is always null-terminated
char const *monad_address_to_hex_static(monad_address const *);

[[gnu::always_inline]] static inline int monad_address_cmp(
    monad_address const *lhs, monad_address const *rhs)
{
    return __builtin_memcmp(lhs, rhs, sizeof *lhs);
}

[[gnu::always_inline]] static inline bool monad_address_eq(
    monad_address const *lhs, monad_address const *rhs)
{
    return monad_address_cmp(lhs, rhs) == 0;
}

[[gnu::always_inline]] inline static char monad_hex_digit(uint8_t nibble)
{
    if (nibble < 10) {
        return (char)('0' + nibble);
    }
    if (nibble < 16) {
        return (char)('a' + (nibble - 10));
    }
    __builtin_unreachable();
}

[[gnu::always_inline]] inline void
monad_address_to_hex_unchecked(monad_address const *addr, char *buf)
{
    for (uint8_t i = 0; i < sizeof(monad_address); ++i) {
        uint8_t const b = addr->bytes[i];
        buf[2 * i] = monad_hex_digit(b >> 4);
        buf[2 * i + 1] = monad_hex_digit(b & 0x0F);
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
