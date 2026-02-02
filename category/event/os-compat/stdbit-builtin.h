// Copyright (C) 2025 Category Labs, Inc.
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

/**
 * @file
 *
 * Only recent glibc has <stdbit.h>, for now provide the pieces that
 * are missing directly using the builtins in gcc/clang
 */

#if __has_builtin(__builtin_stdc_has_single_bit)
    #define stdc_has_single_bit(x) (__builtin_stdc_has_single_bit(x))
#elif __has_builtin(__builtin_popcountll)
[[gnu::always_inline]] inline bool stdc_has_single_bit(unsigned long long ull)
{
    return __builtin_popcountll(ull) == 1;
}
#else
    #error define stdc_has_single_bit
#endif

#if __has_builtin(__builtin_stdc_trailing_zeros)
    #define stdc_trailing_zeros(x) (__builtin_stdc_trailing_zeros(x))
#elif __has_builtin(__builtin_ctzll)
[[gnu::always_inline]] inline unsigned
stdc_trailing_zeros(unsigned long long ull)
{
    return (unsigned)__builtin_ctzll(ull);
}
#else
    #error define stdc_trailing_zeros
#endif

#if __has_builtin(__builtin_stdc_bit_width)
    #define stdc_bit_width(x) (__builtin_stdc_bit_width(x))
#elif __has_builtin(__builtin_clzll)
[[gnu::always_inline]] inline unsigned stdc_bit_width(unsigned long long ull)
{
    return 64 - (unsigned)__builtin_clzll(ull);
}
#else
    #error define stdc_bit_width
#endif

#if __has_builtin(__builtin_stdc_bit_ceil)
    #define stdc_bit_ceil(x) (__builtin_stdc_bit_ceil(x))
#else
[[gnu::always_inline]] inline unsigned long long
stdc_bit_ceil(unsigned long long ull)
{
    return ull <= 1 ? 1 : (1ULL << (stdc_bit_width(ull - 1)));
}
#endif
