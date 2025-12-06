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

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file
 *
 * This file contains thread routines which are not standardized in pthread(3)
 */

#include <errno.h>
#include <stdint.h>

#include <category/core/likely.h>

typedef long monad_tid_t;
extern thread_local monad_tid_t monad_tl_tid;

extern void monad_tl_tid_init();

/// Get the system ID of the calling thread
[[gnu::always_inline]] static inline monad_tid_t monad_thread_get_id()
{
    if (MONAD_UNLIKELY(monad_tl_tid == 0)) {
        monad_tl_tid_init();
    }
    return monad_tl_tid;
}

#ifdef __cplusplus
}
#endif
