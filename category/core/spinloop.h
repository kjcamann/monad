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
 * This file defines an architecture-dependent macro to accelerate the
 * performance of code containing spin loops. These are used in the spinlock
 * implementation, but should appear in any kind of tight atomic
 * synchronization loop.
 *
 * A surface-level explanation of what these intrinsics do can be found in
 * the description of the PAUSE instruction in the Intel Developers Manual,
 * Volume 2B. A more detailed explanation of why these are needed can be found
 * here:
 *
 *   https://stackoverflow.com/questions/12894078/what-is-the-purpose-of-the-pause-instruction-in-x86
 */

#ifdef __x86_64__
    #define monad_spinloop_hint() __builtin_ia32_pause()
#elif __aarch64__
    // See Linux arch/arm64/include/asm/processor.h
    #define monad_spinloop_hint() asm volatile("yield" ::: "memory")
#else
    #define monad_spinloop_hint()
    #warning this CPU type should define monad_spinloop_hint()
#endif
