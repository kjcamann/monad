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

#include <string.h>

#include <category/core/assert.h>
#include <category/core/likely.h>
#include <category/core/spinloop.h>
#include <category/core/thread.h>

#if MONAD_SPINLOCK_TRACK_OWNER
    #include <category/core/srcloc.h>
#endif

typedef struct monad_spinlock monad_spinlock_t;

struct monad_spinlock
{
    monad_tid_t owner_tid; ///< System ID of thread that owns lock
#if MONAD_SPINLOCK_TRACK_OWNER
    monad_source_location_t srcloc; ///< Location in code where lock taken
#endif
};

[[gnu::always_inline]] static inline bool
monad_spinlock_is_self_owned(monad_spinlock_t *const lock)
{
    return __atomic_load_n(&lock->owner_tid, __ATOMIC_ACQUIRE) ==
           monad_thread_get_id();
}

[[gnu::always_inline]] static inline bool
monad_spinlock_is_unowned(monad_spinlock_t *const lock)
{
    return __atomic_load_n(&lock->owner_tid, __ATOMIC_ACQUIRE) == 0;
}

[[gnu::always_inline]] static inline void
monad_spinlock_init(monad_spinlock_t *const lock)
{
    lock->owner_tid = 0;
#if MONAD_SPINLOCK_TRACK_OWNER
    memset(&lock->srcloc, 0, sizeof lock->srcloc);
#endif
}

[[gnu::always_inline]] static inline bool
monad_spinlock_try_lock(monad_spinlock_t *const lock)
{
    monad_tid_t expected = 0;
    return __atomic_compare_exchange_n(
        &lock->owner_tid,
        &expected,
        monad_thread_get_id(),
        /*weak=*/false,
        __ATOMIC_ACQ_REL,
        __ATOMIC_RELAXED);
}

[[gnu::always_inline]] static inline void
monad_spinlock_lock(monad_spinlock_t *const lock)
{
    monad_tid_t const desired = monad_thread_get_id();
    monad_tid_t expected;
    bool owned;

    MONAD_DEBUG_ASSERT(!monad_spinlock_is_self_owned(lock));

TryAgain:
    expected = 0;
    owned = __atomic_compare_exchange_n(
        &lock->owner_tid,
        &expected,
        desired,
        /*weak=*/true,
        __ATOMIC_ACQ_REL,
        __ATOMIC_RELAXED);
    if (MONAD_UNLIKELY(!owned)) {
        monad_spinloop_hint();
        goto TryAgain;
    }
}

[[gnu::always_inline]] static inline void
monad_spinlock_unlock(monad_spinlock_t *const lock)
{
    MONAD_DEBUG_ASSERT(monad_spinlock_is_self_owned(lock));
    __atomic_store_n(&lock->owner_tid, 0, __ATOMIC_RELEASE);
}

#if MONAD_SPINLOCK_TRACK_OWNER

[[gnu::always_inline]] static inline bool monad_spinlock_try_lock_with_srcloc(
    monad_spinlock_t *const lock, monad_source_location_t srcloc)
{
    bool const have_lock = monad_spinlock_try_lock(lock);
    if (have_lock) {
        lock->srcloc = srcloc;
    }
    return have_lock;
}

[[gnu::always_inline]] static inline void monad_spinlock_lock_with_srcloc(
    monad_spinlock_t *const lock, monad_source_location_t srcloc)
{
    monad_spinlock_lock(lock);
    lock->srcloc = srcloc;
}

    #define MONAD_SPINLOCK_TRY_LOCK(LCK)                                       \
        monad_spinlock_try_lock_with_srcloc(                                   \
            (LCK), MONAD_SOURCE_LOCATION_CURRENT())

    #define MONAD_SPINLOCK_LOCK(LCK)                                           \
        monad_spinlock_lock_with_srcloc((LCK), MONAD_SOURCE_LOCATION_CURRENT())

#else

    #define MONAD_SPINLOCK_TRY_LOCK(LCK) monad_spinlock_try_lock((LCK))
    #define MONAD_SPINLOCK_LOCK(LCK) monad_spinlock_lock((LCK))

#endif // MONAD_SPINLOCK_TRACK_OWNER

#define MONAD_SPINLOCK_UNLOCK(LCK) monad_spinlock_unlock((LCK))
