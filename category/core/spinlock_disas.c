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

#include <category/core/spinlock.h>

void monad_spinlock_init_disas(monad_spinlock_t *const lock)
{
    monad_spinlock_init(lock);
}

bool monad_spinlock_try_lock_disas(monad_spinlock_t *const lock)
{
    return monad_spinlock_try_lock(lock);
}

void monad_spinlock_lock_disas(monad_spinlock_t *const lock)
{
    monad_spinlock_lock(lock);
}

void monad_spinlock_unlock_disas(monad_spinlock_t *const lock)
{
    monad_spinlock_unlock(lock);
}
