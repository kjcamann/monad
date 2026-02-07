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

#include_next <sys/mman.h>

#ifdef __APPLE__

    #define MFD_CLOEXEC 0x1U
    #define MFD_HUGETLB 0x4U

int memfd_create(char const *, unsigned int);
void *mremap(void *old_address, size_t old_size, size_t new_size, int flags);

    #define MREMAP_MAYMOVE 1
#endif
