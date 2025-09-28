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

#include <stddef.h>

#include <sys/types.h>

// A wrapper around around strlcpy that appends a '/' followed by the contents
// of src and adjusts the input buffer (both pointer and size) to reflect the
// append; the result is always null terminated but may be truncated, in which
// case ERANGE is returned
int monad_path_append(char **dst, char const *src, size_t *size);

// A helper function which starts at the open directory file descriptor
// `init_dirfd` and opens subdirectory paths along `path_suffix`, creating them
// if they don't exist if `mode & ACCESSPERMS` is not zero; each pach segment
// is appended to `namebuf` as it is translated, so that the last path
// component is the one associated with the error if one occurs; on success,
// final_dirfd holds an open descriptor to the final subdirectory
int monad_path_open_subdir(
    int init_dirfd, char const *path_suffix, mode_t mode, int *final_dirfd,
    char *namebuf, size_t namebuf_size);
