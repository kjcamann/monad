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

#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int memfd_create(char const *name, unsigned int flags)
{
    char pathbuf[1024];
    char *p;
    int fd;
    int oflags;
    size_t namelen;

    if ((flags & ~MFD_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }
    oflags = flags & MFD_CLOEXEC ? O_CLOEXEC : 0;
    namelen = strlen(name);
    if (namelen + 16 > sizeof pathbuf) {
        errno = ENAMETOOLONG;
        return -1;
    }
    p = stpcpy(pathbuf, "/tmp/");
    for (size_t i = 0; i < namelen; ++i) {
        *p++ = name[i] == '/' ? '_' : name[i];
    }
    *stpcpy(p, ".XXXXXX") = '\0';
    fd = mkostemp(pathbuf, oflags);
    if (fd == -1) {
        return -1;
    }
    if (unlink(pathbuf) == -1) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}
