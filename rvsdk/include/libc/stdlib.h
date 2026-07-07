#pragma once

#include <stddef.h>

#include "libc_syscalls.h"

inline void *malloc(size_t);
inline void *calloc(size_t, size_t);
inline void *realloc(void *, size_t);
inline void free(void *);
inline void *aligned_alloc(size_t, size_t);

inline void *malloc(size_t size)
{
    return (void *)rv64_syscall1((long)size, MONAD_RV_CSYS_MALLOC);
}

inline void *calloc(size_t n, size_t size)
{
    return (void *)rv64_syscall2((long)n, (long)size, MONAD_RV_CSYS_CALLOC);
}

inline void *realloc(void *p, size_t size)
{
    return (void *)rv64_syscall2((long)p, (long)size, MONAD_RV_CSYS_REALLOC);
}

inline void free(void *p)
{
    (void)rv64_syscall1((long)p, MONAD_RV_CSYS_FREE);
}

inline void *aligned_alloc(size_t alignment, size_t size)
{
    return (void *)rv64_syscall2(
        (long)alignment, (long)size, MONAD_RV_CSYS_ALIGNED_ALLOC);
}
