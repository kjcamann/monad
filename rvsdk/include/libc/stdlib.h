#pragma once

#include <stddef.h>

#include <sys/syscall.h>

inline void *malloc(size_t);
inline void *calloc(size_t, size_t);
inline void *realloc(void *, size_t);
inline void free(void *);
inline void *aligned_alloc(size_t, size_t);

inline void *malloc(size_t size)
{
    return (void *)rv64_syscall1((long)size, RVI_ECALL_C_MALLOC);
}

inline void *calloc(size_t n, size_t size)
{
    return (void *)rv64_syscall2((long)n, (long)size, RVI_ECALL_C_CALLOC);
}

inline void *realloc(void *p, size_t size)
{
    return (void *)rv64_syscall2((long)p, (long)size, RVI_ECALL_C_REALLOC);
}

inline void free(void *p)
{
    (void)rv64_syscall1((long)p, RVI_ECALL_C_FREE);
}

inline void *aligned_alloc(size_t alignment, size_t size)
{
    return (void *)rv64_syscall2(
        (long)alignment, (long)size, RVI_ECALL_C_ALIGNED_ALLOC);
}
