#pragma once

#include <stddef.h>
#include <stdint.h>

#include "libc_syscalls.h"

inline void *memcpy(void *__restrict, void const *__restrict, size_t);
inline void *memmove(void *, void const *, size_t);
inline void *memset(void *, int, size_t);
inline int memcmp(void const *, void const *, size_t);
inline void *memchr(void const *, int, size_t);

inline char *strcpy(char *__restrict, char const *__restrict);
inline char *strncpy(char *__restrict, char const *__restrict, size_t);

char *strcat(char *__restrict, char const *__restrict);
char *strncat(char *__restrict, char const *__restrict, size_t);

int strcmp(char const *, char const *);
int strncmp(char const *, char const *, size_t);

inline char *strchr(char const *, int);
inline char *strrchr(char const *, int);

inline size_t strlen(char const *);
inline char *strerror(int);

inline char *stpcpy(char *__restrict, char const *__restrict);
inline char *stpncpy(char *__restrict, char const *__restrict, size_t);

inline size_t strlcpy(char *, char const *, size_t);
inline void *mempcpy(void *__restrict, void const *__restrict, size_t);

/*
 * memcpy, memmove, memset, memcmp, memchr
 */

inline void *memcpy(void *__restrict dst, void const *__restrict src, size_t n)
{
    return (void *)rv64_syscall3(
        (long)dst, (long)src, (long)n, MONAD_RV_CSYS_MEMCPY);
}

inline void *memmove(void *dst, void const *src, size_t n)
{
    return (void *)rv64_syscall3(
        (long)dst, (long)src, (long)n, MONAD_RV_CSYS_MEMMOVE);
}

inline void *memset(void *dst, int c, size_t n)
{
    return (void *)rv64_syscall3(
        (long)dst, (long)c, (long)n, MONAD_RV_CSYS_MEMSET);
}

inline int memcmp(void const *s1, void const *s2, size_t n)
{
    return (int)rv64_syscall3(
        (long)s1, (long)s2, (long)n, MONAD_RV_CSYS_MEMCMP);
}

inline void *memchr(void const *s, int c, size_t n)
{
    return (void *)rv64_syscall3(
        (long)s, (long)c, (long)n, MONAD_RV_CSYS_MEMCHR);
}

/*
 * strcpy, strncpy
 */

inline char *strcpy(char *__restrict dst, char const *__restrict src)
{
    return (char *)rv64_syscall2((long)dst, (long)src, MONAD_RV_CSYS_STRCPY);
}

inline char *strncpy(char *__restrict dst, char const *__restrict src, size_t n)
{
    return (char *)rv64_syscall3(
        (long)dst, (long)src, (long)n, MONAD_RV_CSYS_STRNCPY);
}

/*
 * strchr, strrchr
 */

inline char *strchr(char const *s, int c)
{
    return (char *)rv64_syscall2((long)s, (long)c, MONAD_RV_CSYS_STRCHR);
}

inline char *strrchr(char const *s, int c)
{
    return (char *)rv64_syscall2((long)s, (long)c, MONAD_RV_CSYS_STRRCHR);
}

/*
 * strlen, strerror
 */

inline size_t strlen(char const *s)
{
    return (size_t)rv64_syscall1((long)s, MONAD_RV_CSYS_STRLEN);
}

inline char *strerror(int rc)
{
    return (char *)rv64_syscall1((long)rc, MONAD_RV_CSYS_STRERROR);
}

/*
 * stpcpy, stpncpy
 */

inline char *stpcpy(char *__restrict dst, char const *__restrict src)
{
    return (char *)rv64_syscall2((long)dst, (long)src, MONAD_RV_CSYS_STPCPY);
}

inline char *stpncpy(char *__restrict dst, char const *__restrict src, size_t n)
{
    return (char *)rv64_syscall3(
        (long)dst, (long)src, (long)n, MONAD_RV_CSYS_STPNCPY);
}

/*
 * strlcpy, mempcpy
 */

inline size_t strlcpy(char *dst, char const *src, size_t n)
{
    return (size_t)rv64_syscall3(
        (long)dst, (long)src, (long)n, MONAD_RV_CSYS_STRLCPY);
}

inline void *mempcpy(void *__restrict dst, void const *__restrict src, size_t n)
{
    return (uint8_t *)memcpy(dst, src, n) + n;
}
