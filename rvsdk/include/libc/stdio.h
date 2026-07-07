#pragma once

#include <stdarg.h>
#include <stddef.h>

#include "libc_syscalls.h"

inline int sprintf(char *__restrict, char const *__restrict, ...);

inline int snprintf(char *__restrict, size_t, char const *__restrict, ...);

inline int vsprintf(char *__restrict, char const *__restrict, va_list);

inline int vsnprintf(char *__restrict, size_t, char const *__restrict, va_list);

inline int sprintf(char *__restrict str, char const *__restrict format, ...)
{
    int rc;
    va_list ap;

    va_start(ap, format);
    rc = vsprintf(str, format, ap);
    va_end(ap);
    return rc;
}

inline int
snprintf(char *__restrict str, size_t size, char const *__restrict format, ...)
{
    int rc;
    va_list ap;

    va_start(ap, format);
    rc = vsnprintf(str, size, format, ap);
    va_end(ap);
    return rc;
}

inline int
vsprintf(char *__restrict str, char const *__restrict format, va_list ap)
{
    return (int)rv64_syscall3(
        (long)str, (long)format, (long)ap, MONAD_RV_CSYS_VSPRINTF);
}

inline int vsnprintf(
    char *__restrict str, size_t size, char const *__restrict format,
    va_list ap)
{
    return (int)rv64_syscall4(
        (long)str, (long)size, (long)format, (long)ap, MONAD_RV_CSYS_VSNPRINTF);
}
