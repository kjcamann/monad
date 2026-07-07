#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint32_t mrv_err_t;

char const *mrv_strerror(mrv_err_t);

mrv_err_t mrv_strerror_r(mrv_err_t, char *buf, size_t *buflen);

#define mrv_unreachable() __builtin_unreachable()

#ifdef __cplusplus
} // extern "C"
#endif
