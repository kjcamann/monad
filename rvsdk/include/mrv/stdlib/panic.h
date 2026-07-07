#pragma once

#include <stdarg.h>

#include <category/core/srcloc.h>

#include <mrv/stdlib/error.h>

#ifdef __cplusplus
extern "C"
{
#endif

[[noreturn]] void
mrv_vpanic(monad_source_location_t const *, mrv_err_t, char const *, va_list);

[[noreturn, gnu::always_inline]]
static inline void mrv_vpanicx(
    monad_source_location_t const *const srcloc, char const *const format,
    va_list ap)
{
    mrv_vpanic(srcloc, 0, format, ap);
}

__attribute__((format(printf, 3, 4))) [[noreturn, gnu::always_inline]]
static inline void mrv_panic(
    monad_source_location_t const *const srcloc, mrv_err_t const err,
    char const *const format, ...)
{
    va_list ap;
    va_start(ap, format);
    mrv_vpanic(srcloc, err, format, ap);
}

__attribute__((format(printf, 2, 3))) [[noreturn, gnu::always_inline]]
static inline void mrv_panicx(
    monad_source_location_t const *const srcloc, char const *const format, ...)
{
    va_list ap;
    va_start(ap, format);
    mrv_vpanicx(srcloc, format, ap);
}

#define MRV_PANIC(...) mrv_panic(&MONAD_SOURCE_LOCATION_CURRENT(), __VA_ARGS__)
#define MRV_PANICX(...)                                                        \
    mrv_panicx(&MONAD_SOURCE_LOCATION_CURRENT(), __VA_ARGS__)

#ifdef __cplusplus
} // extern "C"
#endif
