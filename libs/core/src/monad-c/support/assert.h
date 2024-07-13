#pragma once

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct monad_source_location {
    const char *function;
    const char *file;
    unsigned line;
};

[[noreturn]] extern void monad_abort(const struct monad_source_location *srcloc,
                                     const char *format, va_list ap);

[[noreturn]] extern void
monad_assert_failed(const struct monad_source_location *srcloc,
                    const char *expr, const char *format, va_list ap);

[[noreturn]] static inline void
monad_abort_trampoline(const char *function, const char *file, unsigned line,
                       const char *format, ...) {
    const struct monad_source_location srcloc = {
        .function = function,
        .file = file,
        .line = line
    };
    va_list ap;
    va_start(ap, format);
    monad_abort(&srcloc, format, ap);
    va_end(ap);
}

[[noreturn]] static inline void
monad_assert_failed_trampoline(const char *function, const char *file,
                               unsigned line, const char *expr,
                               const char *format, ...) {
    const struct monad_source_location srcloc = {
        .function = function,
        .file = file,
        .line = line
    };
    va_list ap;
    va_start(ap, format);
    monad_assert_failed(&srcloc, expr, format, ap);
    va_end(ap);
}

#define MONAD_ABORT(FMT, ...) \
    monad_abort_trampoline(__FUNCTION__, __FILE__, __LINE__, \
                           FMT __VA_OPT__(,) __VA_ARGS__)

#define MONAD_ASSERT_MSG(EXPR, FMT, ...) \
    (__builtin_expect((EXPR), 1)) \
      ? (void)0                 \
      : monad_assert_failed_trampoline(__FUNCTION__, __FILE__, __LINE__, \
                                         #EXPR, FMT __VA_OPT__(,) __VA_ARGS__)

#define MONAD_ASSERT(EXPR) MONAD_ASSERT_MSG(EXPR, nullptr)

#ifdef __cplusplus
} // extern "C"
#endif