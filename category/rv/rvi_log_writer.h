#pragma once

#include <stdarg.h>
#include <stdint.h>

#include <syslog.h>

#include <category/core/likely.h>
#include <category/core/srcloc.h>
#include <category/rv/rv_log_observer.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uintptr_t rvi_log_writer_t;

constexpr uintptr_t RVI_LOG_WRITER_LEVEL_MASK = 0x7;

#define RVI_LOG_WRITE(WRITER, ...)                                             \
    rvi_log_writer_publish(                                                    \
        (WRITER), &MONAD_SOURCE_LOCATION_CURRENT(), __VA_ARGS__)

extern int rvi_log_writer_vpublish_observer(
    struct monad_rv_log_observer *, monad_source_location_t const *,
    uint8_t level, int err, char const *format, va_list);

[[gnu::always_inline]] static inline rvi_log_writer_t rvi_log_writer_init(
    struct monad_rv_log_observer *const o, uint8_t const max_level)
{
    return (uintptr_t)o | max_level;
}

[[gnu::always_inline]] static inline int rvi_log_writer_vpublish(
    rvi_log_writer_t const wr, monad_source_location_t const *const srcloc,
    uint8_t const level, int const err, char const *const format,
    va_list const ap)
{
    struct monad_rv_log_observer *o;

    if (MONAD_LIKELY(level > (wr & RVI_LOG_WRITER_LEVEL_MASK))) {
        return 0;
    }
    o = (struct monad_rv_log_observer *)(wr & ~RVI_LOG_WRITER_LEVEL_MASK);
    if (MONAD_LIKELY(level > monad_rv_log_max_level(o))) {
        return 0;
    }
    return rvi_log_writer_vpublish_observer(o, srcloc, level, err, format, ap);
}

__attribute__((format(printf, 5, 6))) [[gnu::always_inline]] static inline int
rvi_log_writer_publish(
    rvi_log_writer_t const wr, monad_source_location_t const *const srcloc,
    uint8_t const level, int const err, char const *const format, ...)
{
    int rc;
    va_list ap;

    va_start(ap, format);
    rc = rvi_log_writer_vpublish(wr, srcloc, level, err, format, ap);
    va_end(ap);
    return rc;
}

[[gnu::always_inline]] static inline void
rvi_log_writer_flush(rvi_log_writer_t const wr, uint8_t const level)
{
    struct monad_rv_log_observer *o;

    if (MONAD_LIKELY(level > (wr & RVI_LOG_WRITER_LEVEL_MASK))) {
        return;
    }
    o = (struct monad_rv_log_observer *)(wr & ~RVI_LOG_WRITER_LEVEL_MASK);
    monad_rv_log_flush(o);
}

#ifdef __cplusplus
} // extern "C"
#endif
