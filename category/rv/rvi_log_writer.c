#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/likely.h>
#include <category/core/srcloc.h>
#include <category/rv/rv_log_observer.h>

#include "rvi_log_writer.h"

thread_local static char g_error_buf[4096];

int rvi_log_writer_vpublish_observer(
    struct monad_rv_log_observer *const o,
    monad_source_location_t const *const srcloc, uint8_t const level,
    int const err, char const *const format, va_list const ap)
{
    int rc;
    struct monad_rv_log_entry log = {
        .level = level,
        .error = err,
        .msg = g_error_buf,
        .msglen = 0,
        .srcloc = srcloc,
    };
    rc = vsnprintf(g_error_buf, sizeof g_error_buf, format, ap);
    if (MONAD_UNLIKELY(rc < 0)) {
        sprintf(
            g_error_buf,
            "vsprintf error: %d, format: %.*s",
            rc,
            (int)(sizeof(g_error_buf) - 128),
            g_error_buf);
    }
    else if (MONAD_UNLIKELY(rc >= sizeof g_error_buf)) {
        log.msglen = sizeof(g_error_buf) - 1;
        g_error_buf[log.msglen] = '\0';
    }
    else {
        log.msglen = (size_t)rc;
    }
    return monad_rv_log_publish(o, &log);
}
