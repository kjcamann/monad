#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/exit.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/rvabi.h>

static char const *final_path_component(char const *const path)
{
    char const *last = strrchr(path, '/');
    return last == nullptr ? path : last + 1;
}

void mrv_vpanic(
    monad_source_location_t const *const srcloc, mrv_err_t const err,
    char const *const format, va_list ap)
{
    size_t len;
    int rc = 0;
    monad_abi_t abi = g_mrv_default_param_abi;
    char err_buf[1024];

    if (srcloc != nullptr) {
        rc = snprintf(
            err_buf,
            sizeof err_buf,
            "%s@%s:%u",
            srcloc->function_name,
            final_path_component(srcloc->file_name),
            srcloc->line);
    }
    len = rc > 0 ? (size_t)rc : 0;
    if (len < sizeof err_buf - 2) {
        if (srcloc != nullptr) {
            err_buf[len++] = ':';
            err_buf[len++] = ' ';
        }
        rc = vsnprintf(err_buf + len, sizeof err_buf - len, format, ap);
        if (rc >= 0) {
            len += (size_t)rc;
        }
    }
    if (err != 0 && len < sizeof err_buf) {
        (void)snprintf(
            err_buf + len,
            sizeof err_buf - len,
            ": %s (%d)",
            mrv_strerror(err),
            err);
    }

    if (abi == MONAD_ABI_UNSPECIFIED) {
        // Sometimes `g_mrv_default_param_abi` is set during contract
        // initialization, but we may panic before it is set. When that happens,
        // be conservative and use Solidity encoding
        abi = MONAD_ABI_SOLIDITY;
    }
    mrv_revert_with_cstr(abi, err_buf);
}
