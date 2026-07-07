#include <alloca.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/xabi_encode.h>
#include <category/core/bytes32.h>
#include <category/core/likely.h>
#include <category/core/strview.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/exit.h>

// This is similar to mrv_panic, but for errors that occur inside the local
// mrv_exit_ helper functions. The panic family of functions themselves call
// `mrv_exit_with_sv`, so if an internal error occurs there (e.g., during
// string encoding), we call this helper to directly format that message and
// manually exit via mrv_evm_revert to prevent unbounded recursion
__attribute__((format(printf, 2, 3))) [[noreturn]] static void
internal_revert(mrv_err_t const err, char const *const format, ...)
{
    int len;
    va_list ap;
    char error_buf[1024];

    va_start(ap, format);
    len = vsnprintf(error_buf, sizeof error_buf, format, ap);
    va_end(ap);

    if (MONAD_UNLIKELY(len < 0)) {
        // Being pedantic here: negative values are never returned in our RISC-V
        // libc vsnprintf(3)
        uint64_t *const err = (uint64_t *)error_buf;
        err[0] = 0xf1f1dead0101dead;
        err[1] = 0x736e7072696e7466; // ASCII for "snprintf"
        err[2] = (uintptr_t)errno;
        mrv_evm_revert(error_buf, len + 4);
    }

    mrv_evm_revert(error_buf, (size_t)len);
}

void mrv_exit_with_sv(
    mrv_evm_exit_type_t const type, monad_abi_t const abi,
    struct monad_sv const sv)
{
    mrv_err_t err;
    char buf[1024];
    char *p = buf;
    size_t buflen = sizeof buf;

TryAgain:
    err = monad_xabi_encode_sv(abi, sv, p, &buflen);
    if (err == MONAD_ABIERR_NO_BUFFER_SPACE) {
        p = alloca(buflen);
        goto TryAgain;
    }
    if (err) {
        internal_revert(err, "monad_xabi_encode_sv of %s failed", sv.begin);
    }

    mrv_evm_exit(type, p, buflen);
}

void mrv_exit_with_uint(
    mrv_evm_exit_type_t const type, monad_abi_t const abi, void const *const u,
    size_t const nbytes)
{
    mrv_err_t err;
    struct monad_bytes32 buf;
    size_t buflen = sizeof buf;

    err = monad_xabi_encode_uint(abi, u, nbytes, &buf, &buflen);
    if (err) {
        internal_revert(
            err, "monad_xabi_encode_uint (size %zu) failed", nbytes);
    }
    mrv_evm_exit(type, &buf, buflen);
}
