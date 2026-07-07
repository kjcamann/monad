#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <category/core/abi/error.h>
#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>

char const *mrv_evm_strerror(mrv_evm_err_t const err)
{
    switch (err) {
#define ERR_DEF(ENUM, STRING)                                                  \
    case ENUM:                                                                 \
        return STRING;

#include "evm_error.def"
#undef ERR_DEF

    default:
        return "Unknown EVM error";
    }
}

char const *mrv_strerror(mrv_err_t const err)
{
    uint16_t const domain = err >> 16;
    switch (domain) {
    case 0:
        return strerror(err);
    case MRV_EVM_ERROR_DOMAIN:
        return mrv_evm_strerror(err);
    case MONAD_ABI_ERROR_DOMAIN:
        return monad_abi_strerror(err);
    default:
        return "Unknown error domain";
    }
}

mrv_err_t
mrv_strerror_r(mrv_err_t const err, char *const buf, size_t *const buflen)
{
    char const *s = mrv_strerror(err);
    size_t const len = strlcpy(buf, s, *buflen);
    mrv_err_t const r = len >= *buflen ? ERANGE : 0;
    *buflen = len + 1;
    return r;
}
