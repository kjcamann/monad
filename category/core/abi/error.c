#include <category/core/abi/error.h>

char const *monad_abi_strerror(monad_abi_err_t err)
{
    switch (err) {
#define ERR_DEF(ENUM, STRING)                                                  \
    case ENUM:                                                                 \
        return STRING;

#include "error.def"
#undef ERR_DEF

    default:
        return "Unknown ABI error";
    }
}
