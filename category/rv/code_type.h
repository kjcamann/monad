#pragma once

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

typedef enum monad_code_type
{
    MONAD_CODE_TYPE_UNKNOWN,
    MONAD_CODE_TYPE_EVM_BYTECODE,
    MONAD_CODE_TYPE_MRVC,
} monad_code_type_t;

static monad_code_type_t monad_get_code_type(struct monad_bv code);

static char const *monad_get_code_type_name(monad_code_type_t);

inline monad_code_type_t monad_get_code_type(struct monad_bv const code)
{
    return monad_bv_len(code) >= sizeof MONAD_RV_CODE_PREFIX &&
                   __builtin_memcmp(
                       code.begin,
                       MONAD_RV_CODE_PREFIX,
                       sizeof MONAD_RV_CODE_PREFIX) == 0
               ? MONAD_CODE_TYPE_MRVC
               : MONAD_CODE_TYPE_EVM_BYTECODE;
}

inline char const *monad_get_code_type_name(monad_code_type_t type)
{
    switch (type) {
    case MONAD_CODE_TYPE_EVM_BYTECODE:
        return "EVM bytecode";
    case MONAD_CODE_TYPE_MRVC:
        return "Monad RISC-V code";
    default:
        return "unknown";
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
