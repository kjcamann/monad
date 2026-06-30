#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

constexpr uint16_t MONAD_ABI_ERROR_DOMAIN = 0x0002;

enum monad_abi_err : uint32_t
{
    MONAD_ABIERR_UNKNOWN = ((uint32_t)MONAD_ABI_ERROR_DOMAIN) << 16,
    MONAD_ABIERR_ABI_NOT_SUPPORTED,
    MONAD_ABIERR_NO_BUFFER_SPACE,
    MONAD_ABIERR_UNALIGNED_EVM_WORD,
    MONAD_ABIERR_TUPLE_RANGE,
    MONAD_ABIERR_RUNT_BUFFER,
    MONAD_ABIERR_OFFSET_POINTS_OUTSIDE,
    MONAD_ABIERR_ILLEGAL_UINT,
    MONAD_ABIERR_ILLEGAL_STRING,
    MONAD_ABIERR_ILLEGAL_ABI_TYPE,
    MONAD_ABIERR_OVERFLOW,
    MONAD_ABIERR_ELEMENT_UNINIT,
    MONAD_ABIERR_NO_DYNAMIC,
    MONAD_ABIERR_UNKNOWN_ABI_TYPE,
    MONAD_ABIERR_UNKNOWN_SELECTOR,
    MONAD_ABIERR_NOT_RV64_MAGIC,
};

typedef enum monad_abi_err monad_abi_err_t;

char const *monad_abi_strerror(monad_abi_err_t);

#ifdef __cplusplus
} // extern "C"
#endif
