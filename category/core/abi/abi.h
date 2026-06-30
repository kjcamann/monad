#pragma once

#include <stddef.h>
#include <stdint.h>

struct monad_allocator;

#ifdef __cplusplus
extern "C"
{
#endif

enum monad_abi : uint8_t
{
    MONAD_ABI_UNSPECIFIED,
    MONAD_ABI_SOLIDITY,
    MONAD_ABI_RV64_V1,
};

typedef enum monad_abi monad_abi_t;

constexpr uint32_t MONAD_ABI_RV64_DYNELF = 0x5256AB11; // 'R' 'V' 0xAB 0x11

enum monad_abi_type
{
    MONAD_ABI_TYPE_NONE,
    MONAD_ABI_TYPE_ADDRESS,
    MONAD_ABI_TYPE_UINT_BE,
    MONAD_ABI_TYPE_UINT_HE,
    MONAD_ABI_TYPE_BOOL,
    MONAD_ABI_TYPE_BYTES,
    MONAD_ABI_TYPE_STRING,
    MONAD_ABI_TYPE_DYNAMIC_ARRAY,
    MONAD_ABI_TYPE_DYNAMIC_TUPLE,
};

typedef enum monad_abi_type monad_abi_type_t;

struct monad_abi_input
{
    monad_abi_type_t type;

    union
    {
        void const *fixed;
        void **dyn;
    } ptr;

    size_t size;
};

struct monad_abi_output
{
    monad_abi_type_t type;

    union
    {
        void *buf;
        void const **view;
    } ptr;

    size_t size;
};

#ifdef __cplusplus
} // extern "C"
#endif
