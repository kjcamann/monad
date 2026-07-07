#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include <category/core/abi/abi.h>
#include <category/core/address.h>
#include <category/core/byteview.h>

#define MRV_EXPORT __attribute__((visibility("default")))

#if defined(MRV_EVM_HOST_PLATFORM) && defined(__APPLE__)
    #define MRV_STORAGE_ZINIT __attribute__((section("__DATA,.bss.storage")))
#else
    #define MRV_STORAGE_ZINIT __attribute__((section(".bss.storage")))
#endif

extern monad_abi_t g_mrv_default_param_abi;

typedef struct monad_bv(mrv_abi_rv64_func_t)(monad_abi_t, struct monad_bv);

struct mrv_abi_callable
{
    struct monad_address address;
    monad_abi_t abi;
};

monad_abi_t mrv_abi_get_safe(struct mrv_abi_callable const *);

struct mrv_abi_rv64_header
{
    uint32_t magic;
    monad_abi_t param_cc;
    uint8_t : 8;
    uint16_t name_length;
    uint32_t ordinal;
};

struct mrv_abi_rv64_decode_result
{
    monad_abi_t param_cc;
    char const *fn_name;
    struct monad_bv fn_data;
};

mrv_err_t mrv_abi_rv64_decode_calldata(
    struct monad_bv calldata, struct mrv_abi_rv64_decode_result *);

struct monad_bv mrv_abi_dynelf_txn_main(struct monad_bv calldata);

#ifdef __cplusplus
} // extern "C"
#endif
