#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>
#include <category/rv/rvi_ecall.h>

#include <mrv/stdlib/error.h>

typedef struct mrv_uint256 mrv_uint256_t;
struct monad_address;
struct monad_bytes32;

#ifdef __cplusplus
extern "C"
{
#endif

constexpr uint16_t MRV_EVM_ERROR_DOMAIN = 0x0001;

enum mrv_evm_err : uint32_t
{
    MRV_EVM_ERR_NONE = 0,
    MRV_EVM_ERR_UNKNOWN = ((uint32_t)MRV_EVM_ERROR_DOMAIN) << 16,
    MRV_EVM_ERR_NO_ACCOUNT,
    MRV_EVM_ERR_REVERT,
    MRV_EVM_ERR_OUT_OF_GAS,
};

typedef enum mrv_evm_err mrv_evm_err_t;

char const *mrv_evm_strerror(mrv_evm_err_t);

enum mrv_evm_call_type : uint8_t
{
    MRV_EVM_CALL,
    MRV_EVM_CALL_CODE,
    MRV_EVM_DELEGATE_CALL,
    MRV_EVM_STATIC_CALL,
};

typedef enum mrv_evm_call_type mrv_evm_call_type_t;

enum mrv_evm_exit_type : uint8_t
{
    MRV_EVM_STOP = RVI_EXIT_STOP,
    MRV_EVM_RETURN = RVI_EXIT_RETURN,
    MRV_EVM_REVERT = RVI_EXIT_REVERT,
};

typedef enum mrv_evm_exit_type mrv_evm_exit_type_t;

struct mrv_evm_call_args
{
    mrv_evm_call_type_t call_type;
    uint64_t gas;
    struct monad_address const *address;
    mrv_uint256_t const *value;
    struct monad_bv calldata;
};

mrv_err_t mrv_evm_call(struct mrv_evm_call_args const *args);

size_t mrv_evm_copy_code(
    struct monad_address const *addr, size_t offset, uint8_t *codebuf,
    size_t buflen);

[[noreturn]] void mrv_evm_exit(mrv_evm_exit_type_t, void const *, size_t);

struct monad_bv mrv_evm_calldata();

struct monad_bv mrv_evm_returndata();

uint64_t mrv_evm_gas_left();

struct monad_bytes32 *
mrv_evm_keccak(void const *, size_t, struct monad_bytes32 *);

void mrv_evm_log(
    struct monad_bytes32 const *topics, size_t topic_count,
    struct monad_bv data);

struct monad_address const *mrv_evm_address();

struct monad_address const *mrv_evm_msg_sender();

void mrv_evm_sload(
    struct monad_bytes32 const *key, struct monad_bytes32 *value);

void mrv_evm_sstore(
    struct monad_bytes32 const *key, struct monad_bytes32 const *value);

void mrv_evm_tload(
    struct monad_bytes32 const *key, struct monad_bytes32 *value);

void mrv_evm_tstore(
    struct monad_bytes32 const *key, struct monad_bytes32 const *value);

[[gnu::always_inline, noreturn]] static inline void
mrv_evm_return(void const *const p, size_t const len)
{
    mrv_evm_exit(MRV_EVM_RETURN, p, len);
}

[[gnu::always_inline, noreturn]] static inline void
mrv_evm_revert(void const *const p, size_t const len)
{
    mrv_evm_exit(MRV_EVM_REVERT, p, len);
}

[[gnu::always_inline, noreturn]] static inline void mrv_evm_stop()
{
    mrv_evm_exit(MRV_EVM_STOP, nullptr, 0);
}

#ifdef __cplusplus
} // extern "C"
#endif
