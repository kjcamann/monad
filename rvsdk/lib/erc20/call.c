#include <endian.h>
#include <stdcountof.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <category/core/abi/xabi_decode.h>
#include <category/core/abi/xabi_encode.h>
#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/mem/cma/cma_alloc.h>
#include <category/core/mem/cma/cma_bump.h>
#include <category/core/strview.h>

#include <mrv/erc20/call.h>
#include <mrv/erc20/solidity_abi.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/rvabi.h>
#include <mrv/stdlib/uint256.h>

static inline struct monad_bv selector_bv(uint32_t const *const i)
{
    return monad_bv_from_size(i, sizeof *i);
}

static mrv_err_t call_string_info_func(
    struct mrv_abi_callable const *const token, uint32_t const selector,
    struct monad_sv *const sv, bool *const is_zstr)
{
    mrv_err_t err;

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = selector_bv(&selector)};

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return monad_xabi_decode_string(
        mrv_abi_get_safe(token), mrv_evm_returndata(), sv, is_zstr);
}

static mrv_err_t call_uint_info_func(
    struct mrv_abi_callable const *const token, uint32_t const selector,
    size_t const uint_bytes, void *const u)
{
    mrv_err_t err;

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = selector_bv(&selector)};

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return monad_xabi_decode_uint(
        mrv_abi_get_safe(token), mrv_evm_returndata(), uint_bytes, u);
}

mrv_err_t mrv_erc20_call_name(
    struct mrv_abi_callable const *const token, struct monad_sv *const sv,
    bool *const is_zstr)
{
    return call_string_info_func(
        token, htobe32(MRV_ERC20_SOLABI_NAME), sv, is_zstr);
}

mrv_err_t mrv_erc20_call_symbol(
    struct mrv_abi_callable const *const token, struct monad_sv *const sv,
    bool *const is_zstr)
{
    return call_string_info_func(
        token, htobe32(MRV_ERC20_SOLABI_SYMBOL), sv, is_zstr);
}

mrv_err_t mrv_erc20_call_decimals(
    struct mrv_abi_callable const *const token, uint8_t *const decimals)
{
    return call_uint_info_func(
        token, htobe32(MRV_ERC20_SOLABI_DECIMALS), sizeof *decimals, decimals);
}

mrv_err_t mrv_erc20_call_total_supply(
    struct mrv_abi_callable const *const token, mrv_uint256_t *const value)
{
    return call_uint_info_func(
        token, htobe32(MRV_ERC20_SOLABI_DECIMALS), sizeof *value, value);
}

mrv_err_t mrv_erc20_call_balance_of(
    struct mrv_abi_callable const *const token,
    struct monad_address const *const owner, mrv_uint256_t *const value)
{
    monad_abi_t abi;
    mrv_err_t err;

    struct balance_of_args
    {
        uint32_t selector;

        union
        {
            struct monad_address rvabi;
            struct monad_bytes32 solabi;
        } storage;
    } encoded_args;

    size_t encoded_addr_size = sizeof encoded_args.storage;

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = {}};

    abi = mrv_abi_get_safe(token);

    // Fill in `encoded_args`
    encoded_args.selector = htobe32(MRV_ERC20_SOLABI_BALANCE_OF);
    err = monad_xabi_encode_address(
        abi, owner, &encoded_args.storage, &encoded_addr_size);
    if (err) {
        return err;
    }
    call_args.calldata =
        monad_bv_from_size(&encoded_args, sizeof(uint32_t) + encoded_addr_size);

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return monad_xabi_decode_uint(
        abi, mrv_evm_returndata(), sizeof *value, value);
}

mrv_err_t mrv_erc20_call_allowance(
    struct mrv_abi_callable const *const token,
    struct monad_address const *const owner,
    struct monad_address const *const spender, mrv_uint256_t *const value)
{
    monad_abi_t abi;
    mrv_err_t err;
    alignas(8) uint8_t encodebuf[128];
    size_t encodebuf_len = sizeof encodebuf;
    uint32_t const selector = htobe32(MRV_ERC20_SOLABI_ALLOWANCE);

    struct monad_abi_input const inputs[] = {
        [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = owner}},
        [1] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = spender}}};

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = {}};
    abi = mrv_abi_get_safe(token);
    err = monad_xabi_encode_tuple_inputs(
        abi,
        selector_bv(&selector),
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        encodebuf,
        &encodebuf_len);
    if (err) {
        return err;
    }
    call_args.calldata = monad_bv_from_size(encodebuf, encodebuf_len);

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return monad_xabi_decode_uint(
        mrv_abi_get_safe(token), mrv_evm_returndata(), sizeof *value, value);
}

mrv_err_t mrv_erc20_call_approve(
    struct mrv_abi_callable const *const token,
    struct monad_address const *const spender, mrv_uint256_t const *const value)
{
    monad_abi_t abi;
    mrv_err_t err;
    alignas(8) uint8_t encodebuf[128];
    size_t encodebuf_len = sizeof encodebuf;
    uint32_t const selector = htobe32(MRV_ERC20_SOLABI_APPROVE);

    struct monad_abi_input const inputs[] = {
        [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = spender}},
        [1] = {
            .type = MONAD_ABI_TYPE_UINT_HE,
            .ptr = {.fixed = value},
            .size = sizeof *value}};

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = {}};

    abi = mrv_abi_get_safe(token);
    err = monad_xabi_encode_tuple_inputs(
        abi,
        selector_bv(&selector),
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        encodebuf,
        &encodebuf_len);
    if (err) {
        return err;
    }
    call_args.calldata = monad_bv_from_size(encodebuf, encodebuf_len);

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return 0;
}

mrv_err_t mrv_erc20_call_transfer(
    struct mrv_abi_callable const *const token,
    struct monad_address const *const to, mrv_uint256_t const *const value)
{
    monad_abi_t abi;
    mrv_err_t err;
    alignas(8) uint8_t encodebuf[128];
    size_t encodebuf_len = sizeof encodebuf;
    uint32_t const selector = htobe32(MRV_ERC20_SOLABI_TRANSFER);

    struct monad_abi_input const inputs[] = {
        [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = to}},
        [1] =
            {.type = MONAD_ABI_TYPE_UINT_HE,
             .ptr = {.fixed = value},
             .size = sizeof *value},
    };

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = {}};

    abi = mrv_abi_get_safe(token);
    err = monad_xabi_encode_tuple_inputs(
        abi,
        selector_bv(&selector),
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        encodebuf,
        &encodebuf_len);
    if (err) {
        return err;
    }
    call_args.calldata = monad_bv_from_size(encodebuf, encodebuf_len);

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return 0;
}

mrv_err_t mrv_erc20_call_transfer_from(
    struct mrv_abi_callable const *const token,
    struct monad_address const *const from,
    struct monad_address const *const to, mrv_uint256_t const *const value,
    bool *const success)
{
    int rc;
    monad_abi_t abi;
    mrv_err_t err;
    alignas(8) uint8_t encodebuf[256];
    size_t encodebuf_len = sizeof encodebuf;
    uint32_t const selector = htobe32(MRV_ERC20_SOLABI_TRANSFER_FROM);

    struct monad_abi_input const inputs[] = {
        [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = from}},
        [1] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = to}},
        [2] = {
            .type = MONAD_ABI_TYPE_UINT_HE,
            .ptr = {.fixed = value},
            .size = sizeof *value}};

    struct mrv_evm_call_args call_args = {
        .call_type = MRV_EVM_CALL,
        .gas = mrv_evm_gas_left(),
        .address = &token->address,
        .value = &MRV_UINT256_ZERO,
        .calldata = {}};

    *success = false;
    abi = mrv_abi_get_safe(token);
    err = monad_xabi_encode_tuple_inputs(
        abi,
        selector_bv(&selector),
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        encodebuf,
        &encodebuf_len);
    if (err) {
        return err;
    }
    call_args.calldata = monad_bv_from_size(encodebuf, encodebuf_len);

    err = mrv_evm_call(&call_args);
    if (err) {
        return err;
    }

    return monad_xabi_decode_bool(
        mrv_abi_get_safe(token), mrv_evm_returndata(), success);
}
