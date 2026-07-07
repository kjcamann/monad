#include <alloca.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/solabi_decode.h>
#include <category/core/abi/xabi_decode.h>
#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>

#include <mrv/erc20/native.h>
#include <mrv/erc20/native_abi.h>
#include <mrv/erc20/solidity_abi.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/exit.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/uint256.h>

mrv_err_t mrv_erc20_abi_decode_selector(
    struct monad_bv const calldata, uint32_t *const selector,
    mrv_erc20_abi_func_t **const fn)
{
    if (monad_bv_len(calldata) < sizeof(uint32_t)) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }

    *selector = be32toh(*(uint32_t *)calldata.begin);
    switch (*selector) {
    case MONAD_ABI_RV64_DYNELF:
        *fn = MRV_ERC20_ABI_FUNC_DYNELF;
        return 0;

    case MRV_ERC20_SOLABI_NAME:
        *fn = (mrv_erc20_abi_func_t *)mrv_erc20_abi_name;
        break;

    case MRV_ERC20_SOLABI_SYMBOL:
        *fn = (mrv_erc20_abi_func_t *)mrv_erc20_abi_symbol;
        break;

    case MRV_ERC20_SOLABI_DECIMALS:
        *fn = (mrv_erc20_abi_func_t *)mrv_erc20_abi_decimals;
        break;

    case MRV_ERC20_SOLABI_TOTAL_SUPPLY:
        *fn = (mrv_erc20_abi_func_t *)mrv_erc20_abi_total_supply;
        break;

    case MRV_ERC20_SOLABI_BALANCE_OF:
        *fn = (mrv_erc20_abi_func_t *)mrv_erc20_abi_balance_of;
        break;

    case MRV_ERC20_SOLABI_TRANSFER:
        *fn = mrv_erc20_abi_transfer;
        break;

    case MRV_ERC20_SOLABI_TRANSFER_FROM:
        *fn = mrv_erc20_abi_transfer_from;
        break;

    case MRV_ERC20_SOLABI_APPROVE:
        *fn = mrv_erc20_abi_approve;
        break;

    case MRV_ERC20_SOLABI_ALLOWANCE:
        *fn = mrv_erc20_abi_allowance;
        break;

    default:
        return MONAD_ABIERR_UNKNOWN_SELECTOR;
    }

    return 0;
}

mrv_err_t mrv_erc20_abi_decode_init(
    struct monad_bv const bytes, struct mrv_erc20_init_args *const args)
{
    mrv_uint256_t const *total_supply;
    uint8_t const *decimals;
    struct monad_sv name;
    struct monad_sv symbol;
    monad_abi_t const *default_abi;
    monad_abi_err_t err;

    err = monad_rvabi_unpack_v(
        bytes,
        5,
        nullptr,
        MONAD_ABI_TYPE_UINT_HE,
        &total_supply,
        sizeof *total_supply,
        MONAD_ABI_TYPE_UINT_HE,
        &decimals,
        sizeof *decimals,
        MONAD_ABI_TYPE_STRING,
        &name,
        MONAD_ABI_TYPE_STRING,
        &symbol,
        MONAD_ABI_TYPE_UINT_HE,
        &default_abi,
        sizeof *default_abi);
    if (err) {
        return err;
    }
    args->erc20.total_supply = *total_supply;
    args->erc20.decimals = *decimals;
    err = monad_sv_strncpy(args->erc20.name, sizeof args->erc20.name, name);
    if (err) {
        return err;
    }
    err =
        monad_sv_strncpy(args->erc20.symbol, sizeof args->erc20.symbol, symbol);
    if (err) {
        return err;
    }
    args->default_abi = *default_abi;
    return 0;
}

mrv_err_t mrv_erc20_abi_validate_init_args(
    struct mrv_erc20_init_args const *const args, char *const errbuf,
    size_t const buflen)
{
    if (memchr(args->erc20.name, 0, sizeof args->erc20.name) == nullptr) {
        snprintf(errbuf, buflen, "erc20.name is not null-terminated");
        return EINVAL;
    }

    if (memchr(args->erc20.symbol, 0, sizeof args->erc20.symbol) == nullptr) {
        snprintf(errbuf, buflen, "erc20.symbol is not null-terminated");
        return EINVAL;
    }

    switch (args->default_abi) {
    case MONAD_ABI_SOLIDITY:
        [[fallthrough]];
    case MONAD_ABI_RV64_V1:
        break;

    default:
        snprintf(
            errbuf,
            buflen,
            "default_abi has unrecognized code %hhu",
            args->default_abi);
        return EINVAL;
    }

    return 0;
}

void mrv_erc20_abi_name(
    struct mrv_erc20 const *const token, monad_abi_t const abi,
    struct monad_bv /*unused*/)
{
    mrv_return_cstr(abi, token->name);
}

void mrv_erc20_abi_symbol(
    struct mrv_erc20 const *const token, monad_abi_t const abi,
    struct monad_bv /*unused*/)
{
    mrv_return_cstr(abi, token->symbol);
}

void mrv_erc20_abi_decimals(
    struct mrv_erc20 const *const token, monad_abi_t const abi,
    struct monad_bv /*unused*/)
{
    mrv_return_uint(abi, &token->decimals, sizeof token->decimals);
}

void mrv_erc20_abi_total_supply(
    struct mrv_erc20 const *const token, monad_abi_t const abi,
    struct monad_bv /*unused*/)
{
    mrv_return_uint(abi, &token->total_supply, sizeof token->total_supply);
}

void mrv_erc20_abi_balance_of(
    struct mrv_erc20 const *const token, monad_abi_t const abi,
    struct monad_bv const fn_data)
{
    mrv_err_t err;
    struct monad_address const *owner;
    mrv_uint256_t balance;

    err = monad_xabi_decode_address(abi, fn_data, &owner);
    if (err) {
        MRV_PANIC(err, "balanceOf decode error with ABI %hhu", abi);
    }
    mrv_erc20_balance_of(token, owner, &balance);
    mrv_return_uint(abi, &balance, sizeof balance);
}

void mrv_erc20_abi_transfer(
    struct mrv_erc20 *const token, monad_abi_t const abi,
    struct monad_bv const fn_data)
{
    mrv_err_t err;
    struct mrv_erc20_transfer_args *args;
    struct monad_address const *addr;
    struct monad_bytes32 const *solabi_words;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        args = (struct mrv_erc20_transfer_args *)alloca(sizeof *args);
        err = monad_solabi_decode_fixed(fn_data, &solabi_words, 2);
        if (err) {
            goto Fatal;
        }
        err = monad_solabi_address_from_bytes32(&solabi_words[0], &addr);
        if (err) {
            goto Fatal;
        }
        args->to = *addr;
        mrv_uint256_from_evm_word(&args->value, &solabi_words[1]);
        break;

    case MONAD_ABI_RV64_V1:
        if (monad_bv_len(fn_data) != sizeof *args) {
            MRV_PANIC(
                MONAD_ABIERR_RUNT_BUFFER, "transfer MRV64 ABI decoding failed");
        }
        args = (struct mrv_erc20_transfer_args *)fn_data.begin;
        break;

    default:
        MRV_PANIC(MONAD_ABIERR_ABI_NOT_SUPPORTED, "ABI code %hhu", abi);
    }

    mrv_erc20_transfer(token, &args->to, &args->value);
    mrv_evm_stop();
    mrv_unreachable();

Fatal:
    MRV_PANIC(err, "transfer Solidity ABI decoding failed");
}

void mrv_erc20_abi_transfer_from(
    struct mrv_erc20 *const token, monad_abi_t const abi,
    struct monad_bv const fn_data)
{
    mrv_err_t err;
    struct mrv_erc20_transfer_from_args *args;
    struct monad_address const *addr;
    struct monad_bytes32 const *solabi_words;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        args = (struct mrv_erc20_transfer_from_args *)alloca(sizeof *args);
        err = monad_solabi_decode_fixed(fn_data, &solabi_words, 3);
        if (err) {
            goto Fatal;
        }

        // Copy `from`
        err = monad_solabi_address_from_bytes32(&solabi_words[0], &addr);
        if (err) {
            goto Fatal;
        }
        args->from = *addr;

        // Copy `to`
        err = monad_solabi_address_from_bytes32(&solabi_words[1], &addr);
        if (err) {
            goto Fatal;
        }
        args->to = *addr;

        // Copy and byteswap `value`
        mrv_uint256_from_evm_word(&args->value, &solabi_words[2]);
        break;

    case MONAD_ABI_RV64_V1:
        if (monad_bv_len(fn_data) != sizeof args) {
            MRV_PANIC(
                MONAD_ABIERR_RUNT_BUFFER,
                "transferFrom MRV64 ABI decoding failed");
        }
        args = (struct mrv_erc20_transfer_from_args *)fn_data.begin;
        break;

    default:
        MRV_PANIC(
            MONAD_ABIERR_ABI_NOT_SUPPORTED, "unexpected ABI code %hhu", abi);
    }

    mrv_erc20_transfer_from(token, &args->from, &args->to, &args->value);
    mrv_return_bool(abi, true);
    mrv_unreachable();

Fatal:
    MRV_PANIC(err, "transferFrom Solidity ABI decoding failed");
}

void mrv_erc20_abi_approve(
    struct mrv_erc20 *const token, monad_abi_t const abi,
    struct monad_bv const fn_data)
{
    mrv_err_t err;
    struct mrv_erc20_approve_args *args;
    struct monad_address const *addr;
    struct monad_bytes32 const *solabi_words;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        args = (struct mrv_erc20_approve_args *)alloca(sizeof *args);
        err = monad_solabi_decode_fixed(fn_data, &solabi_words, 2);
        if (err) {
            goto Fatal;
        }

        // Copy `spender`
        err = monad_solabi_address_from_bytes32(&solabi_words[0], &addr);
        if (err) {
            goto Fatal;
        }
        args->spender = *addr;

        // Copy and byteswap `value`
        mrv_uint256_from_evm_word(&args->value, &solabi_words[1]);
        break;

    case MONAD_ABI_RV64_V1:
        if (monad_bv_len(fn_data) != sizeof args) {
            MRV_PANIC(
                MONAD_ABIERR_RUNT_BUFFER, "approve MRV64 ABI decoding failed");
        }
        args = (struct mrv_erc20_approve_args *)fn_data.begin;
        break;

    default:
        MRV_PANIC(
            MONAD_ABIERR_ABI_NOT_SUPPORTED, "unexpected ABI code %hhu", abi);
    }

    mrv_erc20_approve(token, &args->spender, &args->value);
    mrv_return_bool(abi, true);
    mrv_unreachable();

Fatal:
    MRV_PANIC(err, "transferFrom Solidity ABI decoding failed");
}

void mrv_erc20_abi_allowance(
    struct mrv_erc20 *const token, monad_abi_t const abi,
    struct monad_bv const fn_data)
{
    mrv_err_t err;
    struct mrv_erc20_allowance_args *args;
    struct monad_address const *addr;
    struct monad_bytes32 const *solabi_words;
    mrv_uint256_t allowance;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        args = (struct mrv_erc20_allowance_args *)alloca(sizeof *args);
        err = monad_solabi_decode_fixed(fn_data, &solabi_words, 2);
        if (err) {
            goto Fatal;
        }

        // Copy `owner`
        err = monad_solabi_address_from_bytes32(&solabi_words[0], &addr);
        if (err) {
            goto Fatal;
        }
        args->owner = *addr;

        // Copy `spender`
        err = monad_solabi_address_from_bytes32(&solabi_words[1], &addr);
        if (err) {
            goto Fatal;
        }
        args->spender = *addr;
        break;

    case MONAD_ABI_RV64_V1:
        if (monad_bv_len(fn_data) != sizeof args) {
            MRV_PANIC(
                MONAD_ABIERR_RUNT_BUFFER,
                "allowance MRV64 ABI decoding failed");
        }
        args = (struct mrv_erc20_allowance_args *)fn_data.begin;
        break;

    default:
        MRV_PANIC(
            MONAD_ABIERR_ABI_NOT_SUPPORTED, "unexpected ABI code %hhu", abi);
    }

    mrv_erc20_allowance(token, &args->owner, &args->spender, &allowance);
    mrv_return_uint(abi, &allowance, sizeof allowance);
    mrv_unreachable();

Fatal:
    MRV_PANIC(err, "transferFrom Solidity ABI decoding failed");
}
