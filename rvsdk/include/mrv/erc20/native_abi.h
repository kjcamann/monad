#pragma once

#include <stddef.h>

#include <category/core/abi/abi.h>
#include <category/core/address.h>
#include <category/core/byteview.h>

#include <mrv/erc20/native.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/uint256.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct mrv_erc20_init_args
{
    struct mrv_erc20 erc20;
    monad_abi_t default_abi;
};

struct mrv_erc20_transfer_args
{
    struct monad_address to;
    mrv_uint256_t value;
};

struct mrv_erc20_transfer_from_args
{
    struct monad_address from;
    struct monad_address to;
    mrv_uint256_t value;
};

struct mrv_erc20_approve_args
{
    struct monad_address spender;
    mrv_uint256_t value;
};

struct mrv_erc20_allowance_args
{
    struct monad_address owner;
    struct monad_address spender;
};

typedef void(mrv_erc20_abi_func_t)(
    struct mrv_erc20 *, monad_abi_t, struct monad_bv);

constexpr mrv_erc20_abi_func_t *MRV_ERC20_ABI_FUNC_DYNELF = nullptr;

mrv_err_t mrv_erc20_abi_decode_selector(
    struct monad_bv, uint32_t *, mrv_erc20_abi_func_t **);

mrv_err_t
mrv_erc20_abi_decode_init(struct monad_bv, struct mrv_erc20_init_args *);

mrv_err_t mrv_erc20_abi_validate_init_args(
    struct mrv_erc20_init_args const *, char *errbuf, size_t buflen);

/*
 * ABI thunks
 */

[[noreturn]] void
mrv_erc20_abi_name(struct mrv_erc20 const *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_symbol(struct mrv_erc20 const *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_decimals(struct mrv_erc20 const *, monad_abi_t, struct monad_bv);

[[noreturn]] void mrv_erc20_abi_total_supply(
    struct mrv_erc20 const *, monad_abi_t, struct monad_bv);

[[noreturn]] void mrv_erc20_abi_balance_of(
    struct mrv_erc20 const *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_transfer(struct mrv_erc20 *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_transfer_from(struct mrv_erc20 *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_approve(struct mrv_erc20 *, monad_abi_t, struct monad_bv);

[[noreturn]] void
mrv_erc20_abi_allowance(struct mrv_erc20 *, monad_abi_t, struct monad_bv);

#ifdef __cplusplus
} // extern "C"
#endif
