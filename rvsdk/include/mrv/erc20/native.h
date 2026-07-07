#pragma once

#include <stddef.h>
#include <stdint.h>

#include <mrv/stdlib/uint256.h>

struct monad_address;

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * ERC20 native: these functions are used to allow a native RISC-V contract
 * to offer ERC20 token services
 */

constexpr size_t MRV_ERC20_NAME_MAX = 31;
constexpr size_t MRV_ERC20_SYMBOL_MAX = 31;

struct mrv_erc20
{
    mrv_uint256_t total_supply;
    uint8_t decimals;
    char name[MRV_ERC20_NAME_MAX + 1];
    char symbol[MRV_ERC20_SYMBOL_MAX + 1];
};

void mrv_erc20_balance_of(
    struct mrv_erc20 const *token, struct monad_address const *owner,
    mrv_uint256_t *value);

void mrv_erc20_transfer(
    struct mrv_erc20 *token, struct monad_address const *to,
    mrv_uint256_t const *value);

void mrv_erc20_transfer_from(
    struct mrv_erc20 *token, struct monad_address const *from,
    struct monad_address const *to, mrv_uint256_t const *value);

void mrv_erc20_approve(
    struct mrv_erc20 *token, struct monad_address const *spender,
    mrv_uint256_t const *value);

void mrv_erc20_allowance(
    struct mrv_erc20 const *token, struct monad_address const *owner,
    struct monad_address const *spender, mrv_uint256_t *value);

/*
 *
 */

void mrv_erc20_mint(
    struct mrv_erc20 *token, struct monad_address const *account,
    mrv_uint256_t const *value);

void mrv_erc20_burn(
    struct mrv_erc20 *token, struct monad_address const *account,
    mrv_uint256_t const *value);

void mrv_erc20_transfer_unchecked_sender(
    struct mrv_erc20 *token, struct monad_address const *from,
    struct monad_address const *to, mrv_uint256_t const *value);

void mrv_erc20_approve_unchecked_owner(
    struct mrv_erc20 *token, struct monad_address const *owner,
    struct monad_address const *spender, mrv_uint256_t const *value,
    bool emit_event);

void mrv_erc20_update(
    struct mrv_erc20 *token, struct monad_address const *from,
    struct monad_address const *to, mrv_uint256_t const *value);

void mrv_erc20_spend_allowance(
    struct mrv_erc20 *token, struct monad_address const *owner,
    struct monad_address const *spender, mrv_uint256_t const *value);

#ifdef __cplusplus
} // extern "C"
#endif
