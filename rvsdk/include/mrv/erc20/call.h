#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

struct mrv_abi_callable;
struct monad_sv;

typedef struct mrv_uint256 mrv_uint256_t;
typedef uint32_t mrv_err_t;

/*
 * ERC20 call: these functions interact with other ERC20 contracts via message
 * calls
 */

mrv_err_t mrv_erc20_call_name(
    struct mrv_abi_callable const *, struct monad_sv *, bool *is_zstr);

mrv_err_t mrv_erc20_call_symbol(
    struct mrv_abi_callable const *, struct monad_sv *, bool *is_zstr);

mrv_err_t
mrv_erc20_call_decimals(struct mrv_abi_callable const *, uint8_t *decimals);

mrv_err_t mrv_erc20_call_total_supply(
    struct mrv_abi_callable const *, mrv_uint256_t *value);

mrv_err_t mrv_erc20_call_balance_of(
    struct mrv_abi_callable const *, struct monad_address const *owner,
    mrv_uint256_t *value);

mrv_err_t mrv_erc20_call_allowance(
    struct mrv_abi_callable const *, struct monad_address const *owner,
    struct monad_address const *spender, mrv_uint256_t *value);

mrv_err_t mrv_erc20_call_approve(
    struct mrv_abi_callable const *, struct monad_address const *spender,
    mrv_uint256_t const *value);

mrv_err_t mrv_erc20_call_transfer(
    struct mrv_abi_callable const *, struct monad_address const *to,
    mrv_uint256_t const *value);

mrv_err_t mrv_erc20_call_transfer_from(
    struct mrv_abi_callable const *, struct monad_address const *from,
    struct monad_address const *to, mrv_uint256_t const *value, bool *success);

#ifdef __cplusplus
} // extern "C"
#endif
