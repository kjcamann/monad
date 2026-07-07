#include <stdcountof.h>
#include <stdint.h>
#include <string.h>

#include <category/core/abi/solabi_encode.h>
#include <category/core/abi/xabi_encode.h>
#include <category/core/address.h>
#include <category/core/bytes32.h>

#include <mrv/erc20/native.h>
#include <mrv/erc20/solidity_abi.h>

#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/rvabi.h>
#include <mrv/stdlib/uint256.h>

static inline struct monad_bv selector_bv(uint32_t const *const i)
{
    return monad_bv_from_size(i, sizeof *i);
}

static struct monad_bytes32 const *compute_balance_storage_slot(
    struct mrv_erc20 const *const token,
    struct monad_address const *const owner, struct monad_bytes32 *const slot)
{
    struct fingerprint
    {
        uintptr_t token_addr;
        struct monad_address owner;
    };

    struct fingerprint const fp = {
        .token_addr = (uintptr_t)token, .owner = *owner};
    return mrv_evm_keccak(&fp, sizeof fp, slot);
}

static struct monad_bytes32 const *compute_allowance_storage_slot(
    struct mrv_erc20 const *const token,
    struct monad_address const *const owner,
    struct monad_address const *const spender, struct monad_bytes32 *const slot)
{
    struct fingerprint
    {
        uintptr_t token_addr;
        struct monad_address owner;
        struct monad_address spender;
    };

    struct fingerprint const fp = {
        .token_addr = (uintptr_t)token, .owner = *owner, .spender = *spender};

    return mrv_evm_keccak(&fp, sizeof fp, slot);
}

// Helper function to revert with any error type that takes a single address
// argument, e.g., ERC20InvalidReceiver, ERC20InvalidSender, etc.
[[noreturn]] static void revert_invalid_address(
    uint32_t const error, struct monad_address const *const addr)
{
    struct revert_details
    {
        uint32_t selector;

        union
        {
            struct monad_address rvabi;
            struct monad_bytes32 solabi;
        };
    };

    mrv_err_t err;
    struct revert_details r;
    size_t addr_abilen = sizeof r.solabi;

    r.selector = error;
    err = monad_xabi_encode_address(
        g_mrv_default_param_abi, addr, &r.solabi, &addr_abilen);
    if (err) {
        MRV_PANIC(err, "monad_xabi_encode_address failed");
    }
    mrv_evm_revert(&r, sizeof(uint32_t) + addr_abilen);
}

// Helper function to revert with error type ERC20InsufficientBalance or
// ERC20InsufficientAllowance, which share the same formal parameters
// `(address, uint256, uint256)`
[[noreturn]] static void revert_insufficient(
    uint32_t const selector, struct monad_address const *const addr,
    mrv_uint256_t const *const value1, mrv_uint256_t const *const value2)
{
    mrv_err_t err;
    alignas(8) uint8_t encodebuf[256];
    size_t encodebuf_len = sizeof encodebuf;

    struct monad_abi_input const inputs[] = {
        [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = addr}},
        [1] =
            {.type = MONAD_ABI_TYPE_UINT_HE,
             .ptr = {.fixed = value1},
             .size = sizeof *value1},
        [2] = {
            .type = MONAD_ABI_TYPE_UINT_HE,
            .ptr = {.fixed = value2},
            .size = sizeof *value2}};

    err = monad_xabi_encode_tuple_inputs(
        g_mrv_default_param_abi,
        selector_bv(&selector),
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        encodebuf,
        &encodebuf_len);
    if (err) {
        MRV_PANIC(err, "monad_solenc_encode_tuple_inputs failed");
    }
    mrv_evm_revert(encodebuf, encodebuf_len);
}

// ERC20 defines two events, Transfer and Address, which accept the same
// parameter types, i.e., `(address,address,uint256)`; this helper function
// is used to emit EVM logs for both of them
static void write_erc20_log(
    struct monad_bytes32 const *const event_hash,
    struct monad_address const *const addr1,
    struct monad_address const *const addr2, mrv_uint256_t const *const value)
{
    mrv_err_t err;
    struct monad_bytes32 topics[4];
    size_t buflen = sizeof topics;

    struct monad_abi_input const inputs[] = {
        [0] =
            {.type = MONAD_ABI_TYPE_UINT_BE,
             .ptr = {.fixed = event_hash},
             .size = sizeof *event_hash},
        [1] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = addr1}},
        [2] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.fixed = addr2}},
        [3] = {
            .type = MONAD_ABI_TYPE_UINT_HE,
            .ptr = {.fixed = value},
            .size = sizeof *value}};

    err = monad_xabi_encode_tuple_inputs(
        g_mrv_default_param_abi,
        MONAD_BV_EMPTY,
        inputs,
        countof(inputs),
        MONAD_BV_EMPTY,
        topics,
        &buflen);
    if (err) {
        MRV_PANIC(err, "monad_xabi_encode_tuple_inputs failed");
    }
    mrv_evm_log(topics, countof(topics), MONAD_BV_EMPTY);
}

void mrv_erc20_balance_of(
    struct mrv_erc20 const *const token,
    struct monad_address const *const owner, mrv_uint256_t *const value)
{
    struct monad_bytes32 slot;
    mrv_evm_sload(
        compute_balance_storage_slot(token, owner, &slot),
        (struct monad_bytes32 *)value);
}

void mrv_erc20_transfer(
    struct mrv_erc20 *const token, struct monad_address const *const to,
    mrv_uint256_t const *const value)
{
    mrv_erc20_transfer_unchecked_sender(
        token, /*from*/ mrv_evm_msg_sender(), to, value);
}

void mrv_erc20_transfer_from(
    struct mrv_erc20 *const token, struct monad_address const *const from,
    struct monad_address const *const to, mrv_uint256_t const *const value)
{
    struct monad_address const *const spender = mrv_evm_msg_sender();
    mrv_erc20_spend_allowance(token, from, spender, value);
    mrv_erc20_transfer_unchecked_sender(token, from, to, value);
}

void mrv_erc20_approve(
    struct mrv_erc20 *const token, struct monad_address const *const spender,
    mrv_uint256_t const *const value)
{

    struct monad_address const *const owner = mrv_evm_msg_sender();
    mrv_erc20_approve_unchecked_owner(token, owner, spender, value, true);
}

void mrv_erc20_allowance(
    struct mrv_erc20 const *const token,
    struct monad_address const *const owner,
    struct monad_address const *const spender, mrv_uint256_t *const value)
{
    struct monad_bytes32 slot;
    mrv_evm_sload(
        compute_allowance_storage_slot(token, owner, spender, &slot),
        (struct monad_bytes32 *)value);
}

void mrv_erc20_mint(
    struct mrv_erc20 *const token, struct monad_address const *const account,
    mrv_uint256_t const *const value)
{
    if (monad_address_eq(account, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidReceiver(address sender)
        //   RECOMMENDED for disallowed transfers to the zero address
        revert_invalid_address(
            MRV_ERC6093_INVALID_RECEIVER, &MONAD_ADDRESS_ZERO);
    }
    return mrv_erc20_update(token, &MONAD_ADDRESS_ZERO, account, value);
}

void mrv_erc20_burn(
    struct mrv_erc20 *const token, struct monad_address const *const account,
    mrv_uint256_t const *const value)
{
    if (monad_address_eq(account, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidSender(address sender)
        //   RECOMMENDED for disallowed transfers from the zero address
        revert_invalid_address(MRV_ERC6093_INVALID_SENDER, &MONAD_ADDRESS_ZERO);
    }
    return mrv_erc20_update(token, account, &MONAD_ADDRESS_ZERO, value);
}

void mrv_erc20_transfer_unchecked_sender(
    struct mrv_erc20 *const token, struct monad_address const *const from,
    struct monad_address const *const to, mrv_uint256_t const *const value)
{
    if (monad_address_eq(from, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidSender(address sender)
        //   RECOMMENDED for disallowed transfers from the zero address
        revert_invalid_address(MRV_ERC6093_INVALID_SENDER, &MONAD_ADDRESS_ZERO);
    }
    if (monad_address_eq(to, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidReceiver(address receiver)
        //   RECOMMENDED for disallowed transfers to the zero address
        revert_invalid_address(
            MRV_ERC6093_INVALID_RECEIVER, &MONAD_ADDRESS_ZERO);
    }

    mrv_erc20_update(token, from, to, value);
}

void mrv_erc20_approve_unchecked_owner(
    struct mrv_erc20 *const token, struct monad_address const *const owner,
    struct monad_address const *const spender, mrv_uint256_t const *const value,
    bool const emit_event)
{
    struct monad_bytes32 slot;

    if (monad_address_eq(owner, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidApprover(address approver)
        //   RECOMMENDED for disallowed approvals from the zero address
        revert_invalid_address(
            MRV_ERC6093_INVALID_APPROVER, &MONAD_ADDRESS_ZERO);
    }
    if (monad_address_eq(spender, &MONAD_ADDRESS_ZERO)) {
        // [ERC-6093] ERC20InvalidSpender(address spender)
        //   RECOMMENDED for disallowed approvals to the zero address
        revert_invalid_address(
            MRV_ERC6093_INVALID_SPENDER, &MONAD_ADDRESS_ZERO);
    }

    mrv_evm_sstore(
        compute_allowance_storage_slot(token, owner, spender, &slot),
        (struct monad_bytes32 const *)value);
    if (emit_event) {
        write_erc20_log(
            &MRV_ERC20_SOLABI_APPROVAL_EVENT, owner, spender, value);
    }
}

void mrv_erc20_update(
    struct mrv_erc20 *const token, struct monad_address const *const from,
    struct monad_address const *const to, mrv_uint256_t const *const value)
{
    mrv_err_t err;
    struct monad_bytes32 slot;
    mrv_uint256_t balance;

    // Update `from` address balance
    if (from == nullptr || monad_address_eq(from, &MONAD_ADDRESS_ZERO)) {
        mrv_uint256_add(&token->total_supply, value);
    }
    else {
        compute_balance_storage_slot(token, from, &slot);
        mrv_evm_sload(&slot, (struct monad_bytes32 *)&balance);
        if (mrv_uint256_lt(&balance, value)) {
            revert_insufficient(
                MRV_ERC6093_INSUFFICIENT_BALANCE, from, &balance, value);
        }
        mrv_evm_sstore(
            &slot,
            (struct monad_bytes32 const *)mrv_uint256_sub(&balance, value));
    }

    // Update `to` address balance
    if (to == nullptr || monad_address_eq(to, &MONAD_ADDRESS_ZERO)) {
        mrv_uint256_sub(&token->total_supply, value);
    }
    else {
        compute_balance_storage_slot(token, to, &slot);
        mrv_evm_sload(&slot, (struct monad_bytes32 *)&balance);
        mrv_evm_sstore(
            &slot,
            (struct monad_bytes32 const *)mrv_uint256_add(&balance, value));
    }

    // Log the transfer
    write_erc20_log(&MRV_ERC20_SOLABI_TRANSFER_EVENT, from, to, value);
}

void mrv_erc20_spend_allowance(
    struct mrv_erc20 *const token, struct monad_address const *const owner,
    struct monad_address const *const spender, mrv_uint256_t const *const value)
{
    mrv_uint256_t allowance;

    mrv_erc20_allowance(token, owner, spender, &allowance);
    if (mrv_uint256_lt(&allowance, &MRV_UINT256_MAX)) {
        if (mrv_uint256_lt(&allowance, value)) {
            revert_insufficient(
                MRV_ERC6093_INSUFFICIENT_ALLOWANCE, spender, &allowance, value);
        }
        mrv_erc20_approve_unchecked_owner(
            token, owner, spender, mrv_uint256_sub(&allowance, value), false);
    }
}
