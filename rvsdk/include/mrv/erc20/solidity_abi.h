#pragma once

#include <stdint.h>

#include <category/core/bytes32.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum mrv_erc20_solabi_selector : uint32_t
{
    // name()
    MRV_ERC20_SOLABI_NAME = 0x06fdde03,

    // symbol()
    MRV_ERC20_SOLABI_SYMBOL = 0x95d89b41,

    // decimals()
    MRV_ERC20_SOLABI_DECIMALS = 0x313ce567,

    // totalSupply()
    MRV_ERC20_SOLABI_TOTAL_SUPPLY = 0x18160ddd,

    // balanceOf(address)
    MRV_ERC20_SOLABI_BALANCE_OF = 0x70a08231,

    // transfer(address,uint256)
    MRV_ERC20_SOLABI_TRANSFER = 0xa9059cbb,

    // transferFrom(address,address,uint256)
    MRV_ERC20_SOLABI_TRANSFER_FROM = 0x23b872dd,

    // approve(address,uint256)
    MRV_ERC20_SOLABI_APPROVE = 0x095ea7b3,

    // allowance(address,address)
    MRV_ERC20_SOLABI_ALLOWANCE = 0xdd62ed3e,
};

enum mrv_erc6093_solabi_selector : uint32_t
{
    // ERC20InsufficientBalance(address, uint256, uint256)
    MRV_ERC6093_INSUFFICIENT_BALANCE = 0xe450d38c,

    // ERC20InsufficientAllowance(address, uint256, uint256)
    MRV_ERC6093_INSUFFICIENT_ALLOWANCE = 0xfb8f41b2,

    // ERC20InvalidSender(address)
    MRV_ERC6093_INVALID_SENDER = 0x96c6fd1e,

    // ERC20InvalidReceiver(address)
    MRV_ERC6093_INVALID_RECEIVER = 0xec442f05,

    // ERC20InvalidApprover(address)
    MRV_ERC6093_INVALID_APPROVER = 0xe602df05,

    // ERC20InvalidSpender(address)
    MRV_ERC6093_INVALID_SPENDER = 0x94280d62,
};

/*
 * Events
 */

// Transfer(address,address,uint256)
constexpr struct monad_bytes32 MRV_ERC20_SOLABI_TRANSFER_EVENT = {
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0,
    0x68, 0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4,
    0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef};

// Approval(address,address,uint256)
constexpr struct monad_bytes32 MRV_ERC20_SOLABI_APPROVAL_EVENT = {
    0x8c, 0x5b, 0xe1, 0xe5, 0xeb, 0xec, 0x7d, 0x5b, 0xd1, 0x4f, 0x71,
    0x42, 0x7d, 0x1e, 0x84, 0xf3, 0xdd, 0x03, 0x14, 0xc0, 0xf7, 0xb2,
    0x29, 0x1e, 0x5b, 0x20, 0x0a, 0xc8, 0xc7, 0xc3, 0xb9, 0x25};

#ifdef __cplusplus
} // extern "C"
#endif
