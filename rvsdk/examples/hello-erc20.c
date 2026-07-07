#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/address.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>
#include <category/core/strview.h>

#include <mrv/erc20/call.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/exit.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/rvabi.h>

// Circle's official fake USDC contract address on Monad testnet is:
// 0x534b2f3A21130d7a60830c2Df862319e593943A3
constexpr struct monad_address testnet_usdc_addr = {
    0x53, 0x4b, 0x2f, 0x3a, 0x21, 0x13, 0x0d, 0x7a, 0x60, 0x83,
    0x0c, 0x2d, 0xf8, 0x62, 0x31, 0x9e, 0x59, 0x39, 0x43, 0xa3};

// This program only supports the Solidity contract ABI
MRV_EXPORT monad_abi_t g_mrv_default_param_abi = MONAD_ABI_SOLIDITY;

MRV_EXPORT struct monad_bv txn_main(struct monad_bv /*unused*/)
{
    int rc;
    uint64_t start_gas;
    mrv_err_t err;
    struct mrv_abi_callable testnet_usdc;
    struct monad_sv return_str;
    char namebuf[32];
    char symbolbuf[32];
    char rdatabuf[128];

    start_gas = mrv_evm_gas_left();
    testnet_usdc.address = testnet_usdc_addr;
    testnet_usdc.abi = MONAD_ABI_SOLIDITY;

    err = mrv_erc20_call_name(&testnet_usdc, &return_str, nullptr);
    if (err) {
        MRV_PANIC(
            err,
            "name() on ERC20 `0x%s` failed",
            monad_address_to_hex_static(&testnet_usdc_addr));
    }
    if (monad_sv_strncpy(namebuf, sizeof namebuf, return_str) == ERANGE) {
        MRV_PANICX(
            "name buffer too small (%zu required)", monad_sv_len(return_str));
    }

    err = mrv_erc20_call_symbol(&testnet_usdc, &return_str, nullptr);
    if (err) {
        MRV_PANIC(
            err,
            "symbol() ERC20 `0x%s` failed",
            monad_address_to_hex_static(&testnet_usdc_addr));
    }
    if (monad_sv_strncpy(symbolbuf, sizeof symbolbuf, return_str) == ERANGE) {
        MRV_PANICX(
            "symbol buffer too small (%zu required)", monad_sv_len(return_str));
    }

    rc = snprintf(
        rdatabuf,
        sizeof rdatabuf,
        "name:symbol is: `%s:%s` and it took %lu gas to figure it out",
        namebuf,
        symbolbuf,
        (unsigned long)(mrv_evm_gas_left() - start_gas));
    if (MONAD_UNLIKELY(rc < 0)) {
        MRV_PANICX("snprintf(3) failed: %s (%d)", strerror(rc), rc);
    }
    if (MONAD_UNLIKELY(rc > sizeof rdatabuf)) {
        MRV_PANIC(
            ERANGE,
            "return data buffer too small, was %zu needed %d",
            sizeof rdatabuf,
            rc);
    }

    mrv_return_sv(MONAD_ABI_SOLIDITY, monad_sv_from_size(rdatabuf, (size_t)rc));
    mrv_unreachable();
}
