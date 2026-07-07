#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/byteview.h>

#include <mrv/erc20/native.h>
#include <mrv/erc20/native_abi.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/rvabi.h>

MRV_CONTRACT_INIT monad_abi_t g_mrv_default_param_abi;
MRV_CONTRACT_INIT struct mrv_erc20 g_demo_token;

MRV_EXPORT struct monad_bv init_contract(struct monad_bv const init_calldata)
{
    mrv_err_t err;
    char errbuf[1024];
    struct mrv_erc20_init_args init_args;

    // Decode the token's initialization arguments from the init calldata
    err = mrv_erc20_abi_decode_init(init_calldata, &init_args);
    if (err) {
        MRV_PANIC(err, "mrv_erc20_abi_decode_init failed");
    }

    // Check that the data in `init_args` appears legit
    err = mrv_erc20_abi_validate_init_args(&init_args, errbuf, sizeof errbuf);
    if (err) {
        MRV_PANIC(
            err,
            "ERC20 contract initialization arguments were invalid: %s",
            errbuf);
    }

    // Initialize our ERC20 contract's variables from the data in `init_args`
    g_mrv_default_param_abi = init_args.default_abi;
    g_demo_token = init_args.erc20;

    // XXX: return list of prefault storage addresses
    return MONAD_BV_EMPTY;
}

MRV_EXPORT struct monad_bv txn_main(struct monad_bv const calldata)
{
    mrv_err_t err;
    mrv_erc20_abi_func_t *erc20_fn;
    struct monad_bv fn_data;
    uint32_t selector;

    err = mrv_erc20_abi_decode_selector(calldata, &selector, &erc20_fn);
    if (err) {
        MRV_PANIC(err, "mrv_erc20_abi_decode_selector failed");
    }

    if (selector == MONAD_ABI_RV64_DYNELF) {
        // `selector` tells us to trampoline into the desired function using our
        // ELF file's dynamic symbol table
        return mrv_abi_dynelf_txn_main(calldata);
    }

    // Otherwise, `selector` is a Solidity contract ABI function selector and
    // `erc20_fn` is pointing to a contract ABI thunk; call it
    fn_data = monad_bv_sub(calldata, sizeof selector, MONAD_BV_ALL);
    (*erc20_fn)(&g_demo_token, g_mrv_default_param_abi, fn_data);
    mrv_unreachable();
}

// XXX: need to be defined in same translation unit?

#if 0
[[gnu::alias("mrv_erc20_abi_name")]]
MRV_EXPORT void name(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_symbol")]]
MRV_EXPORT void symbol(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_decimals")]]
MRV_EXPORT void decimals(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_total_supply")]]
MRV_EXPORT void totalSupply(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_balance_of")]]
MRV_EXPORT void balanceOf(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_transfer")]]
MRV_EXPORT void transfer(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_transfer_from")]]
MRV_EXPORT void transferFrom(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_approve")]]
MRV_EXPORT void approve(mrv_abi_t, struct monad_bv);

[[gnu::alias("mrv_erc20_abi_allowance")]]
MRV_EXPORT void allowance(mrv_abi_t, struct monad_bv);
#endif
