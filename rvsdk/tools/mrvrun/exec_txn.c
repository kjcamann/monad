#include <string.h>

#include <evmc/evmc.h>

#include <category/core/assert.h>

#include "block_input.h"
#include "exec.h"
#include "state_db.h"
#include "state_tracker.h"

extern struct evmc_result
exec_msg(struct exec_txn_context *, struct evmc_message const *);

static uint64_t compute_intrinsic_gas(struct txn_input const *)
{
    return 0; // XXX: do this later
}

static void init_txn_level_evmc_context(
    struct txn_input const *const txn, struct evmc_tx_context *const tx_ctx)
{
    struct monad_eth_txn_header const *const txn_header = &txn->header;

    tx_ctx->tx_gas_price =
        *(evmc_uint256be const *)&txn->header.max_fee_per_gas;
    tx_ctx->tx_origin = *(evmc_address const *)&txn->sender;
    tx_ctx->chain_id = *(evmc_uint256be const *)&txn->header.chain_id;
    tx_ctx->blob_hashes =
        (evmc_bytes32 const *)txn->blob_versioned_hashes.begin;
    tx_ctx->blob_hashes_count =
        monad_bv_len(txn->blob_versioned_hashes) / sizeof *tx_ctx->blob_hashes;
}

static void init_evmc_msg(
    struct txn_input const *const txn, uint64_t const intrinsic_gas,
    struct evmc_message *const msg)
{
    memset(msg, 0, sizeof *msg);
    msg->kind = txn->header.is_contract_creation ? EVMC_CREATE : EVMC_CALL;
    msg->flags = 0;
    msg->depth = 0;
    msg->gas = txn->header.gas_limit - intrinsic_gas;
    msg->recipient = *(evmc_address const *)&txn->header.to;
    msg->sender = *(evmc_address const *)&txn->sender;
    msg->input_data = txn->data.begin;
    msg->input_size = monad_bv_len(txn->data);
    msg->value = *(evmc_uint256be const *)&txn->header.value;
    msg->create2_salt = (evmc_bytes32){};
    msg->code_address = msg->recipient;
}

static void irrevocable_change(
    struct exec_txn_context const *const txn_ctx, uint64_t const intrinsic_gas,
    struct state_tracker *const st)
{
    struct state_scope *scope;
    struct monad_eth_account_state sender_account;
    struct txn_input const *const txn = txn_ctx->txn;

    struct state_access_meta const access_meta = {
        .txn_id = txn_ctx->txn_index + 1,
        .call_frame_id = txn_ctx->call_frame_count,
        .pc = 0,
        .context = SA_CTX_TXN_PROLOGUE,
        .reason = SA_REASON_IRREVOCABLE,
    };

    scope = state_tracker_push_scope(st);
    (void)state_tracker_get_account(
        st, &access_meta, &txn->sender, nullptr, &sender_account);
    if (!txn->header.is_contract_creation) {
        ++sender_account.nonce;
    }

    // XXX: skipping over EIP-4844 stuff

    // upfront_cost = txn->gas_limit * gas_price;
    // monad_uint256_he_sub(&sender_account->balance, &upfront_cost);

    state_tracker_set_account(st, &access_meta, &txn->sender, &sender_account);
    state_scope_pop(scope, STATE_SCOPE_COMMIT);
}

struct evmc_result exec_txn(struct exec_txn_context *const txn_ctx)
{
    struct evmc_result r;
    struct evmc_message msg;
    uint64_t intrinsic_gas;

    init_txn_level_evmc_context(txn_ctx->txn, &txn_ctx->evmc_context);
    intrinsic_gas = compute_intrinsic_gas(txn_ctx->txn);

    // TODO(ken): txn validation
    // validate_txn_static(txn);
    // validate_txn_stateful(txn);
    irrevocable_change(txn_ctx, intrinsic_gas, txn_ctx->exec_env->state);

    // Create top-level message
    init_evmc_msg(txn_ctx->txn, intrinsic_gas, &msg);
    r = exec_msg(txn_ctx, &msg);
    // TODO(ken): txn end epilogue? if we need to do any state modifications
    //   which are revertible then need to push a new state scope here
    return r;
}
