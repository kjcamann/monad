#include <stddef.h>
#include <stdio.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>

#include <category/core/address.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

#include "block_input.h"
#include "exec.h"
#include "state_tracker.h"

extern char const *__progname;

extern struct evmc_result exec_txn(struct exec_txn_context *);
extern void hexdump(FILE *, void const *, size_t);

static void print_evmc_result(
    struct evmc_result const *const r, uint64_t const block_number,
    size_t const txn_index, bool const is_contract_creation)
{
    if (r->status_code != EVMC_SUCCESS && r->status_code != EVMC_REVERT) {
        fprintf(
            stderr,
            "%s: txn %lu:%zu failed => %s (%u)\n",
            __progname,
            (unsigned long)block_number,
            txn_index,
            evmc_status_code_to_string(r->status_code),
            r->status_code);
        return;
    }

    fprintf(
        stdout,
        "txn %lu:%zu %s with output: ",
        (unsigned long)block_number,
        txn_index,
        r->status_code == EVMC_SUCCESS ? "finished" : "was reverted");
    if (r->output_size == 0) {
        fprintf(stdout, "<empty>\n");
    }
    else {
        fprintf(stdout, "%zu bytes\n", r->output_size);
        hexdump(stdout, r->output_data, r->output_size);
    }
    if (is_contract_creation && r->status_code == EVMC_SUCCESS) {
        fprintf(
            stdout,
            "  => created contract 0x%s\n",
            monad_address_to_hex_static(
                (struct monad_address const *)&r->create_address));
    }
}

static void init_block_level_evmc_context(
    struct block_input const *const block, struct evmc_tx_context *const tx_ctx)
{
    struct monad_eth_block_input const *const eth_header =
        &block->eth_block_input;

    tx_ctx->block_coinbase = *(evmc_address const *)&eth_header->beneficiary;
    tx_ctx->block_number = eth_header->number;
    tx_ctx->block_timestamp = eth_header->number;
    tx_ctx->block_gas_limit = eth_header->gas_limit;
    tx_ctx->block_prev_randao =
        *(evmc_uint256be const *)&eth_header->prev_randao;
    tx_ctx->block_base_fee =
        *(evmc_uint256be const *)&eth_header->base_fee_per_gas;
    tx_ctx->blob_base_fee = (evmc_uint256be){};
}

void exec_block(
    struct exec_env *const ee, struct block_input const *const block,
    struct monad_eth_block_exec_output *const block_output)
{
    // Push a scope that aggregates all state changes that occur in the block;
    // we don't pop this scope in this function, but leave it there for the
    // database merge operation to find later on
    (void)state_tracker_push_scope(ee->state);

    // TODO(ken): block prologue and epiloge level state changes needed here
    for (size_t i = 0; i < block->txn_count; ++i) {
        struct evmc_result tx_result;
        struct exec_txn_context txn_ctx = {
            .exec_env = ee,
            .txn = &block->txns[i],
            .txn_index = i,
            .call_frame_count = 0,
        };

        // Copy the block-level inputs into the evmc_tx_context
        init_block_level_evmc_context(block, &txn_ctx.evmc_context);

        // Execute the transaction
        tx_result = exec_txn(&txn_ctx);
        print_evmc_result(
            &tx_result,
            block->eth_block_input.number,
            i,
            txn_ctx.txn->header.is_contract_creation);

        // XXX: this calculation is incorrect
        block_output->gas_used +=
            block->txns[i].header.gas_limit - (uint64_t)tx_result.gas_left;

        // TODO(ken): need to form receipts_root and logs_bloom...
        evmc_release_result(&tx_result);
    }
}
