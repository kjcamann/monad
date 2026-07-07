#include <stdint.h>

#include <err.h>
#include <sysexits.h>

#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/keccak.h>
#include <category/execution/ethereum/core/eth_ctypes.h>
#include <category/rv/code_type.h>
#include <category/rv/rv_code.h>
#include <category/rv/rv_code_cache.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>

#include "block_input.h"
#include "exec.h"
#include "state_tracker.h"

static struct monad_address compute_contract_address(
    struct monad_address const *const sender_addr, uint64_t const nonce)
{
    struct monad_bytes32 hash_digest;

    struct contract_rlp_buf
    {
        uint8_t sender_len;
        struct monad_address sender_addr;
        uint8_t nonce;
    } __attribute__((packed)) const buf = {
        .sender_len = 0x80 + sizeof *sender_addr,
        .sender_addr = *sender_addr,
        .nonce = (uint8_t)nonce,
    };

    MONAD_ASSERT(nonce < 0x80, "can't handle big nonces without real RLP API");
    keccak256(&buf, sizeof buf, hash_digest.bytes);
    return *(struct monad_address const *)(hash_digest.bytes + 12);
}

static struct monad_bv read_account_code(
    struct exec_txn_context const *const txn_ctx,
    monad_address const *const acct_addr)
{
    struct monad_bv code;
    state_db_access_result_t db_result;
    struct monad_eth_account_state acct_state;
    struct state_tracker *const st = txn_ctx->exec_env->state;

    struct state_access_meta const access_meta = {
        .txn_id = txn_ctx->txn_index + 1,
        .call_frame_id = txn_ctx->call_frame_count,
        .pc = 0,
        .context = SA_CTX_MSG_PROLOGUE,
        .reason = SA_REASON_READ_CODE,
    };

    db_result = state_tracker_get_account(
        st, &access_meta, acct_addr, nullptr, &acct_state);
    if (db_result == STATE_DB_NOT_FOUND) {
        return MONAD_BV_EMPTY;
    }
    (void)state_tracker_get_code(
        st, &access_meta, &acct_state.code_hash, &code);
    return code;
}

static struct evmc_result exec_evm(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg, struct monad_bv const code)
{
    if (txn_ctx->exec_env->evm_vm == nullptr) {
        errx(EX_UNAVAILABLE, "no loaded VM can execute EVM bytecode");
    }
    return evmc_execute(
        txn_ctx->exec_env->evm_vm,
        txn_ctx->exec_env->host_if,
        (struct evmc_host_context *)txn_ctx,
        EVMC_OSAKA,
        msg,
        code.begin,
        monad_bv_len(code));
}

static struct evmc_result exec_rv64(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg, monad_rv_code_token_t code_token)
{
    struct evmc_result r;

    if (txn_ctx->exec_env->rv64_vm == nullptr) {
        errx(EX_UNAVAILABLE, "no loaded VM can execute RV64 code");
    }
    r = evmc_execute(
        txn_ctx->exec_env->rv64_vm,
        txn_ctx->exec_env->host_if,
        (struct evmc_host_context *)txn_ctx,
        EVMC_OSAKA,
        msg,
        (uint8_t const *)&code_token,
        sizeof code_token);
    monad_rv_code_token_release(code_token);
    return r;
}

static struct evmc_result exec_code(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg,
    monad_address const *const call_target)
{
    struct monad_bv db_code;
    monad_rv_code_token_t code_token;
    monad_code_type_t code_type;
    bool in_cache;
    struct monad_rv_code_cache *const code_cache =
        txn_ctx->exec_env->rv_code_cache;

    in_cache = monad_rv_code_cache_lookup(code_cache, call_target, &code_token);
    if (in_cache) {
        // RV64 code is present in the cache, execute it using the code token
        return exec_rv64(txn_ctx, msg, code_token);
    }

    // RISC-V code cache does not currently store the code for this address;
    // lookup the account's code and figure out what kind of code it contains
    db_code = read_account_code(txn_ctx, call_target);
    code_type = monad_get_code_type(db_code);

    if (code_type == MONAD_CODE_TYPE_EVM_BYTECODE) {
        // `db_code` contains EVM bytecode; execute using the EVM1 VM
        return exec_evm(txn_ctx, msg, db_code);
    }

    // `db_code` contains RV64_ELF code
    MONAD_ASSERT_PRINTF(
        code_type == MONAD_CODE_TYPE_RV64_ELF,
        "unsupported code type %u",
        (unsigned)code_type);
    monad_rv_code_cache_insert_valid(
        code_cache,
        call_target,
        db_code,
        txn_ctx->exec_env->rv_decomp,
        &code_token);
    // XXX check errors
    return exec_rv64(txn_ctx, msg, code_token);
}

static struct evmc_result exec_msg_call(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg)
{
    struct evmc_result call_result;
    struct state_scope *msg_state;
    state_scope_pop_action_t commit_action;

    // XXX: pre-call stuff (see execute_msg.cpp)
    msg_state = state_tracker_push_scope(txn_ctx->exec_env->state);
    // XXX: check for precompile call targets

    call_result =
        exec_code(txn_ctx, msg, (monad_address const *)&msg->code_address);
    commit_action = call_result.status_code == EVMC_SUCCESS
                        ? STATE_SCOPE_COMMIT
                        : STATE_SCOPE_REVERT;
    state_scope_pop(msg_state, commit_action);
    return call_result;
}

static struct evmc_result create_evm1_contract(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg,
    struct state_scope *const create_scope,
    struct monad_address const *const addr)
{
    MONAD_ABORT("EVM1 contract creation not implemented");
}

static struct evmc_result create_elf_object_contract(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg,
    struct state_scope *const create_state,
    struct monad_address const *const addr,
    struct state_access_meta const *const meta)
{
    struct evmc_message init_msg;
    struct evmc_result init_result;
    struct monad_rv_code_sections sections;
    struct monad_eth_account_state acct_state;
    state_scope_pop_action_t commit_action;
    monad_rv_validate_result_t validate_result;
    monad_rv_code_token_t code_token;
    struct monad_rv_code_cache *const code_cache =
        txn_ctx->exec_env->rv_code_cache;

    validate_result = monad_rv_code_cache_try_insert_new(
        code_cache,
        addr,
        txn_ctx->txn->data,
        &sections,
        /*strict_rv64*/ false,
        txn_ctx->exec_env->rv_decomp,
        &code_token);
    if (validate_result != MONAD_RV_VALIDATE_OK) {
        return evmc_make_result(
            EVMC_CONTRACT_VALIDATION_FAILURE, msg->gas, 0, nullptr, 0);
    }

    // Form the account state
    acct_state.nonce = 1;
    acct_state.balance = MONAD_BYTES32_ZERO; // Balance transferred later
    keccak256(
        sections.db_blob.begin,
        monad_bv_len(sections.db_blob),
        acct_state.code_hash.bytes);

    // TODO(ken): we can't just do this, need to do an EIP-684 collision check
    // first
    state_tracker_set_account(
        txn_ctx->exec_env->state, meta, addr, &acct_state);
    state_tracker_set_code(
        txn_ctx->exec_env->state,
        meta,
        &acct_state.code_hash,
        sections.db_blob);

    init_msg = (struct evmc_message){
        .kind = EVMC_CALL,
        .flags = 4, // XXX: add as a new flag EVMC_ELF_INIT
        .depth = msg->depth,
        .gas = msg->gas,
        .recipient = *(evmc_address const *)addr,
        .sender = msg->sender,
        .input_data = sections.init_blob.begin,
        .input_size = monad_bv_len(sections.init_blob),
        .value = msg->value,
        .create2_salt = (evmc_bytes32){},
        .code_address = *(evmc_address const *)addr,
    };

    init_result = exec_rv64(txn_ctx, &init_msg, code_token);
    init_result.create_address = init_msg.code_address;
    commit_action = init_result.status_code == EVMC_SUCCESS
                        ? STATE_SCOPE_COMMIT
                        : STATE_SCOPE_REVERT;
    state_scope_pop(create_state, commit_action);
    return init_result;
}

static struct evmc_result exec_contract_creation(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg)
{
    struct monad_address contract_addr;
    struct monad_address const *sender_addr;
    struct monad_eth_account_state sender_acct_state;
    struct state_scope *msg_state;
    struct state_tracker *st;
    uint64_t sender_nonce;
    monad_code_type_t code_type;

    struct state_access_meta const meta = {
        .txn_id = txn_ctx->txn_index + 1,
        .call_frame_id = txn_ctx->call_frame_count,
        .pc = 0,
        .context = SA_CTX_MSG_PROLOGUE,
        .reason = SA_REASON_CREATE_CONTRACT,
    };

    // Increment the sender's nonce
    st = txn_ctx->exec_env->state;
    sender_addr = (struct monad_address const *)&msg->sender;
    msg_state = state_tracker_push_scope(st);
    (void)state_tracker_get_account(
        st, &meta, sender_addr, nullptr, &sender_acct_state);
    sender_nonce = sender_acct_state.nonce++;
    state_tracker_set_account(st, &meta, sender_addr, &sender_acct_state);

    switch (msg->kind) {
    case EVMC_CREATE:
        contract_addr = compute_contract_address(sender_addr, sender_nonce);
        break;

    case EVMC_CREATE2:
        MONAD_ABORT("CREATE2 contract address calculation not implemented");
        break;

    default:
        MONAD_ABORT_PRINTF("unsupport msg kind %u", msg->kind);
    }

    code_type = monad_get_code_type(txn_ctx->txn->data);
    switch (code_type) {
    case MONAD_CODE_TYPE_EVM_BYTECODE:
        return create_evm1_contract(txn_ctx, msg, msg_state, &contract_addr);

    case MONAD_CODE_TYPE_RV64_ELF:
        return create_elf_object_contract(
            txn_ctx, msg, msg_state, &contract_addr, &meta);

    default:
        MONAD_ABORT_PRINTF(
            "no support for code type %s (%u)",
            monad_get_code_type_name(code_type),
            code_type);
    }
}

struct evmc_result exec_msg(
    struct exec_txn_context *const txn_ctx,
    struct evmc_message const *const msg)
{
    ++txn_ctx->call_frame_count;

    switch (msg->kind) {
    case EVMC_CALL:
        [[fallthrough]];
    case EVMC_DELEGATECALL:
        [[fallthrough]];
    case EVMC_CALLCODE:
        return exec_msg_call(txn_ctx, msg);

    case EVMC_CREATE:
        [[fallthrough]];
    case EVMC_CREATE2:
        return exec_contract_creation(txn_ctx, msg);

    default:
        err(EX_CONFIG, "unsupported evmc_call_kind %d", msg->kind);
    }
}
