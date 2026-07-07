#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <evmc/evmc.h>

#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/keccak.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>

#include "host_exec.h"

static enum evmc_call_kind to_evmc_call_kind(mrv_evm_call_type_t const type)
{
    switch (type) {
    case MRV_EVM_CALL:
        [[fallthrough]];
    case MRV_EVM_STATIC_CALL:
        return EVMC_CALL;
    case MRV_EVM_CALL_CODE:
        return EVMC_CALLCODE;
    case MRV_EVM_DELEGATE_CALL:
        return EVMC_DELEGATECALL;
    }
}

size_t mrv_evm_copy_code(
    struct monad_address const *const addr, size_t const offset,
    uint8_t *const codebuf, size_t const buflen)
{
    evmc_address const *evmc_addr = (evmc_address const *)addr;
    struct mrv_host_exec_context const *const ctx = mrv_get_host_exec_context();
    return ctx->host->copy_code(
        ctx->context, evmc_addr, offset, codebuf, buflen);
}

mrv_err_t mrv_evm_call(struct mrv_evm_call_args const *const call)
{
    struct mrv_host_exec_context *const ctx = mrv_get_host_exec_context();
    struct evmc_message const *const parent_msg = ctx->msg;
    struct evmc_result *const last_call_result = &ctx->last_call_result;
    mrv_evm_call_type_t const type = call->call_type;

    // XXX: there is a bunch of EIP-7702 delegate stuff missing here
    struct evmc_message const msg = {
        .kind = to_evmc_call_kind(type),
        .flags = type == MRV_EVM_STATIC_CALL ? EVMC_STATIC : parent_msg->flags,
        .depth = parent_msg->depth + 1,
        .gas = (int64_t)call->gas,
        .recipient = type == MRV_EVM_CALL || type == MRV_EVM_STATIC_CALL
                         ? *(evmc_address const *)call->address
                         : parent_msg->recipient,
        .sender = type == MRV_EVM_DELEGATE_CALL ? parent_msg->sender
                                                : parent_msg->recipient,
        .input_data = call->calldata.begin,
        .input_size = monad_bv_len(call->calldata),
        .value = type == MRV_EVM_DELEGATE_CALL
                     ? parent_msg->value
                     : *(evmc_uint256be const *)call->value,
        .create2_salt = {},
        .code_address = *(evmc_address const *)call->address,
    };

    if (last_call_result->release != nullptr &&
        last_call_result->output_data != nullptr) {
        last_call_result->release(last_call_result);
    }

    ctx->last_call_result = ctx->host->call(ctx->context, &msg);

    switch (ctx->last_call_result.status_code) {
    case EVMC_SUCCESS:
        return 0;

    case EVMC_REVERT:
        return MRV_EVM_ERR_REVERT;

    case EVMC_OUT_OF_GAS:
        return MRV_EVM_ERR_OUT_OF_GAS;

    default:
        return MRV_EVM_ERR_UNKNOWN;
    }
}

void mrv_evm_exit(
    mrv_evm_exit_type_t const type, void const *const buf, size_t const len)
{
    mrv_host_exit((enum monad_rv_exit_type)type, buf, len);
}

struct monad_bv mrv_evm_calldata()
{
    struct evmc_message const *const msg = mrv_get_host_exec_context()->msg;
    return monad_bv_from_size(msg->input_data, msg->input_size);
}

struct monad_bv mrv_evm_returndata()
{
    struct evmc_result const *const r =
        &mrv_get_host_exec_context()->last_call_result;
    return monad_bv_from_size(r->output_data, r->output_size);
}

uint64_t mrv_evm_gas_left()
{
    return (uint64_t)mrv_get_host_exec_context()->gas;
}

struct monad_bytes32 *mrv_evm_keccak(
    void const *const buf, size_t const len, struct monad_bytes32 *const digest)
{
    keccak256(buf, len, digest->bytes);
    return digest;
}
