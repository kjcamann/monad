#include <alloca.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>
#include <evmc/loader.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

#include <rvc/loader.h>
#include <rvc/rvc.h>

#include "block_input.h"
#include "exec.h"
#include "input.h"
#include "mem_state_db.h"
#include "state_db.h"
#include "state_tracker.h"

extern void exec_block(
    struct exec_env *ee, struct block_input const *,
    struct monad_eth_block_exec_output *);

extern struct evmc_result
exec_msg(struct exec_txn_context *, struct evmc_message const *);

constexpr struct mem_state_db_config MEM_STATE_DB_DEFAULT_CONFIG = {
    .expected_accounts = 8,
    .expected_code_accounts = 4,
    .expected_storage_slots_per_account = 16,
};

static struct state_access_meta
make_host_state_access_meta(struct exec_txn_context const *const ctx)
{
    return (struct state_access_meta){
        .txn_id = ctx->txn_index + 1,
        .call_frame_id = ctx->call_frame_count,
        .pc = 0, // XXX: need to plumb this through somewhere
        .context = SA_CTX_VM_RUNTIME,
        .reason = SA_REASON_HOST_CALL,
    };
}

static bool exec_account_exists(
    struct evmc_host_context *const ctx, evmc_address const *const addr)
{
    // XXX: if an account is deleted, this returns false; correct?
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    return state_tracker_get_account(
               txn_ctx->exec_env->state,
               &meta,
               (struct monad_address const *)addr,
               nullptr,
               nullptr) == STATE_DB_SUCCESS;
}

static evmc_bytes32 exec_get_storage(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_bytes32 const *const key)
{
    evmc_bytes32 value;
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    state_tracker_get_storage(
        txn_ctx->exec_env->state,
        &meta,
        (struct monad_address const *)addr,
        nullptr,
        (struct monad_bytes32 const *)key,
        (struct monad_bytes32 *)&value);
    return value;
}

static enum evmc_storage_status exec_set_storage(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_bytes32 const *const key, evmc_bytes32 const *const value)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    return state_tracker_set_storage(
        txn_ctx->exec_env->state,
        &meta,
        (struct monad_address const *)addr,
        (struct monad_bytes32 const *)key,
        (struct monad_bytes32 const *)value);
}

static evmc_uint256be exec_get_balance(
    struct evmc_host_context *const ctx, evmc_address const *const addr)
{
    state_db_access_result_t db_result;
    struct monad_eth_account_state acct_state;
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    db_result = state_tracker_get_account(
        txn_ctx->exec_env->state,
        &meta,
        (monad_address const *)addr,
        nullptr,
        &acct_state);
    return *(evmc_uint256be const *)&acct_state.balance;
}

static size_t exec_get_code_size(
    struct evmc_host_context *const ctx, evmc_address const *const addr)
{
    state_db_access_result_t db_result;
    struct monad_eth_account_state acct_state;
    struct monad_bv code;
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    db_result = state_tracker_get_account(
        txn_ctx->exec_env->state,
        &meta,
        (monad_address const *)addr,
        nullptr,
        &acct_state);
    if (db_result == STATE_DB_NOT_FOUND) {
        return 0;
    }
    (void)state_tracker_get_code(
        txn_ctx->exec_env->state, &meta, &acct_state.code_hash, &code);
    return monad_bv_len(code);
}

static evmc_bytes32 exec_get_code_hash(
    struct evmc_host_context *const ctx, evmc_address const *const addr)
{
    state_db_access_result_t db_result;
    struct monad_eth_account_state acct_state;
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    db_result = state_tracker_get_account(
        txn_ctx->exec_env->state,
        &meta,
        (monad_address const *)addr,
        nullptr,
        &acct_state);
    if (db_result == STATE_DB_NOT_FOUND ||
        __builtin_memcmp(
            &acct_state.code_hash,
            &MONAD_ETH_EMPTY_ACCOUNT,
            sizeof acct_state.code_hash) == 0) {
        return *(evmc_bytes32 const *)&MONAD_BYTES32_EMPTY_KECCAK;
    }
    return *(evmc_bytes32 const *)&MONAD_BYTES32_EMPTY_KECCAK;
}

static size_t exec_copy_code(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    size_t const code_offset, uint8_t *const buf, size_t const buf_size)
{
    state_db_access_result_t db_result;
    struct monad_eth_account_state acct_state;
    struct monad_bv code;
    size_t code_len;
    size_t copy_len;
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    struct state_access_meta const meta = make_host_state_access_meta(txn_ctx);

    db_result = state_tracker_get_account(
        txn_ctx->exec_env->state,
        &meta,
        (monad_address const *)addr,
        nullptr,
        &acct_state);
    if (db_result == STATE_DB_NOT_FOUND) {
        return 0;
    }
    (void)state_tracker_get_code(
        txn_ctx->exec_env->state, &meta, &acct_state.code_hash, &code);
    code_len = monad_bv_len(code) - code_offset;
    copy_len = code_len > buf_size ? buf_size : code_len;
    memcpy(buf, code.begin + code_offset, copy_len);
    return copy_len;
}

static bool exec_selfdestruct(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_address const *const beneficiary)
{
    MONAD_ABORT("unimplemented");
}

static struct evmc_result exec_call(
    struct evmc_host_context *const ctx, struct evmc_message const *const msg)
{
    return exec_msg((struct exec_txn_context *)ctx, msg);
}

static struct evmc_tx_context const *
exec_get_tx_context(struct evmc_host_context *const ctx)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    return &txn_ctx->evmc_context;
}

static evmc_bytes32
exec_get_block_hash(struct evmc_host_context *const ctx, int64_t const number)
{
    MONAD_ABORT("unimplemented");
}

static void exec_emit_log(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    uint8_t const *const data, size_t const data_size,
    evmc_bytes32 const topics[], size_t const topic_count)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;
    (void)state_tracker_emit_log(
        txn_ctx->exec_env->state,
        (struct monad_address const *)addr,
        (struct monad_bytes32 const *)topics,
        topic_count,
        monad_bv_from_size(data, data_size));
}

static enum evmc_access_status exec_access_account(
    struct evmc_host_context *const ctx, evmc_address const *const addr)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;

    // XXX: need to check if this a precompile or special address first
    // XXX: gas cost of accesses not implemented yet
    (void)txn_ctx;
    return EVMC_ACCESS_WARM;
}

static enum evmc_access_status exec_access_storage(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_bytes32 const *const key)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;

    // XXX: gas cost of accesses not implemented yet
    (void)txn_ctx;
    return EVMC_ACCESS_WARM;
}

static evmc_bytes32 exec_get_transient_storage(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_bytes32 const *const key)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;

    MONAD_ABORT("unimplemented");
    (void)txn_ctx;
}

static void exec_set_transient_storage(
    struct evmc_host_context *const ctx, evmc_address const *const addr,
    evmc_bytes32 const *const key, evmc_bytes32 const *const value)
{
    struct exec_txn_context const *const txn_ctx =
        (struct exec_txn_context *)ctx;

    (void)txn_ctx;
    MONAD_ABORT("unimplemented");
}

static struct evmc_host_interface exec_env_host = {
    .account_exists = exec_account_exists,
    .get_storage = exec_get_storage,
    .set_storage = exec_set_storage,
    .get_balance = exec_get_balance,
    .get_code_size = exec_get_code_size,
    .get_code_hash = exec_get_code_hash,
    .copy_code = exec_copy_code,
    .selfdestruct = exec_selfdestruct,
    .call = exec_call,
    .get_tx_context = exec_get_tx_context,
    .get_block_hash = exec_get_block_hash,
    .emit_log = exec_emit_log,
    .access_account = exec_access_account,
    .access_storage = exec_access_storage,
    .get_transient_storage = exec_get_transient_storage,
    .set_transient_storage = exec_set_transient_storage,
};

static char *format_rvc_config(struct exec_env_options const *const ee_opts)
{
    char *config_buf;
    size_t config_len;
    FILE *const config = open_memstream(&config_buf, &config_len);

    if (config == nullptr) {
        err(EX_OSERR, "open_memstream(3) failed");
    }
    fprintf(config, "%s;", ee_opts->rvc_config);

    // Inject RISC-V virtual machine configuration
    fprintf(config, "\nriscv_vm {\n");
    for (size_t i = 0; i < ee_opts->mrv_sys_path_count; ++i) {
        fprintf(config, "\tsystem_archive=%s\n;", ee_opts->mrv_sys_paths[i]);
    }
    fprintf(config, "}\n");

    // Inject host_exec dso overrides
    fprintf(config, "\nhost_exec { dso_overrides {\n");
    for (size_t i = 0; i < ee_opts->dso_override_count; ++i) {
        fprintf(
            config,
            "\t%s=%s;\n",
            ee_opts->dso_overrides[i].address,
            ee_opts->dso_overrides[i].dso_path);
    }
    fprintf(config, "}}\n");
    fclose(config);

    return config_buf;
}

struct exec_env *exec_env_create(struct exec_env_options const *const ee_opts)
{
    struct exec_env *ee;
    // enum state_db_loader_error_code state_db_load_error;

    ee = malloc(sizeof *ee);
    if (!ee) {
        err(EX_OSERR, "malloc of exec_env failed");
    }
    memset(ee, 0, sizeof *ee);

    // Dynamically load a virtual machine capable of executing Ethereum bytecode
    // if the user passed an `evm_config` option; we leave `ee->evm_vm` set to
    // nullptr if no configuration is provided (and we'll only be able to
    // execute ELF shared object code)
    if (ee_opts->evm_config != nullptr) {
        enum evmc_loader_error_code load_error;
        ee->evm_vm = evmc_load_and_configure(ee_opts->evm_config, &load_error);
        if (ee->evm_vm == nullptr) {
            errx(
                EX_UNAVAILABLE,
                "evmc_load_and_configure failed on input `%s`: %s (%d)",
                ee_opts->evm_config,
                evmc_last_error_msg(),
                load_error);
        }
    }

    // Dynamically load a virtual machine capable of executing RV64 code if the
    // user passed an `rvc_config` option; we leave `ee->rvc_vm` set to nullptr
    // if no configuration is provided
    if (ee_opts->rvc_config != nullptr) {
        enum rvc_loader_error_code load_error;
        char *config_buf;
        void *const log_ctx =
            rvc_create_file_logger_ctx(stderr, ee_opts->rv_log_level);

        config_buf = format_rvc_config(ee_opts);
        ee->rvc_vm = rvc_load_and_configure(
            config_buf, &g_rvc_file_logger, log_ctx, &load_error, nullptr);
        if (ee->rvc_vm == nullptr) {
            errx(
                EX_UNAVAILABLE,
                "rvc_load_and_configure failed on input `%s`: %s (%d)",
                ee_opts->rvc_config,
                rvc_describe_last_loader_error(),
                load_error);
        }
        free(config_buf);
    }

    // Dynamically load a provider for the world state database, or create an
    // in-memory database if no dynamic loader config was provided
#if 1
    // Skip this for now, we don't have the state_db loader interface
    if (false) {
#else
    if (ee_opts->db_config != nullptr) {
        ee->lower_db = state_db_load_and_configure(
            ee_opts->db_config, &state_db_load_error);
        if (ee->lower_db == nullptr) {
            errx(
                EX_UNAVAILABLE,
                "state_db_load_and_configure failed on input `%s`: %s (%d)",
                ee_opts->db_config,
                state_db_last_error_msg(),
                state_db_load_error);
        }
#endif
    }
    else {
        ee->lower_db = &mem_state_db_create(&MEM_STATE_DB_DEFAULT_CONFIG)->self;
    }

    ee->prestate_db =
        &overlay_state_db_create(&g_null_state_db->self, ee->lower_db)->self;
    ee->state = state_tracker_create(ee->prestate_db);
    ee->host_if = &exec_env_host;

#if 0
    if (ee->rv64_vm != nullptr) {
        struct monad_rvc_dynlink_config dynlink_cfg;

        dynlink_cfg.sys_archive_count = ee_opts->mrv_boot_path_count;
        dynlink_cfg.sys_archives = (struct monad_bv *)alloca(
            sizeof(struct monad_bv) * dynlink_cfg.sys_archive_count);
        for (size_t i = 0; i < dynlink_cfg.sys_archive_count; ++i) {
            *((struct monad_bv *)dynlink_cfg.sys_archives + 1) =
                mmap_mrv_bootstrap_archive(ee_opts->mrv_boot_paths[i]);
        }

        if (monad_rvc_dynlink_create(&dynlink_cfg, &rvc->dynlink) != 0) {
            errx(
                EX_SOFTWARE,
                "monad_rvc_dynlink_create failed: %s",
                monad_rvc_dynlink_get_last_error());
        }

        // Once monad_rvc_dynlink_create is called, we can free all the
        // memory for the archives
        for (size_t i = 0; i < dynlink_cfg.sys_archive_count; ++i) {
            struct monad_bv const mem_region = dynlink_cfg.sys_archives[i];
            (void)munmap((void *)mem_region.begin, monad_bv_len(mem_region));
        }
    }
#endif

    return ee;
}

void exec_env_destroy(struct exec_env *const ee)
{
    if (ee->evm_vm != nullptr) {
        evmc_destroy(ee->evm_vm);
    }
    if (ee->rvc_vm != nullptr) {
        rvc_vm_destroy(ee->rvc_vm);
    }
    state_db_destroy(ee->prestate_db);
    state_db_destroy(&ee->state->self);
    free(ee);
}

void exec_sim_inputs(
    struct exec_env *const ee, struct sim_input_list const *const inputs)
{
    struct sim_input *si;

    STAILQ_FOREACH(si, inputs, next)
    {
        struct overlay_state_db *odb =
            (struct overlay_state_db *)ee->prestate_db;

        // Install the database overlay used by this simulation input
        odb->upper = si->overlay != nullptr ? &si->overlay->self
                                            : &g_null_state_db->self;

        // Execute all the blocks defined by this simulation input
        // TODO(ken): need to save block outputs, compute MPT hashes
        for (size_t i = 0; i < si->block_count; ++i) {
            struct monad_eth_block_exec_output block_output = {};

            exec_block(ee, &si->blocks[i], &block_output);

            // Apply all changes still active in the state_tracker to the
            // underlying state_db (will compute the next state root if
            // supported by the state_db)
            block_output.state_root = state_tracker_write_to_db(ee->state);

            // Reset all the state tracking data structures; these are kept
            // around even after `state_tracker_write_to_db` in case the caller
            // wants to do detailed frame-level state tracing, but we don't care
            state_tracker_reset(ee->state);
        }
    }
}
