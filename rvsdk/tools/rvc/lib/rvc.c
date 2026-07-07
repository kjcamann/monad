#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>

#include <category/core/assert.h>
#include <category/core/format_err.h>
#include <category/rv/rv_vm.h>

#include <rvc/log.h>
#include <rvc/rvc.h>

#include "rvc_impl.h"

constexpr char RVC_VM_LOG_LEVEL[] = "RVC_VM_LOG_LEVEL";

thread_local static char g_error_buf[4096];

static int rvm_tramp_publish(
    struct monad_rv_log_observer *const self,
    struct monad_rv_log_entry const *const log)
{
    struct riscv_vm_log_trampoline *const tramp =
        (struct riscv_vm_log_trampoline *)self;
    write_log(
        tramp->rvc->log_if,
        tramp->rvc->log_ctx,
        log->level,
        log->srcloc,
        log->error,
        log->msg);
    return (int)log->msglen;
}

static uint8_t
rvm_tramp_max_level(struct monad_rv_log_observer const *const self)
{
    struct riscv_vm_log_trampoline *const tramp =
        (struct riscv_vm_log_trampoline *)self;
    return tramp->rvc->log_if->max_level(tramp->rvc->log_ctx);
}

static void rvm_tramp_flush(struct monad_rv_log_observer *const self)
{
    struct riscv_vm_log_trampoline *const tramp =
        (struct riscv_vm_log_trampoline *)self;
    tramp->rvc->log_if->flush(tramp->rvc->log_ctx);
}

static struct monad_rv_log_observer_ops const riscv_vm_log_trampoline_vtable = {
    .publish = rvm_tramp_publish,
    .max_level = rvm_tramp_max_level,
    .flush = rvm_tramp_flush,
};

static void setup_logger_from_environment(
    struct rvc_log_interface const **log_if_p, void **log_ctx_p)
{
    unsigned long log_level;
    char *endptr;
    char const *const env_var = getenv(RVC_VM_LOG_LEVEL);
    if (env_var == nullptr) {
        return;
    }

    log_level = (unsigned)strtoul(env_var, &endptr, 0);
    MONAD_ASSERT_PRINTF(
        log_level <= LOG_DEBUG && *endptr == '\0',
        "`%s` is not a valid %s value",
        env_var,
        RVC_VM_LOG_LEVEL);
    *log_if_p = &g_rvc_file_logger;
    *log_ctx_p = rvc_create_file_logger_ctx(stderr, (uint8_t)log_level);
}

int write_log(
    struct rvc_log_interface const *log_if, void *log_ctx, unsigned level,
    monad_source_location_t const *srcloc, int err, char const *format, ...)
{
    int rc;
    va_list ap;
    struct rvc_log_msg const msg = {
        .syslog_level = level,
        .message = g_error_buf,
    };

    if (log_if == nullptr) {
        return err;
    }
    MONAD_ASSERT(level <= LOG_DEBUG);
    if (level > log_if->max_level(log_ctx)) {
        return err;
    }
    rc = snprintf(g_error_buf, sizeof g_error_buf, "[rvc-vm]: ");
    MONAD_ASSERT(rc >= 0);
    va_start(ap, format);
    rc = monad_vformat_err(
        g_error_buf + (size_t)rc,
        sizeof g_error_buf - (size_t)rc,
        srcloc,
        err,
        format,
        ap);
    va_end(ap);
    MONAD_ASSERT(rc >= 0);
    log_if->publish(log_ctx, &msg);
    return err;
}

struct rvc_vm *rvc_vm_create(
    char const *const ucl_config, struct rvc_log_interface const *log_if,
    void *log_ctx)
{
    struct rvc_config parsed_config;
    struct rvc_vm *vm;

    if (log_if == nullptr) {
        // There is no log consumer, but we might install a default one if
        // certain environment variables are set
        setup_logger_from_environment(&log_if, &log_ctx);
    }
    vm = malloc(sizeof *vm);
    if (vm == nullptr) {
        WRITE_LOG(
            log_if, log_ctx, LOG_ERR, errno, "malloc(3) of rvc_vm failed");
        return nullptr;
    }
    memset(vm, 0, sizeof *vm);

    // After this, we can use the VM_ logging macros
    vm->log_if = log_if;
    vm->log_ctx = log_ctx;

    if (rvc_config_parse(&parsed_config, ucl_config, log_if, log_ctx) != 0) {
        rvc_vm_destroy(vm);
        return nullptr;
    }

    parsed_config.riscv_vm_config.max_log_level = log_if->max_level(log_ctx);
    vm->rv_log_tramp.self.vtable = &riscv_vm_log_trampoline_vtable;
    vm->rv_log_tramp.rvc = vm;
    if (monad_rv_vm_create(
            &vm->riscv_vm,
            &vm->rv_log_tramp.self,
            &parsed_config.riscv_vm_config) != 0) {
        rvc_vm_destroy(vm);
        vm = nullptr;
        goto Exit;
    }

    if (host_exec_init(vm, &parsed_config.host_exec_config) != 0) {
        rvc_vm_destroy(vm);
        vm = nullptr;
        goto Exit;
    }

Exit:
    rvc_config_free(&parsed_config);
    return vm;
}

bool rvc_vm_pin_cached_code(
    struct rvc_vm *const vm, struct evmc_address const *const addr,
    rvc_code_token_t *const code_token)
{
    return monad_rv_vm_pin_cached_code(
        vm->riscv_vm, (struct monad_address const *)addr, code_token);
}

void rvc_vm_pin_valid_code(
    struct rvc_vm *const vm, struct evmc_address const *const addr,
    void const *code, size_t const codelen, rvc_code_token_t *const code_token)
{
    struct monad_rv_vm_ctx *const ctx = monad_rv_vm_acquire_ctx(vm->riscv_vm);
    monad_rv_vm_ctx_pin_valid_code(
        ctx,
        (struct monad_address const *)addr,
        monad_bv_from_size(code, codelen),
        code_token);
    monad_rv_vm_ctx_release(ctx);
}

bool rvc_vm_pin_txn_create_code(
    struct rvc_vm *const vm, struct evmc_address const *const addr,
    void const *const data, size_t const datalen, size_t *const init_offset,
    rvc_code_token_t *const code_token)
{
    struct monad_bv init_blob;
    struct monad_rv_vm_ctx *ctx;
    monad_rv_validate_code_result_t vcode_result;

    ctx = monad_rv_vm_acquire_ctx(vm->riscv_vm);
    vcode_result = monad_rv_vm_ctx_pin_txn_create_code(
        ctx,
        (struct monad_address const *)addr,
        monad_bv_from_size(data, datalen),
        &init_blob,
        code_token);
    monad_rv_vm_ctx_release(ctx);
    if (vcode_result == MONAD_RV_VCODE_OK && init_offset != nullptr) {
        *init_offset = init_blob.begin - (uint8_t const *)data;
    }
    return vcode_result == MONAD_RV_VCODE_OK;
}

struct evmc_result rvc_vm_execute(
    struct rvc_vm *const vm, struct evmc_host_interface const *const host_if,
    struct evmc_host_context *const host_ctx, enum evmc_revision const rev,
    struct evmc_message const *const msg, rvc_code_token_t code_token)
{
    int rc;
    void const *elf_image;
    size_t elf_size;
    struct evmc_result result;
    struct monad_rv_vm_ctx *ctx;
    monad_rv_elf_type_t elf_type;

    elf_type =
        monad_rv_code_token_get_raw_elf(code_token, &elf_image, &elf_size);
    if (elf_type == MONAD_RV_ELF_TYPE_HOST) {
        // Not RISC-V; run this directly on the host
        struct monad_bv const elf_bytes =
            monad_bv_from_size(elf_image, elf_size);
        return host_exec_run(vm, host_if, host_ctx, rev, msg, elf_bytes);
    }

    MONAD_ASSERT(elf_type == MONAD_RV_ELF_TYPE_RV64);
    ctx = monad_rv_vm_acquire_ctx(vm->riscv_vm);
TryAgain:
    rc = monad_rv_vm_ctx_execute(
        ctx, host_if, host_ctx, rev, msg, code_token, &result);
    if (rc == EINPROGRESS) {
        // XXX: this is not what we want here, multi-threaded of multi-fiber
        // programs need a chance to yield here. This would make the API more
        // complex, and we don't care right now.
        goto TryAgain;
    }
    monad_rv_vm_ctx_release(ctx);
    if (rc != 0) {
        return evmc_make_result(EVMC_INTERNAL_ERROR, msg->gas, 0, nullptr, 0);
    }
    return result;
}

void rvc_vm_release_code_token(struct rvc_vm *, rvc_code_token_t code_token)
{
    monad_rv_code_token_release(code_token);
}

void rvc_vm_destroy(struct rvc_vm *const vm)
{
    if (vm != nullptr) {
        host_exec_cleanup(vm);
        monad_rv_vm_destroy(vm->riscv_vm);
        free(vm);
    }
}
