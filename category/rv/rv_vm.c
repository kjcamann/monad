#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>

#include <category/core/assert.h>
#include <category/core/likely.h>
#include <category/rv/rv_vm.h>
#include <category/rv/rv_vm_config.h>
#include <category/rv/rvi_dynlink.h>

#include "rv_vm_internal.h"
#include "rvi_code_cache.h"
#include "rvi_dynlink.h"
#include "rvi_log_writer.h"
#include "rvi_zstd.h"

struct code_token
{
    struct rvi_code_cache_entry *entry;
    uint64_t generation;
};

#define VM_LOCK(VM)                                                            \
    do {                                                                       \
        rc = pthread_mutex_lock(&(VM)->mtx);                                   \
        MONAD_ASSERT(rc == 0);                                                 \
    }                                                                          \
    while (0)

#define VM_UNLOCK(VM)                                                          \
    do {                                                                       \
        rc = pthread_mutex_unlock(&(VM)->mtx);                                 \
        MONAD_ASSERT(rc == 0);                                                 \
    }                                                                          \
    while (0)

static int
init_vm_ctx(struct monad_rv_vm_ctx *const ctx, struct monad_rv_vm *const vm)
{
    int rc;

    ctx->vm = vm;
    rc = rvi_zstd_decomp_init(&ctx->decomp);
    if (rc != 0) {
        return VM_ERR(rc, "rvi_zstd_decomp_init failed");
    }
    return 0;
}

static int init_vm_ctx_pool(
    struct monad_rv_vm *const vm, uint8_t const ctx_pool_size_shift)
{
    int rc;

    if (ctx_pool_size_shift > 20) {
        return VM_ERR(
            EINVAL,
            "VM context count shift %hhu too large",
            ctx_pool_size_shift);
    }
    vm->ctx_count = 1U << ctx_pool_size_shift;
    vm->ctx_array = calloc(vm->ctx_count, sizeof(struct monad_rv_vm_ctx));
    if (vm->ctx_array == nullptr) {
        return VM_ERR(errno, "calloc of %u VM contexts failed", vm->ctx_count);
    }
    SLIST_INIT(&vm->ctx_free_list);
    for (uint32_t i = 0; i < vm->ctx_count; ++i) {
        struct monad_rv_vm_ctx *const ctx = &vm->ctx_array[i];
        rc = init_vm_ctx(ctx, vm);
        if (rc != 0) {
            return rc;
        }
        SLIST_INSERT_HEAD(&vm->ctx_free_list, ctx, link);
    }
    return 0;
}

static int init_linker(
    struct monad_rv_vm *const vm,
    struct monad_rv_vm_config const *const vm_config)
{
    struct rvi_dynlink_config const dl_config = {
        .sys_archive = vm_config->sys_archive,
        .bare_metal = vm_config->no_system_libs,
    };

    if (monad_bv_empty(vm_config->sys_archive) && !vm_config->no_system_libs) {
        VM_ERRX("dynamic linker needs a system archive to initialize");
    }
    // Create the dynamic linker, which will load all the system shared
    // libraries and relocate them into the final position in the RV64
    // address space
    return rvi_dynlink_create(&vm->linker, vm, &dl_config);
}

int monad_rv_vm_create(
    struct monad_rv_vm **const vm_p,
    struct monad_rv_log_observer *const log_obs,
    struct monad_rv_vm_config const *const config)
{
    int rc;
    rvi_log_writer_t log_wr;
    struct monad_rv_vm *vm;

    log_wr = rvi_log_writer_init(log_obs, config->max_log_level);
    *vm_p = vm = malloc(sizeof *vm);
    if (vm == nullptr) {
        return LW_ERR(errno, "malloc(3) of monad_rv_failed");
    }
    memset(vm, 0, sizeof *vm);
    vm->log_wr = log_wr;

    rc = pthread_mutex_init(&vm->mtx, nullptr);
    if (rc != 0) {
        VM_ERR(rc, "pthread_mutex_init failed");
        free(vm);
        return rc;
    }
    rc = init_vm_ctx_pool(vm, config->ctx_pool_size_shift);
    if (rc != 0) {
        monad_rv_vm_destroy(vm);
        return rc;
    }
    rc = rvi_code_cache_create(
        &vm->code_cache, config->code_cache_size_shift, vm->log_wr);
    if (rc != 0) {
        monad_rv_vm_destroy(vm);
        return rc;
    }
    rc = init_linker(vm, config);
    if (rc != 0) {
        monad_rv_vm_destroy(vm);
        return rc;
    }
    return 0;
}

bool monad_rv_vm_pin_cached_code(
    struct monad_rv_vm *const vm, struct monad_address const *const addr,
    monad_rv_code_token_t *const raw_token)
{
    struct rvi_code_cache_entry *entry;

    if (rvi_code_cache_lookup(vm->code_cache, addr, &entry)) {
        struct code_token *code_token = (struct code_token *)raw_token;
        code_token->entry = entry;
        code_token->generation = entry->generation;
        return true;
    }
    *raw_token = (monad_rv_code_token_t){};
    return false;
}

struct monad_rv_vm_ctx *monad_rv_vm_acquire_ctx(struct monad_rv_vm *const vm)
{
    int rc;
    struct monad_rv_vm_ctx *ctx;

    VM_LOCK(vm);
    ctx = SLIST_FIRST(&vm->ctx_free_list);
    if (MONAD_LIKELY(ctx != nullptr)) {
        SLIST_REMOVE_HEAD(&vm->ctx_free_list, link);
    }
    VM_UNLOCK(vm);
    return ctx;
}

void monad_rv_vm_pin_valid_code(
    struct monad_rv_vm_ctx *const ctx, struct monad_address const *const addr,
    struct monad_bv const code, monad_rv_code_token_t *const raw_token)
{
    struct rvi_code_cache_entry *entry;
    struct code_token *code_token = (struct code_token *)raw_token;
    struct monad_rv_vm const *const vm = ctx->vm;

    rvi_code_cache_insert_valid(
        vm->code_cache, addr, code, &ctx->decomp, &entry);
    (void)rvi_dynlink_relocate(vm->linker, entry);
    code_token->entry = entry;
    code_token->generation = entry->generation;
}

int monad_rv_vm_ctx_execute(
    struct monad_rv_vm_ctx *const ctx, struct evmc_host_interface const *const,
    struct evmc_host_context *const, enum evmc_revision const,
    struct evmc_message const *const msg, monad_rv_code_token_t raw_token,
    struct evmc_result *result)
{
    int rc;
    rvi_code_cache_state_t cache_state;
    struct monad_rv_vm const *const vm = ctx->vm;
    struct rvi_code_cache_entry *const entry =
        ((struct code_token *)raw_token)->entry;

    cache_state = __atomic_load_n(&entry->state, __ATOMIC_ACQUIRE);
    switch (cache_state) {
    case RVI_CCS_NOT_READY:
        [[fallthrough]];
    case RVI_CCS_DYN_READY:
        rc = rvi_dynlink_relocate(vm->linker, entry);
        if (rc == EINPROGRESS || rc == ENOEXEC) {
            return rc;
        }
        if (rc != 0) {
            // XXX: the revert output should be the error message from the
            // dynamic linker. The initial dynamic link is _not_ expected to
            // succeed: it's not a validation error
            *result = evmc_make_result(EVMC_REVERT, msg->gas, 0, nullptr, 0);
            return 0;
        }
        // Otherwise rc == 0, and the link is successful
        break;

    case RVI_CCS_DYN_INIT:
        return EINPROGRESS;

    case RVI_CCS_READY:
        break; // Ready to execute

    default:
        MONAD_ABORT_PRINTF("unexpected cache state %u", cache_state);
    }

    return VM_ERR(ENOSYS, "Monad RISC-V VM not implemented");
}

monad_rv_validate_code_result_t monad_rv_vm_ctx_pin_txn_create_code(
    struct monad_rv_vm_ctx *const ctx, struct monad_address const *const addr,
    struct monad_bv const txn_data, struct monad_bv *const init_blob,
    monad_rv_code_token_t *const raw_token)
{
    monad_rv_validate_code_result_t vcode_result;
    struct monad_rv_code_create_sections sections;
    struct monad_rv_vm *vm;
    struct rvi_code_cache_entry *entry;

    vm = ctx->vm;
    vcode_result = rvi_code_cache_try_insert_new(
        vm->code_cache,
        addr,
        txn_data,
        &sections,
        vm->strict_rv64,
        &ctx->decomp,
        &entry);
    if (vcode_result == MONAD_RV_VCODE_OK) {
        struct code_token *const code_token = (struct code_token *)raw_token;
        *init_blob = sections.init_blob;
        code_token->entry = entry;
        code_token->generation = entry->generation;
        return vcode_result;
    }
    *raw_token = (monad_rv_code_token_t){};
    *init_blob = MONAD_BV_EMPTY;
    return vcode_result;
}

void monad_rv_vm_ctx_release(struct monad_rv_vm_ctx *ctx)
{
    int rc;
    struct monad_rv_vm *const vm = ctx->vm;

    VM_LOCK(vm);
    SLIST_INSERT_HEAD(&vm->ctx_free_list, ctx, link);
    VM_UNLOCK(vm);
}

void monad_rv_vm_destroy(struct monad_rv_vm *vm)
{
    if (vm != nullptr) {
        for (uint32_t i = 0; i < vm->ctx_count; i++) {
            rvi_zstd_decomp_cleanup(&vm->ctx_array[i].decomp);
        }
        free(vm->ctx_array);
        rvi_code_cache_destroy(vm->code_cache);
        rvi_dynlink_destroy(vm->linker);
        pthread_mutex_destroy(&vm->mtx);
        free(vm);
    }
}

monad_rv_elf_type_t monad_rv_code_token_get_raw_elf(
    monad_rv_code_token_t const raw_token, void const **p, size_t *const size)
{
    uint64_t token_gen;
    struct code_token const *const code_token =
        (struct code_token const *)&raw_token;

    token_gen =
        __atomic_load_n(&code_token->entry->generation, __ATOMIC_ACQUIRE);
    if (code_token->generation != token_gen) {
        *p = nullptr;
        *size = 0;
        return MONAD_RV_ELF_TYPE_INVALID;
    }
    *p = code_token->entry->elf_buf;
    *size = code_token->entry->elf_size;
    return code_token->entry->elf_type;
}

void monad_rv_code_token_release(monad_rv_code_token_t raw_token)
{
    struct code_token const *const code_token = (struct code_token *)&raw_token;
    // XXX: should we check generation here?
    rvi_code_cache_unref_entry(code_token->entry);
}
