#pragma once

#include <syslog.h>

#include <category/core/address.h>
#include <category/core/bytes32_map.h>
#include <category/core/srcloc.h>
#include <category/rv/rv_log_observer.h>
#include <category/rv/rv_vm_config.h>

#include <rvc/log.h>
#include <rvc/rvc.h>

struct evmc_host_context;
struct evmc_host_interface;
struct evmc_message;
struct evmc_result;
enum evmc_revision;

struct mem_zone;
struct monad_rv_vm;

#define WRITE_LOG(LOG_IF, LOG_CTX, LEVEL, ...)                                 \
    write_log(                                                                 \
        (LOG_IF),                                                              \
        (LOG_CTX),                                                             \
        (LEVEL),                                                               \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

#define VM_ERR(...) WRITE_LOG(vm->log_if, vm->log_ctx, LOG_ERR, __VA_ARGS__)
#define VM_ERRX(...) WRITE_LOG(vm->log_if, vm->log_ctx, LOG_ERR, 0, __VA_ARGS__)
#define VM_DEBUG(...)                                                          \
    WRITE_LOG(vm->log_if, vm->log_ctx, LOG_DEBUG, 0, __VA_ARGS__)

extern int write_log(
    struct rvc_log_interface const *log_if, void *log_ctx, unsigned level,
    monad_source_location_t const *srcloc, int err, char const *format, ...);

struct riscv_vm_log_trampoline
{
    struct monad_rv_log_observer self;
    struct rvc_vm *rvc;
};

struct rvc_vm
{
    struct monad_rv_vm *riscv_vm;
    struct riscv_vm_log_trampoline rv_log_tramp;
    struct rvc_log_interface const *log_if;
    void *log_ctx;
    struct bytes32_map host_contracts;
    struct mem_zone *map_entry_zone;
};

struct dso_override
{
    struct monad_address addr;
    char const *dso_path;
};

struct host_exec_config
{
    size_t expected_host_contracts;
    struct dso_override *dso_overrides;
    size_t dso_override_count;
};

struct rvc_config
{
    struct monad_rv_vm_config riscv_vm_config;
    struct host_exec_config host_exec_config;
};

int rvc_config_parse(
    struct rvc_config *, char const *ucl_config,
    struct rvc_log_interface const *, void *log_ctx);

void rvc_config_free(struct rvc_config *);

int host_exec_init(struct rvc_vm *, struct host_exec_config const *);

void host_exec_cleanup(struct rvc_vm *);

struct evmc_result host_exec_run(
    struct rvc_vm *, struct evmc_host_interface const *,
    struct evmc_host_context *, enum evmc_revision, struct evmc_message const *,
    rvc_code_token_t);
