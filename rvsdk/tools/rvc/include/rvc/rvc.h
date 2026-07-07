#pragma once

#include <stddef.h>

#include <rvc/log.h>

struct evmc_address;
struct evmc_host_context;
struct evmc_host_interface;
struct evmc_message;
struct evmc_result;

enum evmc_revision;

#ifdef __cplusplus
extern "C"
{
#endif

#define RVC_EXPORT __attribute__((visibility("default")))

struct rvc_vm;

typedef __uint128_t rvc_code_token_t;

typedef struct rvc_vm *(rvc_vm_create_fn)(char const *ucl_config,
                                          struct rvc_log_interface const *,
                                          void *log_ctx);

RVC_EXPORT struct rvc_vm *rvc_vm_create(
    char const *ucl_config, struct rvc_log_interface const *, void *log_ctx);

RVC_EXPORT bool rvc_vm_pin_cached_code(
    struct rvc_vm *, struct evmc_address const *addr, rvc_code_token_t *);

RVC_EXPORT void rvc_vm_pin_valid_code(
    struct rvc_vm *, struct evmc_address const *, void const *code,
    size_t codelen, rvc_code_token_t *);

RVC_EXPORT bool rvc_vm_pin_txn_create_code(
    struct rvc_vm *, struct evmc_address const *, void const *data,
    size_t datalen, size_t *init_offset, rvc_code_token_t *);

RVC_EXPORT struct evmc_result rvc_vm_execute(
    struct rvc_vm *vm, struct evmc_host_interface const *,
    struct evmc_host_context *, enum evmc_revision rev,
    struct evmc_message const *, rvc_code_token_t);

RVC_EXPORT void rvc_vm_release_code_token(struct rvc_vm *, rvc_code_token_t);

RVC_EXPORT void rvc_vm_destroy(struct rvc_vm *);

#ifdef __cplusplus
} // extern "C"
#endif
