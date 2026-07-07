#pragma once

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

typedef __uint128_t monad_rv_code_token_t;

struct evmc_host_interface;
struct evmc_message;
struct evmc_result;

struct monad_address;
struct monad_rv_log_observer;
struct monad_rv_vm;
struct monad_rv_vm_config;

#ifdef __cplusplus
extern "C"
{
#endif

int monad_rv_vm_create(
    struct monad_rv_vm **, struct monad_rv_log_observer *,
    struct monad_rv_vm_config const *);

void monad_rv_vm_destroy(struct monad_rv_vm *);

monad_rv_validate_code_result_t monad_rv_vm_pin_unvalidated_code(
    struct monad_rv_vm *, struct monad_address const *, struct monad_bv code,
    monad_rv_code_token_t *);

void monad_rv_vm_pin_valid_code(
    struct monad_rv_vm *, struct monad_address const *, struct monad_bv code,
    monad_rv_code_token_t *);

bool monad_rv_vm_pin_cached_code(
    struct monad_rv_vm *, struct monad_address const *,
    monad_rv_code_token_t *);

struct evmc_result monad_rv_vm_execute(
    struct monad_rv_vm *, struct evmc_host_interface *,
    struct evmc_message const *, monad_rv_code_token_t *);

/// Release the code token obtained by an earlier pin call; this must be called
/// when the user is done using the code object
void monad_rv_code_token_release(monad_rv_code_token_t);

#ifdef __cplusplus
} // extern "C"
#endif
