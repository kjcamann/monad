#pragma once

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

typedef __uint128_t monad_rv_code_token_t;

struct evmc_host_interface;
struct evmc_host_context;
struct evmc_message;
struct evmc_result;
enum evmc_revision;

struct monad_address;
struct monad_rv_link_map;
struct monad_rv_log_observer;
struct monad_rv_vm;
struct monad_rv_vm_config;
struct monad_rv_vm_ctx;

#ifdef __cplusplus
extern "C"
{
#endif

/// Create a Monad RISC-V virtual machine
int monad_rv_vm_create(
    struct monad_rv_vm **, struct monad_rv_log_observer *,
    struct monad_rv_vm_config const *);

/// Destroy a Monad RISC-V virtual machine
void monad_rv_vm_destroy(struct monad_rv_vm *);

/// Get an address map describing the layout of the shared library address
/// space; the address space of contract ELF images is not described by this
/// map (it is fixed when the executable is created)
struct monad_rv_link_map const *monad_rv_vm_get_link_map(struct monad_rv_vm *);

/// Check if the VM holds the code for the given contract address in its cache
/// and if so, return a token referring to it (the token must be released after
/// the caller is done using the code); returns true only if the code is cached
bool monad_rv_vm_pin_cached_code(
    struct monad_rv_vm *, struct monad_address const *,
    monad_rv_code_token_t *);

/// Acquire the local context necessary to run a "virtual thread" of the VM;
/// if the caller wants a multi-threaded (or fiber-based) VM, each thread (or
/// fiber) needs its own context object; APIs that require one of these may
/// return EINPROGRESS if calling thread/fiber tries to use an execution
/// resource being exclusively used by another thread (the caller may want to
/// yield to another thread or fiber in this case, and try again shortly)
struct monad_rv_vm_ctx *monad_rv_vm_acquire_ctx(struct monad_rv_vm *);

/// Place the pre-validated code for the given contract address in the VM's
/// code cache; this always succeeds and returns a code token; the `code` (in
/// MRVC format) may be zstd compressed and will be decompressed during caching
void monad_rv_vm_ctx_pin_valid_code(
    struct monad_rv_vm_ctx *, struct monad_address const *,
    struct monad_bv code, monad_rv_code_token_t *);

/// Given the raw data in a contract creation transaction, validate the code
/// and insert it into the cache if it is valid. A code token will be returned
/// only if the return value is MONAD_RV_VCODE_OK
monad_rv_validate_code_result_t monad_rv_vm_ctx_pin_txn_create_code(
    struct monad_rv_vm_ctx *, struct monad_address const *,
    struct monad_bv txn_data, struct monad_bv *init_blob,
    monad_rv_code_token_t *);

/// Execute an EVM message using the RISC-V VM using the code token obtained
/// by an earlier "pin code" call
int monad_rv_vm_ctx_execute(
    struct monad_rv_vm_ctx *, struct evmc_host_interface const *,
    struct evmc_host_context *, enum evmc_revision, struct evmc_message const *,
    monad_rv_code_token_t, struct evmc_result *);

/// When the calling thread (or fiber) no longer needs execution resources, it
/// must release them using this function
void monad_rv_vm_ctx_release(struct monad_rv_vm_ctx *);

/// Given a code token, get the raw data for its executable image
monad_rv_elf_type_t monad_rv_code_token_get_raw_elf(
    monad_rv_code_token_t, void const **, size_t *size);

/// Release the code token obtained by an earlier "pin code" call; this must
/// be called when the user is done using the code object
void monad_rv_code_token_release(monad_rv_code_token_t);

#ifdef __cplusplus
} // extern "C"
#endif
