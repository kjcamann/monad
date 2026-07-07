#pragma once

#include <stdint.h>

#include <category/core/address.h>
#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_rv_code_cache;

typedef __uint128_t monad_rv_code_token_t;

constexpr uint8_t MONAD_RV_CODE_CACHE_MAX_SIZE_SHIFT = 20;

/// Create an RV64 code cache which holds 2^(size_shift) entries
int monad_rv_code_cache_create(
    uint8_t size_shift, struct monad_rv_code_cache **);

/// Destroy an RV64 code cache
void monad_rv_code_cache_destroy(struct monad_rv_code_cache *);

/// Check if the cache holds the code for the given address, and if so, obtain
/// a code token referencing it; returns true if the code was cached
bool monad_rv_code_cache_lookup(
    struct monad_rv_code_cache *, struct monad_address const *,
    monad_rv_code_token_t *);

/// Insert pre-validated code into the code cache; the raw code may be zstd
/// compressed and will be decompressed during caching
void monad_rv_code_cache_insert_valid(
    struct monad_rv_code_cache *, struct monad_address const *,
    struct monad_bv db_code, struct monad_rv_zstd_decomp *,
    monad_rv_code_token_t *);

/// Given the raw data in a contract creation transaction, validate the code
/// and, if valid, insert it into the cache. A code token will be returned only
/// if the return value is MONAD_RV_VCODE_OK
monad_rv_validate_code_result_t monad_rv_code_cache_try_insert_new(
    struct monad_rv_code_cache *, struct monad_address const *,
    struct monad_bv txn_data, struct monad_rv_code_create_sections *,
    bool strict_rv64, struct monad_rv_zstd_decomp *, monad_rv_code_token_t *);

/// Given a code token, return to the handle that must be passed to the RV64
/// virtual machine
void const *monad_rv_code_token_get_vm_handle(monad_rv_code_token_t);

/// Release the code token obtained by an earlier call; this must be called
/// when the user is done using the code object
void monad_rv_code_token_release(monad_rv_code_token_t);

#ifdef __cplusplus
} // extern "C"
#endif
