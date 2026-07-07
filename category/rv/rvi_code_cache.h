#pragma once

#include <stdint.h>

#include <sys/queue.h>

#include <category/core/address.h>
#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

#include "rvi_log_writer.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct rvi_code_cache;
struct rvi_zstd_decomp;

constexpr uint8_t RVI_CODE_CACHE_MIN_SIZE_SHIFT = 0;
constexpr uint8_t RVI_CODE_CACHE_MAX_SIZE_SHIFT = 20;

// clang-format off

/// Describes the state of a code cache slot; cache entries signal their state
/// by modifying a lock-free variable holding one of these values, to avoid
/// locking the code cache while slow code-preparation operations are
/// running (zstd decompression, dynamic linker GOT table patching, etc.)
typedef enum rvi_code_cache_state
{
    RVI_CCS_NOT_READY,  ///< ELF image cannot be read (still decompressing)
    RVI_CCS_DYN_READY,  ///< ELF image can be read, linker may start
    RVI_CCS_DYN_INIT,   ///< Dynlink is running (code being patched)
    RVI_CCS_READY,      ///< Dynlink is done, code is stable / safe to run
} rvi_code_cache_state_t;

/// Represents a cache slot that holds
struct rvi_code_cache_entry
{
    alignas(64) int64_t refcount;
    struct monad_address address;
    TAILQ_ENTRY(rvi_code_cache_entry) lru_link;
    TAILQ_ENTRY(rvi_code_cache_entry) hash_link;
    alignas(64) rvi_code_cache_state_t state;
    void *elf_buf;
    size_t elf_size;
    uint64_t generation;
    monad_rv_elf_type_t elf_type;
};

/// Create an RV64 code cache which holds 2^(size_shift) entries
int rvi_code_cache_create(
    struct rvi_code_cache **, uint8_t size_shift, rvi_log_writer_t);

/// Destroy an RV64 code cache
void rvi_code_cache_destroy(struct rvi_code_cache *);

/// Check if the cache holds the code for the given address, and if so, obtain
/// the cache entry referencing it; returns true if the code is in cache
bool rvi_code_cache_lookup(
    struct rvi_code_cache *, struct monad_address const *,
    struct rvi_code_cache_entry **);

/// Insert pre-validated code into the code cache; this always succeeds and
/// returns the cache entry; the raw code may be zstd compressed and will be
/// decompressed during caching
void rvi_code_cache_insert_valid(
    struct rvi_code_cache *, struct monad_address const *,
    struct monad_bv db_code, struct rvi_zstd_decomp *,
    struct rvi_code_cache_entry **);

/// Given the raw data in a contract creation transaction, validate the code
/// and, if valid, insert it into the cache. A cache entry will be returned
/// only if the return value is MONAD_RV_VCODE_OK
monad_rv_validate_code_result_t rvi_code_cache_try_insert_new(
    struct rvi_code_cache *, struct monad_address const *,
    struct monad_bv txn_data, struct monad_rv_code_create_sections *,
    bool strict_rv64, struct rvi_zstd_decomp *, struct rvi_code_cache_entry **);

/// Drop the reference count on a cache entry that was acquired by the earlier
/// API call that returned it; this must be called whenever a cache is returned,
/// after the called has finished using the code object
void rvi_code_cache_unref_entry(struct rvi_code_cache_entry *);

#ifdef __cplusplus
} // extern "C"
#endif
