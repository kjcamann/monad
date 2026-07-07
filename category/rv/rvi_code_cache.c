#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <elf.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/rv/rv_code.h>

#include "rvi_code_cache.h"
#include "rvi_elf.h"
#include "rvi_zstd.h"

alignas(4096) static thread_local uint8_t
    s_validate_code_buf[MONAD_RV_CODE_MAX_SIZE];

TAILQ_HEAD(cache_entry_list, rvi_code_cache_entry);

struct rvi_code_cache
{
    pthread_rwlock_t lock;
    struct cache_entry_list *buckets;
    struct cache_entry_list lru_list;
    rvi_log_writer_t log_wr;
    void *elf_buf;
    uint32_t bucket_count;
    uint32_t size;
    uint64_t generation_counter;
};

static struct cache_entry_list *get_bucket_chain(
    struct rvi_code_cache const *const cc,
    struct monad_address const *const addr)
{
    uint64_t hash;
    __builtin_memcpy(&hash, &addr->bytes[12], sizeof hash);
    return &cc->buckets[hash & (cc->bucket_count - 1)];
}

// Return a fresh cache entry to the caller. We evict take the oldest cache
// item on the LRU list to make space for this one. The caller must hold a
// write-locke on the cache to call this.
static struct rvi_code_cache_entry *alloc_cache_entry(
    struct rvi_code_cache *const cc, struct monad_address const *const addr)
{
    struct rvi_code_cache_entry *entry;

    // Scan the LRU list backwards, skipping over cache entries which are
    // pinned in place because their outstanding reference count is greater
    // than zero
    TAILQ_FOREACH_REVERSE(entry, &cc->lru_list, cache_entry_list, lru_link)
    {
        if (__atomic_load_n(&entry->refcount, __ATOMIC_ACQUIRE) != 0) {
            continue; // Skip pinned entry
        }
        // refcount is zero, and getting a new reference to it (via
        // rvi_code_cache_lookup) is not possible since we're holding write
        // lock; no one can be looking at it while we modify it
        entry->state = RVI_CCS_NOT_READY;
        if (entry->generation > 0) {
            struct cache_entry_list *const bucket =
                get_bucket_chain(cc, &entry->address);
            TAILQ_REMOVE(bucket, entry, hash_link);
        }
        TAILQ_REMOVE(&cc->lru_list, entry, lru_link);
        entry->address = *addr;
        entry->generation =
            __atomic_add_fetch(&cc->generation_counter, 1, __ATOMIC_ACQ_REL);
        return entry;
    }

    // There is no way this can realistically happen if references are being
    // released correctly
    MONAD_ABORT("exhausted unpinned cache entries?");
}

int rvi_code_cache_create(
    struct rvi_code_cache **cc_p, uint8_t size_shift, rvi_log_writer_t log_wr)
{
    int rc;
    struct rvi_code_cache *cc;
    struct rvi_code_cache_entry *entries;

    *cc_p = nullptr;
    if (size_shift < RVI_CODE_CACHE_MIN_SIZE_SHIFT ||
        size_shift > RVI_CODE_CACHE_MAX_SIZE_SHIFT) {
        return LW_ERR(EINVAL, "cache size shift %hhu out of range", size_shift);
    }
    cc = malloc(sizeof *cc);
    if (cc == nullptr) {
        return LW_ERR(errno, "malloc(3) of rvi_code_cache failed");
    }
    memset(cc, 0, sizeof *cc);
    rc = pthread_rwlock_init(&cc->lock, nullptr);
    if (rc != 0) {
        return LW_ERR(rc, "pthread_rwlock_init failed");
    }
    cc->log_wr = log_wr;
    cc->size = 1U << size_shift;
    cc->bucket_count = 2 * cc->size;
    cc->generation_counter = 1;
    cc->buckets = calloc(cc->bucket_count, sizeof(struct cache_entry_list));
    if (cc->buckets == nullptr) {
        rc =
            LW_ERR(errno, "calloc of %u hash buckets failed", cc->bucket_count);
        rvi_code_cache_destroy(cc);
        return rc;
    }
    cc->elf_buf = mmap(
        nullptr,
        cc->size * MONAD_RV_CODE_MAX_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    if (cc->elf_buf == MAP_FAILED) {
        rc = LW_ERR(errno, "mmap of ELF buffer failed");
        rvi_code_cache_destroy(cc);
        return rc;
    }
    for (size_t i = 0; i < cc->bucket_count; i++) {
        TAILQ_INIT(&cc->buckets[i]);
    }
    TAILQ_INIT(&cc->lru_list);

    entries = calloc(cc->size, sizeof(struct rvi_code_cache_entry));
    if (entries == nullptr) {
        rc = LW_ERR(errno, "calloc of %u code cache entries failed", cc->size);
        rvi_code_cache_destroy(cc);
        return rc;
    }
    for (size_t i = 0; i < cc->size; ++i) {
        struct rvi_code_cache_entry *const entry = &entries[i];
        entry->elf_buf = (uint8_t *)cc->elf_buf + i * MONAD_RV_CODE_MAX_SIZE;
        TAILQ_INSERT_TAIL(&cc->lru_list, entry, lru_link);
    }

    *cc_p = cc;
    return 0;
}

void rvi_code_cache_destroy(struct rvi_code_cache *cc)
{
    if (cc != nullptr) {
        pthread_rwlock_destroy(&cc->lock);
        munmap(cc->elf_buf, MONAD_RV_CODE_MAX_SIZE * cc->size);
        free(cc->buckets);
        free(cc);
    }
}

bool rvi_code_cache_lookup(
    struct rvi_code_cache *cc, struct monad_address const *addr,
    struct rvi_code_cache_entry **entry_p)
{
    struct cache_entry_list *bucket;
    struct rvi_code_cache_entry *entry;

    // XXX: need to assert if failure
    pthread_rwlock_rdlock(&cc->lock);
    bucket = get_bucket_chain(cc, addr);
    TAILQ_FOREACH(entry, bucket, hash_link)
    {
        uint64_t old_generation;

        if (!monad_address_eq(addr, &entry->address)) {
            continue; // Hash collision; keep looking
        }

        // The normal cache-hit case: we found the entry, and need to move it
        // to the front of the LRU list. To do this, we need to "upgrade" the
        // rwlock to allow writes. The pthread rwlock does not have native lock
        // upgrade support, so we drop the read lock and re-acquire it. Before
        // dropping the lock, we first save the old generation number of the
        // cache entry, so we can check if it got recycled during the time that
        // it was unlocked
        old_generation = __atomic_load_n(&entry->generation, __ATOMIC_ACQUIRE);
        pthread_rwlock_unlock(&cc->lock);

        pthread_rwlock_wrlock(&cc->lock);
        if (__atomic_load_n(&entry->generation, __ATOMIC_ACQUIRE) !=
            old_generation) {
            // Our cache entry was yanked while the lock was dropped
            pthread_rwlock_unlock(&cc->lock);
            return false;
        }

        // Maintain the LRU ordering
        TAILQ_REMOVE(&cc->lru_list, entry, lru_link);
        TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);

        // Export a reference to the caller
        __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
        pthread_rwlock_unlock(&cc->lock);
        *entry_p = entry;
        return true;
    }

    pthread_rwlock_unlock(&cc->lock);
    return false;
}

void rvi_code_cache_insert_valid(
    struct rvi_code_cache *cc, struct monad_address const *addr,
    struct monad_bv db_code, struct rvi_zstd_decomp *decomp,
    struct rvi_code_cache_entry **entry_p)
{
    struct cache_entry_list *bucket;
    struct rvi_code_cache_entry *entry;
    monad_rv_validate_code_result_t vcode_result;

    pthread_rwlock_wrlock(&cc->lock);
    bucket = get_bucket_chain(cc, addr);
    TAILQ_FOREACH(entry, bucket, hash_link)
    {
        if (monad_address_eq(addr, &entry->address)) {
            // We already have a cache entry for this address, so we must have
            // lost a race to re-insert it against another thread; grab a new
            // reference for ourselves and exit
            __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
            pthread_rwlock_unlock(&cc->lock);
            *entry_p = entry;
            return;
        }
    }
    // The normal case: we are responsible for re-inserting this and
    // initializing it ourselves
    entry = alloc_cache_entry(cc, addr);
    TAILQ_INSERT_HEAD(bucket, entry, hash_link);
    TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);
    __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
    pthread_rwlock_unlock(&cc->lock);
    *entry_p = entry;

    // At this point another thread may discover this half-initialized cache
    // entry, but it will be marked RVI_CCS_NOT_READY so they will know they
    // cannot do anything with it while we are initializing it. Namely, the
    // dynamic linker will know not to touch it until we compare-exchange
    // entry->state from RVI_CCS_NOT_READY to RVI_CCS_DYN_READY. This is how
    // we decompress (or memcpy) with the cache lock released.
    if (__builtin_memcmp(
            db_code.begin + sizeof(struct monad_rv_code_header),
            ELFMAG,
            SELFMAG) == 0) {
        entry->elf_size = monad_bv_len(db_code);
        memcpy(entry->elf_buf, db_code.begin, entry->elf_size);
    }
    else {
        entry->elf_size = MONAD_RV_CODE_MAX_SIZE;
        vcode_result = rvi_zstd_decompress_code(
            decomp,
            db_code,
            entry->elf_buf,
            &entry->elf_size,
            nullptr,
            nullptr);
        MONAD_ASSERT(vcode_result == MONAD_RV_VCODE_HAS_ELF_MAGIC);
    }
    entry->elf_type = rvi_elf_get_type(entry->elf_buf);

    // Tell the linker it can start
    __atomic_store_n(&entry->state, RVI_CCS_DYN_READY, __ATOMIC_RELEASE);
}

monad_rv_validate_code_result_t rvi_code_cache_try_insert_new(
    struct rvi_code_cache *cc, struct monad_address const *addr,
    struct monad_bv txn_data, struct monad_rv_code_create_sections *sections,
    bool strict_rv64, struct rvi_zstd_decomp *decomp,
    struct rvi_code_cache_entry **entry_p)
{
    struct cache_entry_list *bucket;
    struct rvi_code_cache_entry *entry;
    monad_rv_elf_type_t elf_type;
    monad_rv_validate_code_result_t vcode_result;
    void const *code;
    size_t codelen;

    vcode_result = monad_rv_parse_create_txn_data(txn_data, sections);
    switch (vcode_result) {
    case MONAD_RV_VCODE_HAS_ELF_MAGIC:
        [[fallthrough]];
    case MONAD_RV_VCODE_HAS_ZSTD_MAGIC:
        break; // Handled in main body of the function

    default:
        return vcode_result; // Error, will not proceed
    }

    if (vcode_result == MONAD_RV_VCODE_HAS_ZSTD_MAGIC) {
        codelen = MONAD_RV_CODE_MAX_SIZE;
        code = s_validate_code_buf;
        vcode_result = rvi_zstd_decompress_code(
            decomp,
            sections->db_blob,
            s_validate_code_buf,
            &codelen,
            nullptr,
            nullptr);
    }
    else {
        code = sections->code_blob.begin;
        codelen = monad_bv_len(sections->code_blob);
    }

    if (vcode_result != MONAD_RV_VCODE_HAS_ELF_MAGIC) {
        return vcode_result;
    }

    vcode_result = rvi_elf_validate(code, codelen, &elf_type);
    if (vcode_result != MONAD_RV_VCODE_OK) {
        return vcode_result;
    }
    if (elf_type == MONAD_RV_ELF_TYPE_HOST && strict_rv64) {
        return MONAD_RV_VCODE_ELF_NOT_RV64;
    }

    pthread_rwlock_wrlock(&cc->lock);
    bucket = get_bucket_chain(cc, addr);
    TAILQ_FOREACH(entry, bucket, hash_link)
    {
        if (monad_address_eq(addr, &entry->address)) {
            // The case we lose a "create entry race"; as described in
            // insert_valid
            __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
            pthread_rwlock_unlock(&cc->lock);
            *entry_p = entry;
            return MONAD_RV_VCODE_OK;
        }
    }
    entry = alloc_cache_entry(cc, addr);
    TAILQ_INSERT_HEAD(bucket, entry, hash_link);
    TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);
    __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_ACQ_REL);
    pthread_rwlock_unlock(&cc->lock);
    *entry_p = entry;

    entry->elf_size = codelen;
    memcpy(entry->elf_buf, code, entry->elf_size);
    entry->elf_type = elf_type;
    __atomic_store_n(&entry->state, RVI_CCS_DYN_READY, __ATOMIC_RELEASE);
    return MONAD_RV_VCODE_OK;
}

void rvi_code_cache_unref_entry(struct rvi_code_cache_entry *entry)
{
    int64_t const last_ref =
        __atomic_fetch_sub(&entry->refcount, 1, __ATOMIC_ACQ_REL);
    MONAD_ASSERT(last_ref > 0, "mismatched acquire/release");
}
