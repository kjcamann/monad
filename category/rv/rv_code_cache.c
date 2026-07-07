#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include <libelf.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/rv/rv_code.h>
#include <category/rv/rv_code_cache.h>

constexpr uint8_t ELF_MAGIC[] = {0x7F, 'E', 'L', 'F'};

alignas(4096) static thread_local uint8_t
    s_validate_code_buf[MONAD_RV_CODE_MAX_SIZE];

struct cache_entry
{
    struct monad_address address;
    uint64_t generation;
    int64_t refcount;
    TAILQ_ENTRY(cache_entry) hash_link;
    TAILQ_ENTRY(cache_entry) lru_link;
    void *code;
    size_t codelen;
    Elf *elf;
};

struct code_token
{
    struct cache_entry *entry;
    uint64_t generation;
};

static_assert(sizeof(struct code_token) <= sizeof(monad_rv_code_token_t));

TAILQ_HEAD(cache_entry_list, cache_entry);

struct monad_rv_code_cache
{
    pthread_rwlock_t lock;
    struct cache_entry_list *buckets;
    struct cache_entry_list lru_list;
    void *code_buf;
    uint32_t bucket_count;
    uint32_t size;
    uint64_t generation_counter;
};

static struct cache_entry_list *get_bucket_chain(
    struct monad_rv_code_cache const *const cc,
    struct monad_address const *const addr)
{
    uint64_t hash;
    __builtin_memcpy(&hash, &addr->bytes[12], sizeof hash);
    return &cc->buckets[hash & (cc->bucket_count - 1)];
}

static struct cache_entry *get_cache_entry(
    struct monad_rv_code_cache *const cc,
    struct monad_address const *const addr)
{
    struct cache_entry *entry;

    // Scan the LRU list backwards, skipping over cache entries which are
    // pinned in place because their outstanding reference count is greater
    // than zero
    TAILQ_FOREACH_REVERSE(entry, &cc->lru_list, cache_entry_list, lru_link)
    {
        if (__atomic_load_n(&entry->refcount, __ATOMIC_ACQUIRE) != 0) {
            continue; // Skip pinned entry
        }
        if (entry->generation > 0) {
            struct cache_entry_list *const bucket =
                get_bucket_chain(cc, &entry->address);
            TAILQ_REMOVE(bucket, entry, hash_link);
            elf_end(entry->elf);
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

int monad_rv_code_cache_create(
    uint8_t size_shift, struct monad_rv_code_cache **cc_p)
{
    int rc;
    struct monad_rv_code_cache *cc;
    struct cache_entry *entries;

    *cc_p = nullptr;
    if (size_shift > MONAD_RV_CODE_CACHE_MAX_SIZE_SHIFT) {
        return EINVAL;
    }
    cc = malloc(sizeof *cc);
    if (cc == nullptr) {
        return errno;
    }
    memset(cc, 0, sizeof *cc);
    rc = pthread_rwlock_init(&cc->lock, nullptr);
    if (rc != 0) {
        return rc;
    }
    cc->size = 1U << size_shift;
    cc->bucket_count = 2 * cc->size;
    cc->generation_counter = 1;
    cc->buckets = calloc(cc->bucket_count, sizeof(struct cache_entry_list));
    if (cc->buckets == nullptr) {
        rc = errno;
        monad_rv_code_cache_destroy(cc);
        return rc;
    }
    cc->code_buf = mmap(
        nullptr,
        cc->size * MONAD_RV_CODE_MAX_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    if (cc->code_buf == MAP_FAILED) {
        rc = errno;
        monad_rv_code_cache_destroy(cc);
        return rc;
    }
    for (size_t i = 0; i < cc->bucket_count; i++) {
        TAILQ_INIT(&cc->buckets[i]);
    }
    TAILQ_INIT(&cc->lru_list);

    entries = calloc(cc->size, sizeof(struct cache_entry));
    if (entries == nullptr) {
        rc = errno;
        monad_rv_code_cache_destroy(cc);
        return rc;
    }
    for (size_t i = 0; i < cc->size; ++i) {
        struct cache_entry *const entry = &entries[i];
        entry->code = (uint8_t *)cc->code_buf + i * MONAD_RV_CODE_MAX_SIZE;
        TAILQ_INSERT_TAIL(&cc->lru_list, entry, lru_link);
    }

    *cc_p = cc;
    return 0;
}

void monad_rv_code_cache_destroy(struct monad_rv_code_cache *cc)
{
    if (cc != nullptr) {
        pthread_rwlock_destroy(&cc->lock);
        munmap(cc->code_buf, MONAD_RV_CODE_MAX_SIZE * cc->size);
        free(cc->buckets);
        free(cc);
    }
}

bool monad_rv_code_cache_lookup(
    struct monad_rv_code_cache *cc, struct monad_address const *addr,
    monad_rv_code_token_t *raw_token)
{
    struct cache_entry_list *bucket;
    struct cache_entry *entry;

    // XXX: need to assert if failure
    pthread_rwlock_rdlock(&cc->lock);
    bucket = get_bucket_chain(cc, addr);
    if (raw_token != nullptr) {
        *raw_token = (monad_rv_code_token_t){};
    }
    TAILQ_FOREACH(entry, bucket, hash_link)
    {
        struct code_token *code_token;
        uint64_t old_generation;

        if (!monad_address_eq(addr, &entry->address)) {
            continue; // Hash collision; keep looking
        }

        code_token = (struct code_token *)raw_token;
        if (code_token == nullptr) {
            // We found the cache entry, but the user does not want to acquire
            // a code token to use it; we're done
            pthread_rwlock_unlock(&cc->lock);
            return true;
        }

        // The normal cache-hit case: we found the entry, and need to move it
        // to the front of the LRU list. To do this, we need to "upgrade" the
        // rwlock to allow writes. pthread rwlocks do not have native lock
        // upgrade support, so we drop the read lock and re-acquire it. Before
        // dropping the lock, we first save the old generation number of the
        // cache entry, so we can check if it got yanked during the time that
        // it was unlocked
        old_generation = __atomic_load_n(&entry->generation, __ATOMIC_ACQUIRE);
        pthread_rwlock_unlock(&cc->lock);

        pthread_rwlock_wrlock(&cc->lock);
        if (__atomic_load_n(&entry->generation, __ATOMIC_ACQUIRE) !=
            old_generation) {
            // cache_entry yanked while the lock was dropped
            pthread_rwlock_unlock(&cc->lock);
            return false;
        }

        // Maintain the LRU ordering
        TAILQ_REMOVE(&cc->lru_list, entry, lru_link);
        TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);
        __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_ACQ_REL);
        code_token->entry = entry;
        code_token->generation = entry->generation;
        pthread_rwlock_unlock(&cc->lock);
        return true;
    }

    pthread_rwlock_unlock(&cc->lock);
    return false;
}

void monad_rv_code_cache_insert_valid(
    struct monad_rv_code_cache *cc, struct monad_address const *addr,
    struct monad_bv db_code, struct monad_rv_code_zstd_decomp *decomp,
    monad_rv_code_token_t *raw_token)
{
    struct cache_entry_list *bucket;
    struct cache_entry *entry;
    monad_rv_validate_result_t validate_result;
    struct code_token *const code_token = (struct code_token *)raw_token;

    if (raw_token != nullptr) {
        *raw_token = (monad_rv_code_token_t){};
    }
    pthread_rwlock_wrlock(&cc->lock);
    entry = get_cache_entry(cc, addr);
    if (__builtin_memcmp(
            db_code.begin + sizeof(struct monad_rv_code_header),
            ELF_MAGIC,
            sizeof ELF_MAGIC) == 0) {
        entry->codelen = monad_bv_len(db_code);
        validate_result = MONAD_RV_VALIDATE_HAS_ELF_MAGIC;
    }
    else {
        entry->codelen = MONAD_RV_CODE_MAX_SIZE;
        validate_result = monad_rv_decompress_code(
            db_code, entry->code, &entry->codelen, decomp, nullptr, nullptr);
        MONAD_ASSERT(validate_result == MONAD_RV_VALIDATE_HAS_ELF_MAGIC);
    }

    entry->elf = elf_memory((char *)entry->code, entry->codelen);
    MONAD_ASSERT(entry->elf != nullptr);
    if (code_token != nullptr) {
        __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_ACQ_REL);
        code_token->entry = entry;
        code_token->generation = entry->generation;
    }

    bucket = get_bucket_chain(cc, addr);
    TAILQ_INSERT_HEAD(bucket, entry, hash_link);
    TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);
    pthread_rwlock_unlock(&cc->lock);
}

monad_rv_validate_result_t monad_rv_code_cache_try_insert_new(
    struct monad_rv_code_cache *cc, struct monad_address const *addr,
    struct monad_bv txn_data, struct monad_rv_code_sections *sections,
    bool strict_rv64, struct monad_rv_code_zstd_decomp *decomp,
    monad_rv_code_token_t *raw_token)
{
    struct cache_entry_list *bucket;
    struct cache_entry *entry;
    void const *code;
    size_t codelen;
    monad_rv_validate_result_t validate_result;
    Elf *elf;
    struct code_token *const code_token = (struct code_token *)raw_token;

    validate_result = monad_rv_parse_create_txn_data(txn_data, sections);
    switch (validate_result) {
    case MONAD_RV_VALIDATE_HAS_ELF_MAGIC:
        [[fallthrough]];
    case MONAD_RV_VALIDATE_HAS_ZSTD_MAGIC:
        break; // Handled in main body of the function

    default:
        return validate_result; // Error, will not proceed
    }

    if (validate_result == MONAD_RV_VALIDATE_HAS_ZSTD_MAGIC) {
        codelen = MONAD_RV_CODE_MAX_SIZE;
        code = s_validate_code_buf;
        validate_result = monad_rv_decompress_code(
            sections->db_blob,
            s_validate_code_buf,
            &codelen,
            decomp,
            nullptr,
            nullptr);
    }
    else {
        code = sections->code_blob.begin;
        codelen = monad_bv_len(sections->code_blob);
    }

    if (validate_result != MONAD_RV_VALIDATE_HAS_ELF_MAGIC) {
        return validate_result;
    }

    validate_result = monad_rv_validate_code(code, codelen, strict_rv64, &elf);
    if (validate_result != MONAD_RV_VALIDATE_OK) {
        return validate_result;
    }

    pthread_rwlock_wrlock(&cc->lock);
    entry = get_cache_entry(cc, addr);
    entry->codelen = codelen;
    // XXX: don't want to memcpy(3) while wrlock'ed
    memcpy(entry->code, code, entry->codelen);
    bucket = get_bucket_chain(cc, addr);
    TAILQ_INSERT_HEAD(bucket, entry, hash_link);
    TAILQ_INSERT_HEAD(&cc->lru_list, entry, lru_link);
    entry->elf = elf;
    if (code_token != nullptr) {
        __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_ACQ_REL);
        code_token->entry = entry;
        code_token->generation = entry->generation;
    }
    pthread_rwlock_unlock(&cc->lock);
    return MONAD_RV_VALIDATE_OK;
}

void *monad_rv_code_token_native_handle(monad_rv_code_token_t raw_token)
{
    uint64_t token_gen;
    struct code_token const *const code_token =
        (struct code_token const *)&raw_token;

    token_gen =
        __atomic_load_n(&code_token->entry->generation, __ATOMIC_ACQUIRE);
    if (code_token->generation != token_gen) {
        return nullptr;
    }
    return code_token->entry->elf;
}

void monad_rv_code_token_release(monad_rv_code_token_t raw_token)
{
    int64_t last_ref;
    struct code_token const *const code_token =
        (struct code_token const *)&raw_token;

    last_ref =
        __atomic_fetch_sub(&code_token->entry->refcount, 1, __ATOMIC_ACQ_REL);
    MONAD_ASSERT(last_ref > 0, "mismatched acquire/release");
}
