#include <errno.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/bytes32_map.h>
#include <category/core/likely.h>
#include <category/core/mem/mem_zone.h>

/*
 * We assume that the bytes32 keys are already uniformly distributed, and thus
 * are effectively already hashed. Consequently:
 *
 *   - The "hash" function just extracts the last 8 bytes of the 32 byte key.
 *     It is important that this be the last 8 bytes, since this map is also
 *     used to store address keys, where the addresses are copied into the last
 *     20 bytes of a `monad_bytes32`, per the Solidity ABI
 *
 *   - Because the key space has a uniform distribution, we can use a
 *     power-of-2-sized bucket table instead of a prime-number-sized one; this
 *     makes the resize logic easier
 */

static struct bytes32_map_entry_list *get_bucket_chain(
    struct bytes32_map const *const m, struct monad_bytes32 const *const key)
{
    uint64_t hash;
    __builtin_memcpy(&hash, &key->bytes[24], sizeof hash);
    return &m->buckets[hash & (m->bucket_count - 1)];
}

static int
rehash_buckets(struct bytes32_map *const m, size_t const bucket_count)
{
    struct bytes32_map_entry *entry;
    struct bytes32_map_entry_list *bucket_chain;

    free(m->buckets);
    m->bucket_count = stdc_bit_ceil(bucket_count);
    m->buckets = (struct bytes32_map_entry_list *)calloc(
        m->bucket_count, sizeof(struct bytes32_map_entry_list));
    if (m->buckets == nullptr) {
        return errno;
    }
    for (size_t b = 0; b < m->bucket_count; ++b) {
        TAILQ_INIT(&m->buckets[b]);
    }
    TAILQ_FOREACH(entry, &m->all_entries, all_link)
    {
        bucket_chain = get_bucket_chain(m, &entry->key);
        TAILQ_INSERT_TAIL(bucket_chain, entry, bucket_link);
    }
    return 0;
}

int bytes32_map_init(
    struct bytes32_map *const m, size_t const bucket_count,
    float const max_load_factor, struct mem_zone *const entry_zone)
{
    MONAD_ASSERT(max_load_factor != 0);
    __builtin_memset(m, 0, sizeof *m);
    TAILQ_INIT(&m->all_entries);
    m->max_load_factor = max_load_factor;
    m->entry_zone = entry_zone;
    return rehash_buckets(m, bucket_count);
}

void bytes32_map_clear(
    struct bytes32_map *const m, bytes32_map_visit_entry_fn *const visit,
    void *const visit_ctx)
{
    struct bytes32_map_entry *entry;

    if (MONAD_UNLIKELY(m->buckets == nullptr)) {
        return;
    }
    if (visit != nullptr) {
        TAILQ_FOREACH(entry, &m->all_entries, all_link)
        {
            visit(entry, visit_ctx);
        }
    }
    while ((entry = TAILQ_FIRST(&m->all_entries)) != nullptr) {
        TAILQ_REMOVE(&m->all_entries, entry, all_link);
        mem_zone_free(m->entry_zone, entry);
    }
    for (size_t b = 0; b < m->bucket_count; ++b) {
        TAILQ_INIT(&m->buckets[b]);
    }
    m->entry_count = 0;
}

void bytes32_map_release(
    struct bytes32_map *const m, bytes32_map_visit_entry_fn *const visit,
    void *const visit_ctx)
{
    if (m->buckets != nullptr) {
        bytes32_map_clear(m, visit, visit_ctx);
        free(m->buckets);
        m->buckets = nullptr;
    }
}

struct bytes32_map_entry *bytes32_map_find(
    struct bytes32_map const *const m, struct monad_bytes32 const *const key)
{
    struct bytes32_map_entry *entry;
    struct bytes32_map_entry_list *bucket_chain;

    if (MONAD_UNLIKELY(m->buckets == nullptr)) {
        return nullptr;
    }
    bucket_chain = get_bucket_chain(m, key);
    TAILQ_FOREACH(entry, bucket_chain, bucket_link)
    {
        if (monad_bytes32_eq(&entry->key, key)) {
            return entry;
        }
    }
    return nullptr;
}

int bytes32_map_try_insert(
    struct bytes32_map *const m, struct monad_bytes32 const *const key,
    bool *const inserted, struct bytes32_map_entry **entry_p)
{
    int rc;
    struct bytes32_map_entry *entry;
    struct bytes32_map_entry_list *bucket_chain;

    *entry_p = nullptr;
    if (MONAD_UNLIKELY(m->buckets == nullptr)) {
        rc = rehash_buckets(m, m->bucket_count);
        if (MONAD_UNLIKELY(rc != 0)) {
            return rc;
        }
    }
    if ((float)(m->entry_count + 1) / (float)m->bucket_count >
        m->max_load_factor) {
        rc = rehash_buckets(m, m->bucket_count * 2);
        if (MONAD_UNLIKELY(rc != 0)) {
            return rc;
        }
    }

    bucket_chain = get_bucket_chain(m, key);
    TAILQ_FOREACH(entry, bucket_chain, bucket_link)
    {
        if (monad_bytes32_eq(&entry->key, key)) {
            if (inserted != nullptr) {
                *inserted = false;
            }
            *entry_p = entry;
            return 0;
        }
    }

    rc = mem_zone_alloc(m->entry_zone, (void **)&entry);
    if (MONAD_UNLIKELY(rc != 0)) {
        return rc;
    }
    entry->key = *key;
    TAILQ_INSERT_TAIL(bucket_chain, entry, bucket_link);
    TAILQ_INSERT_TAIL(&m->all_entries, entry, all_link);
    ++m->entry_count;
    if (inserted != nullptr) {
        *inserted = true;
    }
    *entry_p = entry;
    return 0;
}

bool bytes32_map_erase(
    struct bytes32_map *const m, struct monad_bytes32 const *const key,
    union bytes32_map_value *const value)
{
    struct bytes32_map_entry *entry;
    struct bytes32_map_entry_list *bucket_chain;

    if (MONAD_UNLIKELY(m->buckets == nullptr)) {
        return false;
    }
    bucket_chain = get_bucket_chain(m, key);
    TAILQ_FOREACH(entry, bucket_chain, bucket_link)
    {
        if (monad_bytes32_eq(&entry->key, key)) {
            TAILQ_REMOVE(bucket_chain, entry, bucket_link);
            TAILQ_REMOVE(&m->all_entries, entry, all_link);
            if (value != nullptr) {
                *value = entry->value;
            }
            mem_zone_free(m->entry_zone, entry);
            --m->entry_count;
            return true;
        }
    }
    return false;
}

int bytes32_map_rehash(
    struct bytes32_map *const m, size_t const expected_entry_count)
{
    size_t min_bucket_count;

    if (((float)expected_entry_count / (float)m->bucket_count) <
        m->max_load_factor) {
        // XXX: this prevents spurious rehashings, but it also means we can
        // never shrink
        return 0;
    }
    min_bucket_count =
        (size_t)((float)expected_entry_count * m->max_load_factor);
    return rehash_buckets(m, stdc_bit_ceil(min_bucket_count) * 2);
}
