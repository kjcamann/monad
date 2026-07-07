#pragma once

#include <stddef.h>
#include <sys/queue.h>

#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>

struct mem_zone;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file
 *
 * A simple bucket-chained hash table where the keys are monad_bytes32 and
 * the values are either stored inline (in a small byte buffer) or they are
 * stored externally and referenced by pointer. This hash table should only
 * be used with bytes32 keys that are known to be uniformly distributed.
 */

constexpr float DEFAULT_MAX_LOAD_FACTOR = 1.0f;
constexpr size_t BYTES32_MAP_INLINE_BUF_SIZE = 96;

union bytes32_map_value
{
    uint8_t buf[BYTES32_MAP_INLINE_BUF_SIZE];
    struct monad_bytes32 b32;
    struct monad_bv bytes;
    void *ptr;
};

// An entry in the map, i.e., a single key-value pair; these are allocated from
// a mem_zone pool and have stable addresses (in-use entries are not moved in
// memory even if the table is rehashed)
struct bytes32_map_entry
{
    TAILQ_ENTRY(bytes32_map_entry) bucket_link;
    struct monad_bytes32 key;
    TAILQ_ENTRY(bytes32_map_entry) all_link;
    union bytes32_map_value value;
};

typedef void bytes32_map_visit_entry_fn(struct bytes32_map_entry *, void *);

TAILQ_HEAD(bytes32_map_entry_list, bytes32_map_entry);

struct bytes32_map
{
    struct bytes32_map_entry_list *buckets;
    struct bytes32_map_entry_list all_entries;
    size_t bucket_count;
    size_t entry_count;
    float max_load_factor;
    struct mem_zone *entry_zone;
};

int bytes32_map_init(
    struct bytes32_map *, size_t bucket_count, float max_load_factor,
    struct mem_zone *);

void bytes32_map_clear(
    struct bytes32_map *, bytes32_map_visit_entry_fn *, void *);

void bytes32_map_release(
    struct bytes32_map *, bytes32_map_visit_entry_fn *, void *);

struct bytes32_map_entry *
bytes32_map_find(struct bytes32_map const *, struct monad_bytes32 const *);

int bytes32_map_try_insert(
    struct bytes32_map *, struct monad_bytes32 const *, bool *,
    struct bytes32_map_entry **);

bool bytes32_map_erase(
    struct bytes32_map *, struct monad_bytes32 const *,
    union bytes32_map_value *);

// Call before bulk inserting to avoid multiple rehashes
int bytes32_map_rehash(struct bytes32_map *, size_t expected_entry_count);

[[gnu::always_inline]] static struct monad_bytes32
bytes32_map_key_from_addr(struct monad_address const *const addr)
{
    struct monad_bytes32 key = {};
    __builtin_memcpy((uint8_t *)&key + 12, addr, sizeof *addr);
    return key;
}

[[gnu::always_inline]] static struct monad_address const *
bytes32_map_key_to_addr(struct monad_bytes32 const *const b32)
{
    return (struct monad_address const *)(b32->bytes + 12);
}

#ifdef __cplusplus
} // extern "C"
#endif
