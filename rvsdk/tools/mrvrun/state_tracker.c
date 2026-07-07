#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <sysexits.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/bytes32_map.h>
#include <category/core/byteview.h>
#include <category/core/keccak.h>
#include <category/core/mem/mem_zone.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

#include <evmc/evmc.h>

#include "mem_state_db.h"
#include "state_db.h"
#include "state_tracker.h"

constexpr size_t EXPECTED_ACCOUNTS = 8;
constexpr size_t EXPECTED_CODE_ACCOUNTS = 4;
constexpr size_t EXPECTED_STORAGE_SLOTS_PER_ACCOUNT = 8;

enum state_tracker_mem_zone
{
    Z_MAP_ENTRY,
    Z_ACCOUNT_ACCESS,
    Z_STORAGE_ACCESS,
    Z_STORAGE_MAP,
    Z_STATE_SCOPE,
    Z_TXN_LOG,
    Z_ZONE_COUNT,
};

struct mem_zone_config const STATE_TRACKER_MEM_ZONES[Z_ZONE_COUNT] = {
    [Z_MAP_ENTRY] =
        {
            .name = "state_tracker map entries",
            .size = sizeof(struct bytes32_map_entry),
            .align = alignof(struct bytes32_map_entry),
        },

    [Z_ACCOUNT_ACCESS] =
        {
            .name = "state_tracker account accesses",
            .size = sizeof(struct account_access),
            .align = alignof(struct account_access),
        },

    [Z_STORAGE_ACCESS] =
        {
            .name = "state_tracker storage accesses",
            .size = sizeof(struct storage_access),
            .align = alignof(struct storage_access),
        },

    [Z_STORAGE_MAP] =
        {
            .name = "state_tracker storage maps",
            .size = sizeof(struct storage_map),
            .align = alignof(struct storage_map),
        },

    [Z_TXN_LOG] =
        {
            .name = "state_tracker txn logs",
            .size = sizeof(struct txn_log),
            .align = alignof(struct txn_log),
        },

    [Z_STATE_SCOPE] =
        {
            .name = "state_tracker scopes",
            .size = sizeof(struct state_scope),
            .align = alignof(struct state_scope),
        },
};

struct state_tracker_impl
{
    struct mem_zone *mem_zones[Z_ZONE_COUNT];
};

static void *
mz_alloc(struct state_tracker *const st, enum state_tracker_mem_zone const z)
{
    void *ptr;
    int const rc = mem_zone_alloc(st->impl->mem_zones[z], &ptr);
    if (rc != 0) {
        errno = rc;
        err(EX_OSERR, "mem_zone_alloc from state tracker zone %u failed", z);
    }
    return ptr;
}

static void mz_free(
    struct state_tracker *const st, enum state_tracker_mem_zone const z,
    void *const p)
{
    mem_zone_free(st->impl->mem_zones[z], p);
}

static struct state_scope *get_current_scope(struct state_tracker *const st)
{
    return SLIST_FIRST(&st->scope_stack);
}

static struct storage_access *
find_first_storage_access(struct storage_access *const prev_access)
{
    struct storage_access *s = prev_access;
    while (s->prev_access != nullptr) {
        s = s->prev_access;
    }
    return s;
}

static enum evmc_storage_status compute_storage_status(
    struct storage_access const *const original,
    struct storage_access const *const current,
    struct storage_access const *const new)
{
    // XXX: we have all the info needed to compute this, but it's incredibly
    // complicated and the gas calculations aren't right anyway; ignore for now
    return EVMC_STORAGE_ASSIGNED;
}

static struct account_access *alloc_account_access(
    struct state_tracker *const st, state_access_type_t const access_type,
    struct state_access_meta const *const meta,
    struct account_access *const prev_access)
{
    struct account_access *const access =
        (struct account_access *)mz_alloc(st, Z_ACCOUNT_ACCESS);
    access->type = access_type;
    access->merge_depth = 0;
    access->prev_access = prev_access;
    access->meta = *meta;
    return access;
}

static inline struct account_access *insert_account_access(
    struct account_access *const access,
    struct state_scope_account *const account)
{
    TAILQ_INSERT_TAIL(&account->local_accesses, access, local_link);
    TAILQ_INSERT_TAIL(&account->merged_accesses, access, merged_link);
    access->merged_account = access->local_account = account;
    return access;
}

static struct state_scope_account *create_account_in_scope(
    struct state_scope *const scope, struct monad_bytes32 const *const addr_key)
{
    struct bytes32_map_entry *map_entry;
    struct state_scope_account *account;
    bool inserted;

    (void)bytes32_map_try_insert(
        &scope->accounts, addr_key, &inserted, &map_entry);
    MONAD_ASSERT(map_entry != nullptr);
    MONAD_ASSERT(inserted, "invariant is that account does not already exist");
    account = (struct state_scope_account *)map_entry->value.buf;
    TAILQ_INIT(&account->local_accesses);
    TAILQ_INIT(&account->merged_accesses);
    account->storage = nullptr;
    account->origin_scope = scope;
    account->acct_map_entry = map_entry;
    return account;
}

// Return the closest scope that has accessed an account (and set *account_p to
// point at the account)
static struct state_scope *find_prev_scope_for_account(
    struct state_tracker *const st, struct state_scope *const start_scope,
    struct monad_bytes32 const *const addr_key,
    struct state_scope_account **const account_p)
{
    struct bytes32_map_entry *map_entry;
    struct state_scope *search_scope;

    MONAD_ASSERT(start_scope != nullptr, "looking up without an active scope");
    search_scope = start_scope;

    // Walk up the scope chain, looking for the most recent scope where we saw
    // this account key being accessed
SearchAgain:
    map_entry = bytes32_map_find(&search_scope->accounts, addr_key);
    if (map_entry == nullptr) {
        search_scope = state_scope_prev(search_scope);
        if (search_scope == nullptr) {
            // No more scopes to search, we're done
            *account_p = nullptr;
            return nullptr;
        }
        goto SearchAgain;
    }
    *account_p = (struct state_scope_account *)map_entry->value.buf;
    return search_scope;
}

static struct account_access *get_or_inject_prev_account_access(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const addr_key)
{
    struct account_access *import_access;
    struct monad_address const *addr;
    struct state_scope *cur_scope;
    struct state_scope *prev_scope;
    struct state_scope_account *account;
    state_db_access_result_t db_result;

    cur_scope = get_current_scope(st);
    MONAD_ASSERT(cur_scope != nullptr, "looking up without an active scope");
    prev_scope = find_prev_scope_for_account(st, cur_scope, addr_key, &account);

    if (prev_scope != nullptr) {
        // Account is present in an earlier scope, return most recent access
        return (struct account_access *)TAILQ_LAST(
            &account->merged_accesses, account_access_list);
    }

    // Account has never been seen before; import it from the database directly
    // into the current scope
    account = create_account_in_scope(cur_scope, addr_key);
    import_access = alloc_account_access(st, SA_TYPE_DB_IMPORT, meta, nullptr);
    addr = bytes32_map_key_to_addr(addr_key);
    db_result = state_db_get_account(
        st->prestate_db, meta, addr, nullptr, &import_access->acct_state);
    import_access->empty = db_result == STATE_DB_NOT_FOUND;
    if (import_access->empty) {
        import_access->acct_state = MONAD_ETH_EMPTY_ACCOUNT;
    }
    return insert_account_access(import_access, account);
}

// Get the most recent account access in the current scope; if there isn't an
// access in this scope, inject a "cached" access record (one with type
// SA_TYPE_CACHE_PROXY) that references the previous access in some parent
// scope; a previous access will always exist, because we'll inject one by
// importing from the prestate database (SA_TYPE_DB_IMPORT) if needed
static struct account_access *get_or_create_account_access(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const addr_key)
{
    struct account_access *prev_access;
    struct account_access *cache_access;
    struct state_scope *cur_scope;
    struct state_scope_account *account;

    cur_scope = get_current_scope(st);
    prev_access = get_or_inject_prev_account_access(st, meta, addr_key);
    if (prev_access->merged_account->origin_scope == cur_scope) {
        // Previous access is in the current scope; we're done
        return prev_access;
    }

    // Previous access is not in the current scope; inject a CACHE_PROXY access
    // that caches the value found in an earlier scope into the current one
    account = create_account_in_scope(cur_scope, addr_key);
    cache_access =
        alloc_account_access(st, SA_TYPE_CACHE_PROXY, meta, prev_access);
    cache_access->acct_state = prev_access->acct_state;
    cache_access->empty = prev_access->empty;
    return insert_account_access(cache_access, account);
}

static struct storage_access *alloc_storage_access(
    struct state_tracker *const st, state_access_type_t const access_type,
    struct state_access_meta const *const meta,
    struct storage_access *const prev_access)
{
    struct storage_access *const access =
        (struct storage_access *)mz_alloc(st, Z_STORAGE_ACCESS);
    access->type = access_type;
    access->merge_depth = 0;
    access->prev_access = prev_access;
    access->meta = *meta;
    return access;
}

static inline struct storage_access *insert_storage_access(
    struct storage_access *const access,
    struct state_scope_storage_slot *const slot)
{
    TAILQ_INSERT_TAIL(&slot->local_accesses, access, local_link);
    TAILQ_INSERT_TAIL(&slot->merged_accesses, access, merged_link);
    access->merged_slot = access->local_slot = slot;
    return access;
}

static struct state_scope_storage_slot *create_storage_slot(
    struct state_scope_account *const account,
    struct monad_bytes32 const *const original_key,
    struct monad_bytes32 const *const hashed_key)
{
    struct bytes32_map_entry *map_entry;
    struct state_scope_storage_slot *slot;
    bool inserted;

    (void)bytes32_map_try_insert(
        &account->storage->slots, hashed_key, &inserted, &map_entry);
    MONAD_ASSERT(map_entry != nullptr);
    MONAD_ASSERT(inserted, "invariant is that slot does not already exist");
    slot = (struct state_scope_storage_slot *)&map_entry->value.buf;
    TAILQ_INIT(&slot->local_accesses);
    TAILQ_INIT(&slot->merged_accesses);
    slot->original_key = *original_key;
    slot->account = account;
    slot->slot_map_entry = map_entry;
    return slot;
}

static struct state_scope *find_prev_scope_for_storage(
    struct state_tracker *const st, struct state_scope *const start_scope,
    struct monad_bytes32 const *const addr_key,
    struct monad_bytes32 const *const key,
    struct state_scope_account **const account_p,
    struct state_scope_storage_slot **const slot_p)
{
    struct bytes32_map_entry *map_entry;
    struct state_scope *prev_scope;
    struct state_scope *search_scope;
    struct storage_map *storage;

    search_scope = start_scope;

    // Walk up the scope chain, looking for the most recent scope where this
    // account has an associated storage map containing the given key
SearchAgain:
    prev_scope =
        find_prev_scope_for_account(st, search_scope, addr_key, account_p);
    if (*account_p == nullptr) {
        // No more accounts to look through, we're done
        *slot_p = nullptr;
        return nullptr;
    }
    storage = (*account_p)->storage;
    if (storage == nullptr ||
        (map_entry = bytes32_map_find(&storage->slots, key)) == nullptr) {
        // This instance of the account either has no storage map or the key
        // is missing; continue searching the parent scopes
        search_scope = state_scope_prev(prev_scope);
        goto SearchAgain;
    }
    *slot_p = (struct state_scope_storage_slot *)&map_entry->value.buf;
    return prev_scope;
}

// An account's storage_map is lazily allocated: it is only created when an
// account needs to track at least one storage key state diff; this function
// ensures the account exists in the current scope and has a storage map
static struct state_scope_account *touch_account_to_access_storage(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const addr_key)
{
    struct state_scope_account *account;

    // Poke at the account as though we are accessing it; this is done so that
    // the account access list always has at least one access entry (in this
    // case, it will be SA_TYPE_CACHE_PROXY if `get_or_create_account_access`
    // needed to inject it)
    account = get_or_create_account_access(st, meta, addr_key)->local_account;
    if (account->storage == nullptr) {
        // Lazy initialization of account's storage map
        struct state_scope *const cur_scope = get_current_scope(st);
        account->storage = (struct storage_map *)mz_alloc(st, Z_STORAGE_MAP);
        bytes32_map_init(
            &account->storage->slots,
            EXPECTED_STORAGE_SLOTS_PER_ACCOUNT,
            DEFAULT_MAX_LOAD_FACTOR,
            st->impl->mem_zones[Z_MAP_ENTRY]);
        TAILQ_INSERT_TAIL(&cur_scope->storage_maps, account->storage, next_map);
    }
    return account;
}

static struct storage_access *get_or_inject_prev_storage_access(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const addr_key,
    struct monad_bytes32 const *const original_key,
    struct monad_bytes32 const *const hashed_key)
{
    struct monad_address const *addr;
    struct state_scope *cur_scope;
    struct state_scope *prev_scope;
    struct state_scope_account *account;
    struct state_scope_storage_slot *slot;
    struct storage_access *import_access;
    state_db_access_result_t db_result;

    cur_scope = get_current_scope(st);
    prev_scope = find_prev_scope_for_storage(
        st, cur_scope, addr_key, hashed_key, &account, &slot);
    if (prev_scope != nullptr) {
        // Storage slot was accessed in an earlier scope; return the most recent
        // state access in that scope
        return (struct storage_access *)TAILQ_LAST(
            &slot->merged_accesses, storage_access_list);
    }

    // Make sure account exists in the current scope and has a storage map
    account = touch_account_to_access_storage(st, meta, addr_key);

    // Storage slot has never been seen before; import its value from the db
    slot = create_storage_slot(account, original_key, hashed_key);
    import_access = alloc_storage_access(
        st,
        SA_TYPE_DB_IMPORT,
        meta,
        /*prev_access*/ nullptr);
    addr = bytes32_map_key_to_addr(&account->acct_map_entry->key);
    db_result = state_db_get_storage(
        st->prestate_db,
        meta,
        addr,
        nullptr,
        original_key,
        &import_access->value);
    import_access->empty = db_result == STATE_DB_NOT_FOUND;
    if (import_access->empty) {
        import_access->value = MONAD_BYTES32_ZERO;
    }
    return insert_storage_access(import_access, slot);
}

static struct storage_access *get_or_create_storage_access(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const addr_key,
    struct monad_bytes32 const *const original_key,
    struct monad_bytes32 const *const hashed_key)
{
    struct state_scope *cur_scope;
    struct state_scope_account *account;
    struct state_scope_storage_slot *slot;
    struct storage_access *cache_access;
    struct storage_access *prev_access;

    prev_access = get_or_inject_prev_storage_access(
        st, meta, addr_key, original_key, hashed_key);
    cur_scope = get_current_scope(st);
    if (prev_access->merged_slot->account->origin_scope == cur_scope) {
        // Previous access is already in this scope
        return prev_access;
    }
    account = touch_account_to_access_storage(st, meta, addr_key);

    slot = create_storage_slot(account, original_key, hashed_key);
    cache_access =
        alloc_storage_access(st, SA_TYPE_CACHE_PROXY, meta, prev_access);
    cache_access->value = prev_access->value;
    cache_access->empty = prev_access->empty;
    return insert_storage_access(cache_access, slot);
}

static void init_mem_zones(struct state_tracker_impl *const impl)
{
    for (unsigned z = 0; z < Z_ZONE_COUNT; ++z) {
        int const rc = mem_zone_create(
            &STATE_TRACKER_MEM_ZONES[z], nullptr, &impl->mem_zones[z]);
        if (rc != 0) {
            errno = rc;
            err(EX_OSERR,
                "mem_zone_create for %s failed",
                STATE_TRACKER_MEM_ZONES[z].name);
        }
    }
}

static void merge_account_storage_slot(
    struct state_scope_account *const cur_account,
    struct monad_bytes32 const *const key,
    struct state_scope_storage_slot *const popped_slot)
{
    struct bytes32_map_entry *map_entry;
    struct state_scope_storage_slot *cur_slot;
    struct storage_access *access;
    bool inserted;

    (void)bytes32_map_try_insert(
        &cur_account->storage->slots, key, &inserted, &map_entry);
    MONAD_ASSERT(map_entry != nullptr);
    cur_slot = (struct state_scope_storage_slot *)map_entry->value.buf;
    if (inserted) {
        TAILQ_INIT(&cur_slot->local_accesses);
        TAILQ_INIT(&cur_slot->merged_accesses);
        cur_slot->original_key = popped_slot->original_key;
        cur_slot->account = cur_account;
        cur_slot->slot_map_entry = map_entry;
    }
    TAILQ_FOREACH(access, &popped_slot->local_accesses, local_link)
    {
        ++access->merge_depth;
        access->merged_slot = cur_slot;
    }
    TAILQ_CONCAT(
        &cur_slot->merged_accesses, &popped_slot->merged_accesses, merged_link);
}

static void merge_account_storage(
    struct state_tracker *const st,
    struct state_scope_account *const cur_account,
    struct state_scope_account *const popped_account)
{
    // XXX: not doing the bucket_count / load factor math correctly here, just
    // assuming max_load_factor = 1.0f, does not matter for now...
    struct bytes32_map_entry *pop_map_entry;
    size_t expected_entry_count;
    bool inserted;
    size_t const cur_storage_size =
        cur_account->storage != nullptr
            ? cur_account->storage->slots.entry_count
            : 0;

    if (popped_account->storage == nullptr) {
        // Nothing to do
        return;
    }

    // The account being merged has storage diffs and the merge target storage
    // map needs to hold them; lazily create the map or rehash it if necessary
    expected_entry_count =
        cur_storage_size + popped_account->storage->slots.entry_count;
    if (cur_account->storage == nullptr) {
        cur_account->storage =
            (struct storage_map *)mz_alloc(st, Z_STORAGE_MAP);
        bytes32_map_init(
            &cur_account->storage->slots,
            expected_entry_count,
            DEFAULT_MAX_LOAD_FACTOR,
            st->impl->mem_zones[Z_MAP_ENTRY]);
        TAILQ_INSERT_TAIL(
            &cur_account->origin_scope->storage_maps,
            cur_account->storage,
            next_map);
    }
    else {
        bytes32_map_rehash(&cur_account->storage->slots, expected_entry_count);
    }

    // Walk over all slots in the popped account's storage map and merge the
    // access lists of each one
    TAILQ_FOREACH(
        pop_map_entry, &popped_account->storage->slots.all_entries, all_link)
    {
        struct state_scope_storage_slot *const slot =
            (struct state_scope_storage_slot *)pop_map_entry->value.buf;
        merge_account_storage_slot(cur_account, &pop_map_entry->key, slot);
    }
}

static void merge_account(
    struct state_tracker *const st, struct state_scope *const cur_scope,
    struct state_scope_account *const popped_account)
{
    struct monad_bytes32 const *addr_key;
    struct account_access *access;
    struct bytes32_map_entry *map_entry;
    struct state_scope_account *cur_account;
    bool inserted;

    // Look up the same account from the popped scope, in the current scope
    addr_key = &popped_account->acct_map_entry->key;
    (void)bytes32_map_try_insert(
        &cur_scope->accounts, addr_key, &inserted, &map_entry);
    MONAD_ASSERT(map_entry != nullptr);
    cur_account = (struct state_scope_account *)map_entry->value.buf;

    if (inserted) {
        // This account isn't in the current scope; create it
        TAILQ_INIT(&cur_account->local_accesses);
        TAILQ_INIT(&cur_account->merged_accesses);
        cur_account->storage = nullptr;
        cur_account->origin_scope = cur_scope;
        cur_account->acct_map_entry = map_entry;
    }

    // Reseat the `merged_account` field in the popped account accesses to refer
    // to the current account, then merge the accesses lists
    TAILQ_FOREACH(access, &popped_account->local_accesses, local_link)
    {
        ++access->merge_depth;
        access->merged_account = cur_account;
    }
    TAILQ_CONCAT(
        &cur_account->merged_accesses,
        &popped_account->merged_accesses,
        merged_link);

    merge_account_storage(st, cur_account, popped_account);
}

static void commit_scope(
    struct state_tracker *const st, struct state_scope *const pop_scope)
{
    struct bytes32_map_entry *account_map_entry;
    struct state_scope *cur_scope;
    struct txn_log *log;

    cur_scope = get_current_scope(st);
    TAILQ_FOREACH(account_map_entry, &pop_scope->accounts.all_entries, all_link)
    {
        struct state_scope_account *const popped_account =
            (struct state_scope_account *)account_map_entry->value.buf;
        merge_account(st, cur_scope, popped_account);
    }

    STAILQ_FOREACH(log, &pop_scope->local_logs, local_link)
    {
        log->merged_scope = cur_scope;
    }
    STAILQ_CONCAT(&cur_scope->merged_logs, &pop_scope->merged_logs);
}

static void
release_storage_entry(struct bytes32_map_entry *const entry, void *const ctx)
{
    struct state_scope_storage_slot *slot;
    struct storage_access *access;
    struct state_tracker *const st = (struct state_tracker *)ctx;

    slot = (struct state_scope_storage_slot *)entry->value.buf;
    while ((access = TAILQ_FIRST(&slot->local_accesses)) != nullptr) {
        TAILQ_REMOVE(&slot->local_accesses, access, local_link);
        mz_free(st, Z_STORAGE_ACCESS, access);
    }
    TAILQ_INIT(&slot->merged_accesses);
}

static void release_scope_account_entry(
    struct bytes32_map_entry *const entry, void *const ctx)
{
    struct account_access *access;
    struct state_scope_account *account;
    struct state_scope *const scope = (struct state_scope *)ctx;
    struct state_tracker *const st = scope->tracker;

    account = (struct state_scope_account *)&entry->value.buf;
    while ((access = TAILQ_FIRST(&account->local_accesses)) != nullptr) {
        TAILQ_REMOVE(&account->local_accesses, access, local_link);
        mz_free(st, Z_ACCOUNT_ACCESS, access);
    }
    TAILQ_INIT(&account->merged_accesses);

    if (account->storage != nullptr) {
        bytes32_map_clear(&account->storage->slots, &release_storage_entry, st);
        TAILQ_REMOVE(&scope->storage_maps, account->storage, next_map);
        mz_free(st, Z_STORAGE_MAP, account->storage);
    }
}

static void
release_code_map_entry(struct bytes32_map_entry *const entry, void *const ctx)
{
    struct monad_bv const *const code = &entry->value.bytes;
    free((void *)code->begin);
}

static state_db_access_result_t st_get_account(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_address const *const addr, state_db_hint_t *,
    struct monad_eth_account_state *const acct_state)
{
    struct account_access *read_access;
    struct account_access *prev_access;
    struct monad_bytes32 addr_key;
    struct state_tracker *const st = (struct state_tracker *)self;

    addr_key = bytes32_map_key_from_addr(addr);

    // Ensure account is injected into this scope
    prev_access = get_or_create_account_access(st, meta, &addr_key);

    // Append a READ access entry
    read_access = alloc_account_access(st, SA_TYPE_READ, meta, prev_access);
    read_access->empty = prev_access->empty;
    read_access->acct_state = prev_access->acct_state;
    insert_account_access(read_access, prev_access->local_account);

    // Copy out the value
    if (acct_state != nullptr) {
        *acct_state = read_access->acct_state;
    }
    return read_access->empty ? STATE_DB_NOT_FOUND : STATE_DB_SUCCESS;
}

static state_db_access_result_t st_get_storage(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_address const *const addr, state_db_hint_t const *,
    struct monad_bytes32 const *const original_key,
    struct monad_bytes32 *const value)
{
    struct monad_bytes32 addr_key;
    struct monad_bytes32 hashed_key;
    struct storage_access *read_access;
    struct storage_access *prev_access;
    struct state_tracker *const st = (struct state_tracker *)self;

    addr_key = bytes32_map_key_from_addr(addr);
    keccak256(original_key, sizeof *original_key, hashed_key.bytes);

    // Ensure storage slot is injected into this scope
    prev_access = get_or_create_storage_access(
        st, meta, &addr_key, original_key, &hashed_key);

    // Append a READ access entry
    read_access = alloc_storage_access(st, SA_TYPE_READ, meta, prev_access);
    read_access->empty = prev_access->empty;
    read_access->value = prev_access->value;

    // Copy out the value
    if (value != nullptr) {
        *value = read_access->value;
    }
    return read_access->empty ? STATE_DB_NOT_FOUND : STATE_DB_SUCCESS;
}

static state_db_access_result_t st_get_code(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const code_hash, struct monad_bv *const code)
{
    struct bytes32_map_entry *map_entry;
    struct state_tracker *const st = (struct state_tracker *)self;

    map_entry = bytes32_map_find(&st->code, code_hash);
    if (map_entry == nullptr) {
        // XXX: by doing this, we don't track code accesses with the same
        // granularity of accounts and storage slots
        return state_db_get_code(st->prestate_db, meta, code_hash, code);
    }
    *code = map_entry->value.bytes;
    return STATE_DB_SUCCESS;
}

static void st_destroy(struct state_db *const self)
{
    struct state_tracker *const st = (struct state_tracker *)self;
    if (st == nullptr) {
        return;
    }
    state_tracker_reset(st);
    bytes32_map_release(&st->code, &release_code_map_entry, st);
    for (unsigned z = 0; z < Z_ZONE_COUNT; ++z) {
        mem_zone_destroy(st->impl->mem_zones[z]);
    }
    free(st->impl);
    free(st);
}

static struct state_db_ops state_tracker_db_ops = {
    .get_account = st_get_account,
    .get_storage = st_get_storage,
    .get_code = st_get_code,
    .merge_changes = nullptr,
    .destroy = st_destroy};

struct state_tracker *state_tracker_create(struct state_db *const prestate_db)
{
    struct state_tracker *st;

    st = (struct state_tracker *)malloc(sizeof *st);
    if (st == nullptr) {
        err(EX_OSERR, "malloc(3) of state_tracker failed");
    }
    __builtin_memset(st, 0, sizeof *st);
    st->self.vtable = &state_tracker_db_ops;
    st->prestate_db = prestate_db;
    SLIST_INIT(&st->scope_stack);
    SLIST_INIT(&st->all_scopes);
    st->impl = (struct state_tracker_impl *)malloc(sizeof *st->impl);
    if (st->impl == nullptr) {
        err(EX_OSERR, "malloc(3) of state_tracker_impl failed");
    }
    init_mem_zones(st->impl);
    bytes32_map_init(
        &st->code,
        EXPECTED_CODE_ACCOUNTS,
        DEFAULT_MAX_LOAD_FACTOR,
        st->impl->mem_zones[Z_MAP_ENTRY]);
    return st;
}

struct state_scope *state_tracker_push_scope(struct state_tracker *const st)
{
    struct state_scope *const scope =
        (struct state_scope *)mz_alloc(st, Z_STATE_SCOPE);
    scope->tracker = st;
    bytes32_map_init(
        &scope->accounts,
        EXPECTED_ACCOUNTS,
        DEFAULT_MAX_LOAD_FACTOR,
        st->impl->mem_zones[Z_MAP_ENTRY]);
    TAILQ_INIT(&scope->storage_maps);
    STAILQ_INIT(&scope->local_logs);
    STAILQ_INIT(&scope->merged_logs);
    SLIST_INSERT_HEAD(&st->scope_stack, scope, stack_link);
    SLIST_INSERT_HEAD(&st->all_scopes, scope, all_link);
    return scope;
}

void state_tracker_set_account(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_address const *const addr,
    struct monad_eth_account_state const *const acct_state)
{
    struct account_access *access;
    struct account_access *prev_access;
    struct monad_bytes32 addr_key;
    struct state_scope *cur_scope;
    struct state_scope_account *account;
    state_access_type_t access_type;
    bool is_delete;

    addr_key = bytes32_map_key_from_addr(addr);
    prev_access = get_or_inject_prev_account_access(st, meta, &addr_key);
    cur_scope = get_current_scope(st);

    if (prev_access->merged_account->origin_scope == cur_scope) {
        // Previous access was in the current scope; use the existing account
        account = prev_access->merged_account;
    }
    else {
        // First time seeing this account at this scope; create a new map entry
        // for it
        account = create_account_in_scope(cur_scope, &addr_key);
    }
    is_delete =
        acct_state == nullptr ||
        __builtin_memcmp(
            acct_state, &MONAD_ETH_EMPTY_ACCOUNT, sizeof *acct_state) == 0;
    access_type = is_delete ? SA_TYPE_DELETE : SA_TYPE_WRITE;
    access = alloc_account_access(st, access_type, meta, prev_access);
    access->empty = is_delete;
    access->acct_state = is_delete ? MONAD_ETH_EMPTY_ACCOUNT : *acct_state;
    (void)insert_account_access(access, account);
}

enum evmc_storage_status state_tracker_set_storage(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_address const *const addr,
    struct monad_bytes32 const *const original_key,
    struct monad_bytes32 const *const value)
{
    struct monad_bytes32 addr_key;
    struct monad_bytes32 hashed_key;
    struct state_scope *cur_scope;
    struct state_scope_storage_slot *slot;
    struct storage_access *access;
    struct storage_access *first_access;
    struct storage_access *prev_access;
    state_access_type_t access_type;
    bool is_delete;

    addr_key = bytes32_map_key_from_addr(addr);
    // See comments in mem_state_db.c for why we compute keccak hashes of
    // storage keys
    keccak256(original_key, sizeof *original_key, hashed_key.bytes);
    prev_access = get_or_inject_prev_storage_access(
        st, meta, &addr_key, original_key, &hashed_key);
    // XXX: everything we did was to prevent having to walk the entire scope
    // chain, but to compute an `evmc_storage_status` we have to do it anyway;
    // the DB_IMPORT access should probably be cached? [Note: that's now 100%
    // true; we only need to walk the slot access chain, but we don't need to
    // hashed lookups in every scope]
    first_access = find_first_storage_access(prev_access);
    cur_scope = get_current_scope(st);

    if (prev_access->merged_slot->account->origin_scope == cur_scope) {
        // Previous access was in the current scope, so the storage slot already
        // exists
        slot = prev_access->merged_slot;
    }
    else {
        // Storage slot does not already exist; create it (we may also have to
        // inject a cache entry for the account in the current scope, if it has
        // never been touched in this scope)
        struct state_scope_account *const account =
            touch_account_to_access_storage(st, meta, &addr_key);
        slot = create_storage_slot(account, original_key, &hashed_key);
    }

    is_delete =
        value == nullptr || monad_bytes32_eq(value, &MONAD_BYTES32_ZERO);
    access_type = is_delete ? SA_TYPE_DELETE : SA_TYPE_WRITE;
    access = alloc_storage_access(st, access_type, meta, prev_access);
    access->value = is_delete ? MONAD_BYTES32_ZERO : *value;
    (void)insert_storage_access(access, slot);

    return compute_storage_status(first_access, prev_access, access);
}

void state_tracker_set_code(
    struct state_tracker *const st, struct state_access_meta const *,
    struct monad_bytes32 const *const code_hash, struct monad_bv const code)
{
    struct bytes32_map_entry *entry;
    bool inserted;
    uint8_t *codebuf;
    size_t codebuf_len;

    if (monad_bv_empty(code)) {
        return;
    }

    (void)bytes32_map_try_insert(&st->code, code_hash, &inserted, &entry);
    // See comment in mem_state_db_set_code for an explanation of this assertion
    MONAD_ASSERT(entry && inserted, "content-addressed code set twice?");

    // Copy the code to a buffer we own, then place this buffer in the map
    codebuf_len = monad_bv_len(code);
    codebuf = (uint8_t *)malloc(codebuf_len);
    if (codebuf == nullptr) {
        err(EX_OSERR, "malloc(3) for code buffer failed");
    }
    memcpy(codebuf, code.begin, codebuf_len);
    entry->value.bytes = monad_bv_from_size(codebuf, codebuf_len);
}

struct txn_log const *state_tracker_emit_log(
    struct state_tracker *const st, struct monad_address const *const addr,
    struct monad_bytes32 const topics[], size_t const topic_count,
    struct monad_bv const data)
{
    uint8_t *data_buf;
    size_t data_len;
    struct state_scope *cur_scope;
    struct txn_log *log;

    cur_scope = get_current_scope(st);
    log = (struct txn_log *)mz_alloc(st, Z_TXN_LOG);
    log->contract = *addr;
    data_len = monad_bv_len(data);
    data_buf = malloc(data_len);
    if (data_buf == nullptr) {
        err(EX_OSERR, "malloc(3) of log data failed");
    }
    log->data =
        monad_bv_from_size(memcpy(data_buf, data.begin, data_len), data_len);
    log->topic_count = topic_count;
    memcpy(log->topics, topics, sizeof(struct monad_bytes32) * topic_count);
    log->local_scope = log->merged_scope = cur_scope;
    STAILQ_INSERT_TAIL(&cur_scope->local_logs, log, local_link);
    STAILQ_INSERT_TAIL(&cur_scope->merged_logs, log, merged_link);
    return log;
}

struct monad_bytes32 state_tracker_write_to_db(struct state_tracker *const st)
{
    struct monad_bytes32 state_root;
    struct state_scope const *const top_scope = get_current_scope(st);
    MONAD_ASSERT(
        state_scope_prev(top_scope) == nullptr,
        "cannot merge non-base scope into db");
    state_db_merge_changes(st->prestate_db, st, &state_root);
    return state_root;
}

void state_tracker_reset(struct state_tracker *const st)
{
    struct state_scope *scope;

    while ((scope = SLIST_FIRST(&st->all_scopes)) != nullptr) {
        struct txn_log *log;

        SLIST_REMOVE_HEAD(&st->all_scopes, all_link);
        bytes32_map_release(
            &scope->accounts, &release_scope_account_entry, scope);
        MONAD_ASSERT(
            TAILQ_EMPTY(&scope->storage_maps),
            "should have been freed by the release of accounts?");
        while ((log = STAILQ_FIRST(&scope->local_logs)) != nullptr) {
            STAILQ_REMOVE_HEAD(&scope->local_logs, local_link);
            mz_free(st, Z_TXN_LOG, log);
        }
        mz_free(st, Z_STATE_SCOPE, scope);
    }
    SLIST_INIT(&st->scope_stack);
    bytes32_map_clear(&st->code, &release_code_map_entry, st);
}

void state_scope_pop(
    struct state_scope *const scope, state_scope_pop_action_t const action)
{
    struct state_access *access;
    struct state_scope *pop_scope;
    struct state_scope *next_scope;
    struct state_tracker *const st = scope->tracker;

    pop_scope = get_current_scope(st);
    MONAD_ASSERT(
        pop_scope == scope, "state scope imbalance in state_scope_pop");
    next_scope = SLIST_NEXT(pop_scope, stack_link);
    MONAD_ASSERT(next_scope != nullptr, "cannot pop the base scope");
    SLIST_REMOVE_HEAD(&st->scope_stack, stack_link);

    switch (action) {
    case STATE_SCOPE_COMMIT:
        commit_scope(st, pop_scope);
        break;

    case STATE_SCOPE_REVERT:
        // We do nothing after popping the scope from the stack; all the pieces
        // of tracking information it holds stick around until
        // state_tracker_reset is called; this is done to help with state access
        // tracing / debugging
        break;

    default:
        MONAD_ABORT_PRINTF("unknown state scope pop action code %hhu", action);
    }
}
