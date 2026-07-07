#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <sys/queue.h>
#include <sysexits.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/bytes32_map.h>
#include <category/core/byteview.h>
#include <category/core/keccak.h>
#include <category/core/mem/mem_zone.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

#include "mem_state_db.h"
#include "state_db.h"
#include "state_tracker.h"

struct mem_zone_config const MAP_ENTRY_MEM_ZONE_CONFIG = {
    .name = "mem_state_db map entries",
    .size = sizeof(struct bytes32_map_entry),
    .align = alignof(struct bytes32_map_entry),
};

struct mem_zone_config const STORAGE_MAP_MEM_ZONE_CONFIG = {
    .name = "mem_state_db storage maps",
    .size = sizeof(struct storage_map),
    .align = alignof(struct storage_map),
};

struct db_account
{
    struct monad_eth_account_state state;
    struct storage_map *storage;
};

struct mem_state_db_impl
{
    struct mem_zone *map_entry_zone;
    struct mem_zone *storage_map_zone;
};

static bool empty_code_hash(struct monad_bytes32 const *const b32)
{
    return monad_bytes32_eq(b32, &MONAD_BYTES32_EMPTY_KECCAK);
}

static struct db_account *lookup_account(
    struct mem_state_db *const db, struct monad_address const *const addr,
    struct bytes32_map_entry **const map_entry_p)
{
    struct monad_bytes32 const key = bytes32_map_key_from_addr(addr);
    *map_entry_p = bytes32_map_find(&db->accounts, &key);
    if (*map_entry_p == nullptr) {
        return nullptr;
    }
    return (struct db_account *)(*map_entry_p)->value.buf;
}

static struct storage_map *lookup_account_storage_map(
    struct mem_state_db *const db, struct monad_address const *const addr,
    bool const create_if_missing)
{
    struct bytes32_map_entry *map_entry;
    struct db_account *const account = lookup_account(db, addr, &map_entry);
    if (account == nullptr) {
        return nullptr;
    }
    if (account->storage == nullptr && create_if_missing) {
        int rc;

        rc = mem_zone_alloc(
            db->impl->storage_map_zone, (void **)&account->storage);
        if (rc != 0) {
            err(EX_OSERR, "mem_zone_alloc in storage_map_zone failed");
        }
        rc = bytes32_map_init(
            &account->storage->slots,
            db->config.expected_storage_slots_per_account,
            DEFAULT_MAX_LOAD_FACTOR,
            db->impl->map_entry_zone);
        if (rc != 0) {
            err(EX_OSERR, "bytes32_map_init failed");
        }
        TAILQ_INSERT_TAIL(&db->storage_maps, account->storage, next_map);
    }
    return account->storage;
}

static void
release_storage_map(struct mem_state_db *const db, struct storage_map *const m)
{
    if (m == nullptr) {
        return;
    }
    TAILQ_REMOVE(&db->storage_maps, m, next_map);
    bytes32_map_release(&m->slots, nullptr, nullptr);
    mem_zone_free(db->impl->storage_map_zone, m);
}

static void
release_account(struct mem_state_db *const db, struct db_account *const account)
{
    release_storage_map(db, account->storage);
}

static void release_account_map_entry(
    struct bytes32_map_entry *const entry, void *const ctx)
{
    release_account(
        (struct mem_state_db *)ctx, (struct db_account *)entry->value.buf);
}

static void
release_code_map_entry(struct bytes32_map_entry *const entry, void *const ctx)
{
    struct monad_bv const *const code = &entry->value.bytes;
    free((void *)code->begin);
}

static void init_db_mem_zones(struct mem_state_db *const db)
{
    (void)mem_zone_create(
        &MAP_ENTRY_MEM_ZONE_CONFIG, db, &db->impl->map_entry_zone);
    if (db->impl->map_entry_zone == nullptr) {
        err(EX_OSERR, "mem_zone_create for entries failed");
    }

    (void)mem_zone_create(
        &STORAGE_MAP_MEM_ZONE_CONFIG, db, &db->impl->storage_map_zone);
    if (db->impl->storage_map_zone == nullptr) {
        err(EX_OSERR, "mem_zone_create for storage_maps failed");
    }
}

static void destroy_db_mem_zones(struct mem_state_db *const db)
{
    mem_zone_destroy(db->impl->map_entry_zone);
    mem_zone_destroy(db->impl->storage_map_zone);
}

static state_db_access_result_t mdb_get_account(
    struct state_db *const self, struct state_access_meta const *,
    struct monad_address const *const addr, state_db_hint_t *const storage_hint,
    struct monad_eth_account_state *const acct_state)
{
    struct db_account *account;
    struct bytes32_map_entry *map_entry;
    struct mem_state_db *const db = (struct mem_state_db *)self;

    account = lookup_account(db, addr, &map_entry);
    if (account == nullptr) {
        return STATE_DB_NOT_FOUND;
    }
    if (storage_hint != nullptr) {
        *storage_hint = (uintptr_t)account->storage;
    }
    *acct_state = account->state;
    return STATE_DB_SUCCESS;
}

static state_db_access_result_t mdb_get_storage(
    struct state_db *const self, struct state_access_meta const *,
    struct monad_address const *const addr,
    state_db_hint_t const *const storage_hint,
    struct monad_bytes32 const *const key, struct monad_bytes32 *const value)
{
    struct monad_bytes32 hashed_key;
    struct bytes32_map_entry const *map_entry;
    struct storage_map const *storage;
    struct mem_state_db *const db = (struct mem_state_db *)self;

    if (storage_hint == nullptr || *storage_hint == 0) {
        storage =
            lookup_account_storage_map(db, addr, /*create_if_missing*/ false);
        if (storage == nullptr) {
            return STATE_DB_NOT_FOUND;
        }
    }
    else {
        storage = (struct storage_map const *)*storage_hint;
    }

    // See explanation in mem_state_db_set_storage for why we hash `key` here
    keccak256(key, sizeof *key, hashed_key.bytes);
    map_entry = bytes32_map_find(&storage->slots, &hashed_key);
    if (map_entry == nullptr) {
        return STATE_DB_NOT_FOUND;
    }
    *value = map_entry->value.b32;
    return STATE_DB_SUCCESS;
}

static state_db_access_result_t mdb_get_code(
    struct state_db *const self, struct state_access_meta const *,
    struct monad_bytes32 const *const code_hash, struct monad_bv *const code)
{
    struct bytes32_map_entry *map_entry;
    struct mem_state_db *const db = (struct mem_state_db *)self;

    map_entry = bytes32_map_find(&db->code, code_hash);
    if (map_entry == nullptr) {
        return STATE_DB_NOT_FOUND;
    }
    *code = map_entry->value.bytes;
    return STATE_DB_SUCCESS;
}

static void mdb_merge_changes(
    struct state_db *const self, struct state_tracker *const st,
    struct monad_bytes32 *const state_root)
{
    struct bytes32_map_entry *merge_map_entry;
    struct state_scope *base_scope;
    struct state_access_meta const meta = {}; // XXX: fill this out somehow?
    struct mem_state_db *const db = (struct mem_state_db *)self;

    if (state_root != nullptr) {
        // TODO(ken): should include mpt computation here
        *state_root = MONAD_BYTES32_ZERO;
    }

    base_scope = SLIST_FIRST(&st->scope_stack);
    MONAD_ASSERT(
        SLIST_NEXT(base_scope, stack_link) == nullptr,
        "cannot merge state_tracker with multiple active scopes");

    // Adjust the hash table sizes to hold all the new entries; this is only
    // approximately correct, since some entries may mark deletions
    bytes32_map_rehash(
        &db->accounts,
        db->accounts.entry_count + base_scope->accounts.entry_count);
    bytes32_map_rehash(&db->code, db->code.entry_count + st->code.entry_count);

    // Account merge
    TAILQ_FOREACH(merge_map_entry, &base_scope->accounts.all_entries, all_link)
    {
        struct monad_address const *addr;
        struct monad_eth_account_state db_acct_state;
        struct bytes32_map_entry *db_map_entry;
        struct account_access const *last_account_access;
        struct bytes32_map_entry const *storage_map_entry;
        struct state_scope_account const *changed_account;
        struct monad_eth_account_state const *new_acct_state;
        struct storage_map *storage;

        addr = bytes32_map_key_to_addr(&merge_map_entry->key);

        // Look up the existing account entry in the db, so we can check if we
        // need to garbage collect code of deleted accounts later
        if (state_db_get_account(self, &meta, addr, nullptr, &db_acct_state) ==
            STATE_DB_NOT_FOUND) {
            db_acct_state = MONAD_ETH_EMPTY_ACCOUNT;
        }

        // Write back the most recent account value to the database
        changed_account =
            (struct state_scope_account *)merge_map_entry->value.buf;
        last_account_access =
            TAILQ_LAST(&changed_account->merged_accesses, account_access_list);
        new_acct_state = last_account_access->type == SA_TYPE_DELETE
                             ? nullptr
                             : &last_account_access->acct_state;
        mem_state_db_set_account(db, addr, new_acct_state, &storage);

        // If the account does not exist in the db but it does exist now and has
        // a non-empty code hash, add the code
        if (empty_code_hash(&db_acct_state.code_hash) &&
            new_acct_state != nullptr &&
            !empty_code_hash(&new_acct_state->code_hash)) {
            struct monad_bv code;
            if (state_tracker_get_code(
                    st, &meta, &new_acct_state->code_hash, &code) ==
                STATE_DB_SUCCESS) {
                mem_state_db_set_code(db, &new_acct_state->code_hash, code);
            }
        }

        if (new_acct_state == nullptr) {
            // Account was deleted; if we are storing code under its code_hash,
            // garbage collect it
            if (!empty_code_hash(&db_acct_state.code_hash)) {
                mem_state_db_set_code(
                    db, &db_acct_state.code_hash, MONAD_BV_EMPTY);
            }
            continue;
        }

        if (changed_account->storage == nullptr) {
            return; // Account has no modified storage slots; we're done
        }

        // Merge all the storage slots
        TAILQ_FOREACH(
            storage_map_entry,
            &changed_account->storage->slots.all_entries,
            all_link)
        {
            struct monad_bytes32 const *value;
            struct storage_access const *last_storage_access;
            struct state_scope_storage_slot const *const changed_slot =
                (struct state_scope_storage_slot *)storage_map_entry->value.buf;

            last_storage_access =
                TAILQ_LAST(&changed_slot->merged_accesses, storage_access_list);
            value = last_storage_access->type == SA_TYPE_DELETE
                        ? nullptr
                        : &last_storage_access->value;
            mem_state_db_set_storage(
                db, addr, storage, &changed_slot->original_key, value);
        }
    }
}

static void mdb_destroy(struct state_db *const self)
{
    struct mem_state_db *const db = (struct mem_state_db *)self;

    if (db == nullptr) {
        return;
    }
    bytes32_map_release(&db->accounts, &release_account_map_entry, db);
    bytes32_map_release(&db->code, &release_code_map_entry, db);
    MONAD_ASSERT(
        TAILQ_EMPTY(&db->storage_maps),
        "should have been freed by the release of accounts?");
    destroy_db_mem_zones(db);
    free(db->impl);
    free(db);
}

static struct state_db_ops mem_state_db_ops = {
    .get_account = mdb_get_account,
    .get_storage = mdb_get_storage,
    .get_code = mdb_get_code,
    .merge_changes = mdb_merge_changes,
    .destroy = mdb_destroy,
};

struct mem_state_db *
mem_state_db_create(struct mem_state_db_config const *const config)
{
    int rc;
    struct mem_state_db *db;

    db = malloc(sizeof *db);
    if (db == nullptr) {
        err(EX_OSERR, "malloc(3) of mem_state_db failed");
    }
    __builtin_memset(db, 0, sizeof *db);
    // XXX: adjust `config` to be more reasonable
    db->self.vtable = &mem_state_db_ops;
    db->impl = malloc(sizeof *db->impl);
    if (db->impl == nullptr) {
        err(EX_OSERR, "malloc(3) of mem_state_db_impl failed");
    }
    init_db_mem_zones(db);

    rc = bytes32_map_init(
        &db->accounts,
        config->expected_accounts,
        DEFAULT_MAX_LOAD_FACTOR,
        db->impl->map_entry_zone);
    if (MONAD_UNLIKELY(rc != 0)) {
        err(EX_OSERR, "bytes32_map_init of map_entry_zone failed");
    }

    rc = bytes32_map_init(
        &db->code,
        config->expected_code_accounts,
        DEFAULT_MAX_LOAD_FACTOR,
        db->impl->map_entry_zone);
    if (MONAD_UNLIKELY(rc != 0)) {
        err(EX_OSERR, "bytes32_map_init of map_entry_zone failed");
    }

    TAILQ_INIT(&db->storage_maps);
    db->config = *config;
    return db;
}

void mem_state_db_set_account(
    struct mem_state_db *const db, struct monad_address const *const addr,
    struct monad_eth_account_state const *const acct_state,
    struct storage_map **const storage)
{
    struct monad_bytes32 key;
    struct db_account *account;
    struct bytes32_map_entry *map_entry;
    bool inserted;

    key = bytes32_map_key_from_addr(addr);
    if (acct_state == nullptr) {
        union bytes32_map_value map_value;

        // XXX: also if memcmp(&acct_state, EMPTY_ACCOUNT, ...) ?
        if (bytes32_map_erase(&db->accounts, &key, &map_value)) {
            release_account(db, (struct db_account *)map_value.buf);
            if (storage != nullptr) {
                *storage = nullptr;
            }
        }
        return;
    }
    (void)bytes32_map_try_insert(&db->accounts, &key, &inserted, &map_entry);
    MONAD_ASSERT(map_entry != nullptr);
    account = (struct db_account *)map_entry->value.buf;
    if (inserted) {
        account->storage = nullptr;
    }
    account->state = *acct_state;
    if (storage != nullptr) {
        *storage = account->storage;
    }
}

void mem_state_db_set_storage(
    struct mem_state_db *const db, struct monad_address const *const addr,
    struct storage_map *storage, struct monad_bytes32 const *const key,
    struct monad_bytes32 const *const value)
{
    struct monad_bytes32 hashed_key;
    struct bytes32_map_entry *entry;

    if (storage == nullptr) {
        storage =
            lookup_account_storage_map(db, addr, /*create_if_missing*/ true);
    }

    // Hash the storage key before inserted it into the map; the bytes32_map
    // assumes it is always working with a uniform key space and "hashes" by
    // truncation. This is a safe assumption for the two other key domains where
    // bytes32_map is used (account addresses and code hashes, which are both
    // crytographic hash digests), but the raw storage keys can be anything a
    // smart contract specifies in its code
    keccak256(key, sizeof *key, hashed_key.bytes);
    (void)bytes32_map_try_insert(&storage->slots, &hashed_key, nullptr, &entry);
    MONAD_ASSERT(entry != nullptr);
    entry->value.b32 = *value;
}

void mem_state_db_set_code(
    struct mem_state_db *const db, struct monad_bytes32 const *const code_hash,
    struct monad_bv const code)
{
    if (monad_bv_empty(code)) {
        // Explicitly mutating to an empty value means "delete the map entry"
        union bytes32_map_value value;
        if (bytes32_map_erase(&db->code, code_hash, &value)) {
            // Free the code bytes, which we own
            free((void *)value.bytes.begin);
        }
    }
    else {
        struct bytes32_map_entry *entry;
        bool inserted;
        uint8_t *codebuf;
        size_t codebuf_len;

        (void)bytes32_map_try_insert(&db->code, code_hash, &inserted, &entry);
        // Because `code_hash` is the keccak256 of the `code` contents, it would
        // only be legal to "update" a code map entry if the code bytes were
        // equal (otherwise this would be a keccak hash collision, something we
        // don't anticipate can happen). Since it would be slow to verify that
        // keccak256(code) is equal to the value already stored here, we instead
        // just abort if they attempt to update a key that is already in the db
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
}
