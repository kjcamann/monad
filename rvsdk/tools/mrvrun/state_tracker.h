#pragma once

#include <stdint.h>

#include <sys/queue.h>

#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/bytes32_map.h>
#include <category/core/byteview.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

#include "mem_state_db.h"
#include "state_db.h"

enum evmc_storage_status;

struct account_access;
struct state_scope;
struct state_scope_account;
struct state_scope_storage_slot;
struct state_tracker_impl;
struct storage_access;

enum state_access_type : uint8_t
{
    SA_TYPE_READ,
    SA_TYPE_WRITE,
    SA_TYPE_DELETE,
    SA_TYPE_DB_IMPORT,
    SA_TYPE_CACHE_PROXY,
};

enum state_scope_pop_action : uint8_t
{
    STATE_SCOPE_COMMIT,
    STATE_SCOPE_REVERT,
};

typedef enum state_access_type state_access_type_t;
typedef enum state_scope_pop_action state_scope_pop_action_t;

TAILQ_HEAD(account_access_list, account_access);

struct account_access
{
    state_access_type_t type;
    bool empty;
    uint32_t merge_depth;
    struct monad_eth_account_state acct_state;
    TAILQ_ENTRY(account_access) local_link;
    TAILQ_ENTRY(account_access) merged_link;
    struct account_access *prev_access;
    struct state_scope_account *local_account;
    struct state_scope_account *merged_account;
    struct state_access_meta meta;
};

struct state_scope_account
{
    struct account_access_list local_accesses;
    struct account_access_list merged_accesses;
    struct storage_map *storage;
    struct state_scope *origin_scope;
    struct bytes32_map_entry *acct_map_entry;
};

static_assert(
    sizeof(struct state_scope_account) <= sizeof(union bytes32_map_value));

TAILQ_HEAD(storage_access_list, storage_access);

struct storage_access
{
    state_access_type_t type;
    bool empty;
    uint32_t merge_depth;
    struct monad_bytes32 value;
    TAILQ_ENTRY(storage_access) local_link;
    TAILQ_ENTRY(storage_access) merged_link;
    struct storage_access *prev_access;
    struct state_scope_storage_slot *local_slot;
    struct state_scope_storage_slot *merged_slot;
    struct state_access_meta meta;
};

struct state_scope_storage_slot
{
    struct storage_access_list local_accesses;
    struct storage_access_list merged_accesses;
    struct monad_bytes32 original_key;
    struct state_scope_account *account;
    struct bytes32_map_entry *slot_map_entry;
};

static_assert(
    sizeof(struct state_scope_storage_slot) <= sizeof(union bytes32_map_value));

// Transactions logs are not a "state" concept but they are revertible, so
// they also live in the `struct state_scope` object to piggyback on its
// commit/revert merge machinery
struct txn_log
{
    struct monad_address contract;
    struct monad_bv data;
    size_t topic_count;
    STAILQ_ENTRY(txn_log) local_link;
    STAILQ_ENTRY(txn_log) merged_link;
    struct monad_bytes32 topics[4];
    struct state_scope *local_scope;
    struct state_scope *merged_scope;
};

STAILQ_HEAD(txn_log_queue, txn_log);

struct state_scope
{
    struct state_tracker *tracker;
    struct bytes32_map accounts;
    struct storage_map_list storage_maps;
    struct txn_log_queue local_logs;
    struct txn_log_queue merged_logs;
    SLIST_ENTRY(state_scope) stack_link;
    SLIST_ENTRY(state_scope) all_link;
};

SLIST_HEAD(state_scope_stack, state_scope);

struct state_tracker
{
    struct state_db self;
    struct state_db *prestate_db;
    struct state_scope_stack scope_stack;
    struct state_scope_stack all_scopes;
    struct state_tracker_impl *impl;
    struct bytes32_map code;
};

struct state_tracker *state_tracker_create(struct state_db *prestate);

struct state_scope *state_tracker_push_scope(struct state_tracker *);

void state_tracker_set_account(
    struct state_tracker *, struct state_access_meta const *,
    struct monad_address const *, struct monad_eth_account_state const *);

enum evmc_storage_status state_tracker_set_storage(
    struct state_tracker *, struct state_access_meta const *,
    struct monad_address const *, struct monad_bytes32 const *,
    struct monad_bytes32 const *);

void state_tracker_set_code(
    struct state_tracker *, struct state_access_meta const *,
    struct monad_bytes32 const *, struct monad_bv);

struct txn_log const *state_tracker_emit_log(
    struct state_tracker *, struct monad_address const *,
    struct monad_bytes32 const topics[], size_t topic_count,
    struct monad_bv data);

struct monad_bytes32 state_tracker_write_to_db(struct state_tracker *);

void state_tracker_reset(struct state_tracker *);

void state_scope_pop(struct state_scope *, state_scope_pop_action_t);

static inline struct state_scope *
state_scope_prev(struct state_scope const *const scope)
{
    return SLIST_NEXT(scope, stack_link);
}

static inline state_db_access_result_t state_tracker_get_account(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_address const *const addr, state_db_hint_t *const storage_hint,
    struct monad_eth_account_state *const acct_state)
{
    return state_db_get_account(
        &st->self, meta, addr, storage_hint, acct_state);
}

static inline state_db_access_result_t state_tracker_get_storage(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_address const *const addr,
    state_db_hint_t const *const storage_hint,
    struct monad_bytes32 const *const key, struct monad_bytes32 *const value)
{
    return state_db_get_storage(
        &st->self, meta, addr, storage_hint, key, value);
}

static inline state_db_access_result_t state_tracker_get_code(
    struct state_tracker *const st, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const code_hash, struct monad_bv *const code)
{
    return state_db_get_code(&st->self, meta, code_hash, code);
}
