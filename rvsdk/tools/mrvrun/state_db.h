#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>

struct monad_eth_account_state;
struct state_db;
struct state_tracker;

typedef __uint128_t state_db_hint_t;

enum state_access_context : uint8_t
{
    SA_CTX_UNKNOWN,
    SA_CTX_TXN_PROLOGUE,
    SA_CTX_MSG_PROLOGUE,
    SA_CTX_VM_RUNTIME,
};

enum state_access_reason : uint8_t
{
    SA_REASON_UNKNOWN,
    SA_REASON_IRREVOCABLE,
    SA_REASON_READ_CODE,
    SA_REASON_HOST_CALL,
    SA_REASON_CREATE_CONTRACT,
};

typedef enum state_access_context state_access_context_t;
typedef enum state_access_reason state_access_reason_t;

struct state_access_meta
{
    uint32_t txn_id;
    uint32_t call_frame_id;
    uint64_t pc;
    state_access_context_t context;
    state_access_reason_t reason;
};

typedef enum state_db_access_result
{
    STATE_DB_SUCCESS,
    STATE_DB_NOT_FOUND,
} state_db_access_result_t;

typedef state_db_access_result_t(state_db_get_account_fn)(
    struct state_db *, struct state_access_meta const *,
    struct monad_address const *, state_db_hint_t *storage_hint,
    struct monad_eth_account_state *);

typedef state_db_access_result_t(state_db_get_storage_fn)(
    struct state_db *, struct state_access_meta const *,
    struct monad_address const *, state_db_hint_t const *storage_hint,
    struct monad_bytes32 const *, struct monad_bytes32 *);

typedef state_db_access_result_t(state_db_get_code_fn)(
    struct state_db *, struct state_access_meta const *,
    struct monad_bytes32 const *, struct monad_bv *);

typedef void(state_db_merge_changes_fn)(
    struct state_db *, struct state_tracker *, struct monad_bytes32 *);

typedef void(state_db_destroy_fn)(struct state_db *);

struct state_db_ops
{
    state_db_get_account_fn *get_account;
    state_db_get_storage_fn *get_storage;
    state_db_get_code_fn *get_code;
    state_db_merge_changes_fn *merge_changes;
    state_db_destroy_fn *destroy;
};

struct state_db
{
    struct state_db_ops *vtable;
};

static inline state_db_access_result_t state_db_get_account(
    struct state_db *const db, struct state_access_meta const *const meta,
    struct monad_address const *const addr, state_db_hint_t *const storage_hint,
    struct monad_eth_account_state *const acct_state)
{
    return db->vtable->get_account(db, meta, addr, storage_hint, acct_state);
}

static inline state_db_access_result_t state_db_get_storage(
    struct state_db *const db, struct state_access_meta const *const meta,
    struct monad_address const *const addr,
    state_db_hint_t const *const storage_hint,
    struct monad_bytes32 const *const key, struct monad_bytes32 *const value)
{
    return db->vtable->get_storage(db, meta, addr, storage_hint, key, value);
}

static inline state_db_access_result_t state_db_get_code(
    struct state_db *const db, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const key, struct monad_bv *const code)
{
    return db->vtable->get_code(db, meta, key, code);
}

static inline void state_db_merge_changes(
    struct state_db *const db, struct state_tracker *const st,
    struct monad_bytes32 *const state_root)
{
    return db->vtable->merge_changes(db, st, state_root);
}

static inline void state_db_destroy(struct state_db *const db)
{
    return db->vtable->destroy(db);
}

/*
 * Utilities
 */

struct null_state_db
{
    struct state_db self;
};

extern struct null_state_db *g_null_state_db;

struct overlay_state_db
{
    struct state_db self;
    struct state_db *upper;
    struct state_db *lower;
};

struct overlay_state_db *
overlay_state_db_create(struct state_db *, struct state_db *);
