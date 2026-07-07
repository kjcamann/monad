#include <stdlib.h>

#include <err.h>
#include <sysexits.h>

#include <category/execution/ethereum/core/eth_ctypes.h>

#include "state_db.h"

static state_db_access_result_t null_get_account(
    struct state_db *, struct state_access_meta const *,
    struct monad_address const *, state_db_hint_t *,
    struct monad_eth_account_state *const acct_state)
{
    *acct_state = (struct monad_eth_account_state){};
    return STATE_DB_NOT_FOUND;
}

static state_db_access_result_t null_get_storage(
    struct state_db *, struct state_access_meta const *,
    struct monad_address const *, state_db_hint_t const *,
    struct monad_bytes32 const *, struct monad_bytes32 *const value)
{
    *value = MONAD_BYTES32_ZERO;
    return STATE_DB_NOT_FOUND;
}

static state_db_access_result_t null_get_code(
    struct state_db *, struct state_access_meta const *,
    struct monad_bytes32 const *, struct monad_bv *const code)
{
    *code = MONAD_BV_EMPTY;
    return STATE_DB_NOT_FOUND;
}

static void null_merge_changes(
    struct state_db *const self, struct state_tracker *const st,
    struct monad_bytes32 *const state_root)
{
}

static void null_destroy(struct state_db *) {}

static struct state_db_ops null_state_db_ops = {
    .get_account = null_get_account,
    .get_storage = null_get_storage,
    .get_code = null_get_code,
    .merge_changes = null_merge_changes,
    .destroy = null_destroy,
};

// TODO(ken): cannot explicitly delete things in an overlay yet, need a
//   state_db_access_result_t value like STATE_DB_DELETED so that upper
//   layer can prevent lower layer from leaking through

static state_db_access_result_t odb_get_account(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_address const *const addr, state_db_hint_t *const storage_hint,
    struct monad_eth_account_state *const acct_state)
{
    state_db_access_result_t db_result;
    struct overlay_state_db *const db = (struct overlay_state_db *)self;

    db_result =
        state_db_get_account(db->upper, meta, addr, storage_hint, acct_state);
    return db_result == STATE_DB_SUCCESS
               ? STATE_DB_SUCCESS
               : state_db_get_account(
                     db->lower, meta, addr, storage_hint, acct_state);
}

static state_db_access_result_t odb_get_storage(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_address const *const addr,
    state_db_hint_t const *const storage_hint,
    struct monad_bytes32 const *const key, struct monad_bytes32 *const value)
{
    state_db_access_result_t db_result;
    struct overlay_state_db *const db = (struct overlay_state_db *)self;

    db_result =
        state_db_get_storage(db->upper, meta, addr, storage_hint, key, value);
    return db_result == STATE_DB_SUCCESS
               ? STATE_DB_SUCCESS
               : state_db_get_storage(
                     db->lower, meta, addr, storage_hint, key, value);
}

static state_db_access_result_t odb_get_code(
    struct state_db *const self, struct state_access_meta const *const meta,
    struct monad_bytes32 const *const code_hash, struct monad_bv *const code)
{
    state_db_access_result_t db_result;
    struct overlay_state_db *const db = (struct overlay_state_db *)self;

    db_result = state_db_get_code(db->upper, meta, code_hash, code);
    return db_result == STATE_DB_SUCCESS
               ? STATE_DB_SUCCESS
               : state_db_get_code(db->lower, meta, code_hash, code);
}

static void odb_merge_changes(
    struct state_db *const self, struct state_tracker *const st,
    struct monad_bytes32 *const state_root)
{
    struct overlay_state_db *const db = (struct overlay_state_db *)self;
    return state_db_merge_changes(db->upper, st, state_root);
}

static void odb_destroy(struct state_db *const self)
{
    free(self);
}

static struct state_db_ops overlay_state_db_ops = {
    .get_account = odb_get_account,
    .get_storage = odb_get_storage,
    .get_code = odb_get_code,
    .merge_changes = odb_merge_changes,
    .destroy = odb_destroy,
};

struct overlay_state_db *overlay_state_db_create(
    struct state_db *const upper, struct state_db *const lower)
{
    struct overlay_state_db *db;

    db = malloc(sizeof *db);
    if (db == nullptr) {
        err(EX_OSERR, "malloc of overlay_state_db failed");
    }
    db->self.vtable = &overlay_state_db_ops;
    db->upper = upper;
    db->lower = lower;
    return db;
}

static struct null_state_db null_state_db_instance = {
    .self = {.vtable = &null_state_db_ops}};

struct null_state_db *g_null_state_db = &null_state_db_instance;
