#pragma once

#include <category/core/bytes32_map.h>
#include <stddef.h>
#include <sys/queue.h>

#include "state_db.h"

struct mem_state_db_impl;
struct monad_eth_account_state;

struct storage_map
{
    struct bytes32_map slots;
    TAILQ_ENTRY(storage_map) next_map;
};

TAILQ_HEAD(storage_map_list, storage_map);

struct mem_state_db_config
{
    size_t expected_accounts;
    size_t expected_code_accounts;
    size_t expected_storage_slots_per_account;
};

struct mem_state_db
{
    struct state_db self;
    struct bytes32_map accounts;
    struct storage_map_list storage_maps;
    struct bytes32_map code;
    struct mem_state_db_impl *impl;
    struct mem_state_db_config config;
};

struct mem_state_db *mem_state_db_create(struct mem_state_db_config const *);

void mem_state_db_set_account(
    struct mem_state_db *, struct monad_address const *,
    struct monad_eth_account_state const *, struct storage_map **);

void mem_state_db_set_storage(
    struct mem_state_db *, struct monad_address const *, struct storage_map *,
    struct monad_bytes32 const *, struct monad_bytes32 const *);

void mem_state_db_set_code(
    struct mem_state_db *, struct monad_bytes32 const *, struct monad_bv);
