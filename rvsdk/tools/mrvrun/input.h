#pragma once

#include <stddef.h>
#include <sys/queue.h>

#include <category/execution/ethereum/core/eth_ctypes.h>

struct block_input;
struct mem_state_db;

struct sim_input
{
    struct mem_state_db *overlay;
    struct block_input const *blocks;
    size_t block_count;
    struct monad_eth_block_input genesis_block_header;
    char const *description;
    STAILQ_ENTRY(sim_input) next;
};

STAILQ_HEAD(sim_input_list, sim_input);

struct sim_input_list sim_input_load_eth_test(char const *path);

void sim_input_destroy(struct sim_input *);
