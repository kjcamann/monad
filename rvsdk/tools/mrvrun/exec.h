#pragma once

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>

struct monad_rv_code_cache;
struct monad_rv_code_decomp;
struct state_db;
struct state_tracker;
struct txn_input;

// clang-format off

struct exec_env_options
{
    char const *evm_config;       ///< evmc_load_and_configure input for EVM1
    char const *rv64_config;      ///< evmc_load_and_configure input for RV64 VM
    char const *db_config;        ///< state_db_load_and_configure input
    char const **macho_overrides; ///< key -> Mach-O file mapping
    size_t macho_override_count;  ///< Size of `macho_overrides` array
    bool elf_host_exec;           ///< Enable host execution
};

// clang-format on

struct exec_env
{
    struct evmc_vm *evm_vm;
    struct evmc_vm *rv64_vm;
    struct state_db *prestate_db;
    struct state_db *lower_db;
    struct state_tracker *state;
    struct evmc_host_interface *host_if;
    struct monad_rv_code_cache *rv_code_cache;
    struct monad_rv_code_zstd_decomp *rv_decomp;
};

struct exec_txn_context
{
    struct exec_env *exec_env;
    struct evmc_tx_context evmc_context;
    struct txn_input const *txn;
    uint32_t txn_index;
    uint32_t call_frame_count;
};

struct exec_env *exec_env_create(struct exec_env_options const *);

void exec_env_destroy(struct exec_env *);
