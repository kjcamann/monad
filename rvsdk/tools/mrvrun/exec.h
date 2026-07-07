#pragma once

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>

struct rvc_vm;
struct state_db;
struct state_tracker;
struct txn_input;

// clang-format off

struct dso_override
{
    char const *address;
    char const *dso_path;
};

struct exec_env_options
{
    char const *evm_config;       ///< evmc_load_and_configure input for EVM1
    char const *rvc_config;       ///< rvc_load_and_configure input for RV64 VM
    char const *db_config;        ///< state_db_load_and_configure input
    struct dso_override
        *dso_overrides;           ///< Contract address -> DSO file mapping
    size_t dso_override_count;    ///< Size of `dso_overrides` array
    char const **mrv_sys_paths;   ///< Paths to MRV system library .tar's
    size_t mrv_sys_path_count;    ///< Size of `mrv_sys_paths` array
    bool dso_host_exec;           ///< Enable host execution
    uint8_t rv_log_level;         ///< syslog(3) level for RISC-V VM logs
};

// clang-format on

struct exec_env
{
    struct evmc_vm *evm_vm;
    struct rvc_vm *rvc_vm;
    struct state_db *prestate_db;
    struct state_db *lower_db;
    struct state_tracker *state;
    struct evmc_host_interface *host_if;
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
