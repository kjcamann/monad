#pragma once

#include <syslog.h>

#include <evmc/evmc.h>

#include <category/core/bytes32_map.h>
#include <category/core/srcloc.h>

struct monad_address;
struct Elf;

extern int vm_write_log(
    unsigned level, monad_source_location_t const *srcloc, int err,
    char const *format, ...);

#define VM_LOG(LEVEL, ...)                                                     \
    vm_write_log((LEVEL), &MONAD_SOURCE_LOCATION_CURRENT(), __VA_ARGS__)

#define VM_ERR(...) VM_LOG(LOG_ERR, __VA_ARGS__)
#define VM_ERRX(...) VM_LOG(LOG_ERR, 0, __VA_ARGS__)
#define VM_DEBUG(...) VM_LOG(LOG_DEBUG, 0, __VA_ARGS__)

struct rv64_vm
{
    struct evmc_vm self;
    struct bytes32_map host_contracts;
    struct mem_zone *map_entry_zone;
};

int host_exec_init(struct rv64_vm *);

void host_exec_cleanup(struct rv64_vm *);

int host_exec_add_macho_override(
    struct rv64_vm *, struct monad_address const *addr, char const *path);

struct evmc_result host_exec_run(
    struct rv64_vm *, struct evmc_host_interface const *,
    struct evmc_host_context *, enum evmc_revision, struct evmc_message const *,
    Elf *);
