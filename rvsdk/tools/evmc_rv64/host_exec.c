#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <setjmp.h>
#include <unistd.h>

#include <evmc/evmc.h>
#include <evmc/helpers.h>
#include <libelf.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/bytes32_map.h>
#include <category/core/mem/mem_zone.h>
#include <category/rv/syscall.h>

#include "../../lib/stdlib/host/host_exec.h"
#include "vm.h"

constexpr size_t EXPECTED_HOST_CONTRACTS = 4;

struct mem_zone_config const MAP_ENTRY_ZONE_CONFIG = {
    .name = "host contract map entires",
    .size = sizeof(struct bytes32_map_entry),
    .align = alignof(struct bytes32_map_entry),
};

struct host_contract
{
    void *handle;
    int fd;
};

static void
release_host_contract(struct bytes32_map_entry *const map_entry, void *)
{
    struct host_contract const *const c =
        (struct host_contract const *)map_entry->value.buf;
    dlclose(c->handle);
    close(c->fd);
}

// clang-format off

// A lightweight "stackless" fiber implemented with setjmp(3)/longjmp(3); we
// use fibers because mrv_evm_exit performs a non-local jump to exit from
// anywhere in the transaction flow back to the execution entry point
struct fiber
{
    struct fiber *prev_fiber;  ///< Fiber running before this one
    jmp_buf suspended_ctx;     ///< setjmp(3) we'll transfer back to
    struct mrv_host_exec_context
        *host_exec_ctx;        ///< Details of what fiber is exec'ing
    struct evmc_result result; ///< Holds return value of call
};

// clang-format on

static thread_local struct fiber *s_cur_fiber;

enum
{
    FIBER_ENTER = 0,
    FIBER_RETURN = 1
};

static struct fiber *
fiber_create(struct mrv_host_exec_context *const host_exec_ctx)
{
    struct fiber *f;

    f = malloc(sizeof *f);
    if (f == nullptr) {
        return nullptr;
    }
    memset(f, 0, sizeof *f);
    f->host_exec_ctx = host_exec_ctx;
    return f;
}

static struct evmc_result fiber_destroy(struct fiber *const f)
{
    struct evmc_result const r = f->result;
    free(f);
    return r;
}

[[noreturn]] static void
fiber_entrypoint(struct fiber *const f, void (*start)())
{
    f->prev_fiber = s_cur_fiber;
    s_cur_fiber = f;
    start();
    // This should be unreachable (mrv_evm_exit should call longjmp(3))
    MONAD_ABORT("should not return from fiber_entrypoint");
}

__attribute__((visibility("default"))) struct mrv_host_exec_context *
mrv_get_host_exec_context()
{
    return s_cur_fiber->host_exec_ctx;
}

__attribute__((visibility("default"))) void mrv_host_exit(
    enum monad_rv_exit_type const type, void const *const buf, size_t const len)
{
    enum evmc_status_code status_code;
    struct fiber *const f = s_cur_fiber;

    MONAD_ASSERT(f != nullptr, "mrv_host_exit called on regular thread");

    switch (type) {
    case MONAD_RV_EXIT_STOP:
        [[fallthrough]];
    case MONAD_RV_EXIT_RETURN:
        status_code = EVMC_SUCCESS;
        break;

    case MONAD_RV_EXIT_REVERT:
        status_code = EVMC_REVERT;
        break;

    default:
        MONAD_ABORT_PRINTF("unrecognized exit type %hhu", type);
    }

    f->result = evmc_make_result(
        status_code,
        /*gas_left*/ UINT64_MAX,
        /*gas_refund*/ 0,
        buf,
        len);
    longjmp(f->suspended_ctx, FIBER_RETURN);
}

static struct evmc_result
exec_txn_fiber(struct mrv_host_exec_context *host_exec_ctx)
{
    int rc;
    struct fiber *f;
    struct fiber *const parent = s_cur_fiber;

    f = fiber_create(host_exec_ctx);
    if (f == nullptr) {
        return evmc_make_result(
            EVMC_INTERNAL_ERROR, host_exec_ctx->gas, 0, nullptr, 0);
    }
    rc = setjmp(f->suspended_ctx);
    if (rc == FIBER_ENTER) {
        fiber_entrypoint(f, host_exec_ctx->start_symbol);
    }
    MONAD_ASSERT(rc == FIBER_RETURN);
    s_cur_fiber = parent;
    return fiber_destroy(f);
}

static struct host_contract *dlopen_host_contract(
    struct rv64_vm *const vm, struct monad_address const *const addr,
    struct monad_bv const code)
{
    char namebuf[64];
    struct bytes32_map_entry *map_entry;
    struct host_contract *host_contract;
    struct monad_bytes32 addr_key;
    ssize_t n_write;
    bool inserted;
    int rc;

    addr_key = bytes32_map_key_from_addr(addr);
    rc = bytes32_map_try_insert(
        &vm->host_contracts, &addr_key, &inserted, &map_entry);
    if (rc != 0) {
        VM_ERR(
            rc,
            "bytes32_map_try_insert could not insert %s",
            monad_address_to_hex_static(addr));
        return nullptr;
    }
    host_contract = (struct host_contract *)map_entry->value.buf;
    if (!inserted) {
        return host_contract;
    }

    // XXX: memfd_create(2) + /proc/self/fd is a bit more elegant but gdb does
    // not like it (dlopen(2) will hang indefinitely when running under gdb)
#if 0
  snprintf(namebuf, sizeof namebuf, "host contract: 0x%s",
           monad_address_to_hex_static(addr));
  host_contract->fd = memfd_create(namebuf, 0);
  if (host_contract->fd == -1) {
    err(EX_OSERR, "unable to memfd_create(2) buffer for 0x%s",
        monad_address_to_hex_static(addr));
  }
#endif
    rc = snprintf(
        namebuf,
        sizeof namebuf,
        "/tmp/%s.so",
        monad_address_to_hex_static(addr));
    MONAD_ASSERT(rc >= 0);
    host_contract->fd = open(namebuf, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (host_contract->fd == -1) {
        VM_ERR(
            errno,
            "unable to open(2) local file %s for 0x%s",
            namebuf,
            monad_address_to_hex_static(addr));
        bytes32_map_erase(&vm->host_contracts, &addr_key, nullptr);
        return nullptr;
    }

    for (struct monad_bv resid = code; monad_bv_len(resid) > 0;
         resid = monad_bv_sub(resid, (size_t)n_write, MONAD_BV_ALL)) {
        n_write = write(host_contract->fd, resid.begin, monad_bv_len(resid));
        if (n_write == -1) {
            VM_ERR(
                errno,
                "write(2) of host contract 0x%s to %s failed",
                monad_address_to_hex_static(addr),
                namebuf);
            bytes32_map_erase(&vm->host_contracts, &addr_key, nullptr);
            (void)close(host_contract->fd);
            (void)unlink(namebuf);
            return nullptr;
        }
    }

#if 0
  snprintf(namebuf, sizeof namebuf, "/proc/self/fd/%d", host_contract->memfd);
#endif
    host_contract->handle = dlopen(namebuf, RTLD_LAZY);
    (void)unlink(namebuf);
    if (host_contract->handle == nullptr) {
        VM_ERRX(
            "unable to dlopen(3) shared library for 0x%s from %s: %s",
            monad_address_to_hex_static(addr),
            namebuf,
            dlerror());
        bytes32_map_erase(&vm->host_contracts, &addr_key, nullptr);
        (void)close(host_contract->fd);
        return nullptr;
    }

    return host_contract;
}

int host_exec_add_macho_override(
    struct rv64_vm *const vm, struct monad_address const *const addr,
    char const *const path)
{
    struct bytes32_map_entry *map_entry;
    struct host_contract *host_contract;
    struct monad_bytes32 addr_key;
    bool inserted;
    int rc;

    addr_key = bytes32_map_key_from_addr(addr);
    rc = bytes32_map_try_insert(
        &vm->host_contracts, &addr_key, &inserted, &map_entry);
    if (rc != 0) {
        return VM_ERR(
            rc,
            "bytes32_map_try_insert of %s failed",
            monad_address_to_hex_static(addr));
    }
    host_contract = (struct host_contract *)map_entry->value.buf;
    if (!inserted) {
        return VM_ERR(
            EADDRINUSE,
            "Mach-O override %s -> %s shadows existing override",
            monad_address_to_hex_static(addr),
            path);
    }

    // This does nothing except keep the file in place
    host_contract->fd = open(path, O_RDONLY);
    if (host_contract->fd == -1) {
        return VM_ERR(
            errno,
            "unable to open(2) Mach-O override file %s for 0x%s",
            path,
            monad_address_to_hex_static(addr));
    }
    host_contract->handle = dlopen(path, RTLD_LAZY);
    if (host_contract->handle == nullptr) {
        return VM_ERR(
            EINVAL,
            "unable to dlopen(3) shared library %s for 0x%s: %s",
            path,
            monad_address_to_hex_static(addr),
            dlerror());
    }
    VM_DEBUG(
        "address 0x%s mapped to Mach-O shared library %s [%p]",
        monad_address_to_hex_static(addr),
        path,
        host_contract->handle);
    return 0;
}

int host_exec_init(struct rv64_vm *vm)
{
    int rc;

    rc = mem_zone_create(&MAP_ENTRY_ZONE_CONFIG, nullptr, &vm->map_entry_zone);
    if (rc != 0) {
        VM_ERR(rc, "mem_zone_create for VM map entries failed");
        host_exec_cleanup(vm);
        return rc;
    }

    rc = bytes32_map_init(
        &vm->host_contracts,
        EXPECTED_HOST_CONTRACTS,
        DEFAULT_MAX_LOAD_FACTOR,
        vm->map_entry_zone);
    if (rc != 0) {
        VM_ERR(rc, "bytes32_map_init for host_contracts failed");
        host_exec_cleanup(vm);
        return rc;
    }

    return 0;
}

void host_exec_cleanup(struct rv64_vm *vm)
{
    bytes32_map_release(&vm->host_contracts, &release_host_contract, nullptr);
    mem_zone_destroy(vm->map_entry_zone);
}

struct evmc_result host_exec_run(
    struct rv64_vm *vm, struct evmc_host_interface const *const host,
    struct evmc_host_context *const context, enum evmc_revision const rev,
    struct evmc_message const *const msg, Elf *image)
{
    struct host_contract const *contract;
    struct monad_address const *code_addr;
    struct monad_bv elf_bytes;
    struct mrv_host_exec_context host_exec_ctx;
    char *elf_contents;
    size_t elf_size;
    bool is_init;

    code_addr = (struct monad_address const *)&msg->code_address;
    elf_contents = elf_rawfile(image, &elf_size);
    elf_bytes = monad_bv_from_size(elf_contents, elf_size);
    contract = dlopen_host_contract((struct rv64_vm *)vm, code_addr, elf_bytes);
    if (contract == nullptr) {
        return evmc_make_result(EVMC_INTERNAL_ERROR, msg->gas, 0, nullptr, 0);
    }
    is_init = msg->flags & 0x4; // EVMC_ELF_INIT
    host_exec_ctx.start_symbol =
        dlsym(contract->handle, is_init ? "mrv_init" : "mrv_start");
    if (host_exec_ctx.start_symbol == nullptr) {
        VM_ERRX(
            "no start symbol found in %s",
            monad_address_to_hex_static(code_addr));
        return evmc_make_result(
            EVMC_CONTRACT_VALIDATION_FAILURE, msg->gas, 0, nullptr, 0);
    }

    // Execute the start routine on the host
    host_exec_ctx.vm = &vm->self;
    host_exec_ctx.host = host;
    host_exec_ctx.context = context;
    host_exec_ctx.gas = msg->gas;
    host_exec_ctx.rev = rev;
    host_exec_ctx.msg = msg;
    host_exec_ctx.last_call_result = (struct evmc_result){};
    host_exec_ctx.code = elf_bytes;
    return exec_txn_fiber(&host_exec_ctx);
}
