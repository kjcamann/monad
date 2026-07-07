#define SYSLOG_NAMES

#include <errno.h>
#include <stdarg.h>
#include <stdcountof.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <syslog.h>

#if __has_include(<elf.h>)
    #include <elf.h>
#else
constexpr unsigned EM_RISCV = 243;
#endif

#include <evmc/evmc.h>
#include <evmc/helpers.h>
#include <libelf.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/format_err.h>
#include <category/core/srcloc.h>
#include <category/rv/rv_code_cache.h>

#include "vm.h"

constexpr char RV64_VM_LOG_LEVEL[] = "RV64_VM_LOG_LEVEL";

// There is no way to return error diagnostics through evmc. Because this is
// loaded as a shared library, we don't want to write anything to stderr by
// default, since we do not control the process and that might not be
// appropriate. The user can opt into writing logs to stderr by setting the
// environment variable RV64_VM_LOG_LEVEL to a numeric syslog(3) priority

static unsigned s_min_log_level = LOG_CRIT;
static thread_local char g_error_buf[1024];

static char const *get_priority_name(unsigned level)
{
    for (size_t i = 0; i < countof(prioritynames); ++i) {
        if (prioritynames[i].c_val == level) {
            return prioritynames[i].c_name;
        }
    }
    return "<unknown>";
}

static void set_log_level()
{
    char *endptr;
    char const *const env_var = getenv(RV64_VM_LOG_LEVEL);
    if (env_var == nullptr) {
        return;
    }
    s_min_log_level = (unsigned)strtoul(env_var, &endptr, 0);
    MONAD_ASSERT(s_min_log_level <= LOG_DEBUG);
    if (*endptr != '\0') {
        s_min_log_level = LOG_ERR;
        VM_ERR(EINVAL, "%s is not a valid log level", env_var);
    }
}

static enum evmc_set_option_result
set_macho_override_option(struct rv64_vm *const vm, char const *const override)
{
    int rc;
    struct monad_address addr;
    char const *const sep = strchr(override, ':');

    if (sep == nullptr) {
        VM_ERR(
            EINVAL,
            "parse error: expected ':' in Mach-O override `%s`",
            override);
        return EVMC_SET_OPTION_INVALID_VALUE;
    }
    rc = monad_address_from_hex(override, (size_t)(sep - override), &addr);
    if (rc != 0) {
        VM_ERR(
            EINVAL,
            "parse error: could not parse address from Mach-O override `%s`",
            override);
        return EVMC_SET_OPTION_INVALID_VALUE;
    }
    return host_exec_add_macho_override(vm, &addr, sep + 1) == 0
               ? EVMC_SET_OPTION_SUCCESS
               : EVMC_SET_OPTION_INVALID_VALUE;
}

static void rv64_vm_destroy(struct evmc_vm *const self)
{
    host_exec_cleanup((struct rv64_vm *)self);
    free(self);
}

static struct evmc_result rv64_vm_execute(
    struct evmc_vm *const vm, struct evmc_host_interface const *const host,
    struct evmc_host_context *const context, enum evmc_revision const rev,
    struct evmc_message const *const msg, uint8_t const *const raw_code,
    size_t const /*unused*/)
{
    Elf *image;
    Elf64_Ehdr *elf_header;
    monad_rv_code_token_t code_token;

    code_token = *(monad_rv_code_token_t const *)raw_code;
    image = (Elf *)monad_rv_code_token_native_handle(code_token);
    elf_header = elf64_getehdr(image);
    MONAD_ASSERT(elf_header != nullptr);
    if (elf_header->e_machine == EM_RISCV) {
        MONAD_ABORT("RISC-V virtual machine not ready yet!");
    }

    // Not RISC-V; run this directly on the host
    return host_exec_run((struct rv64_vm *)vm, host, context, rev, msg, image);
}

static evmc_capabilities_flagset rv64_vm_get_capabilities(struct evmc_vm *)
{
    // TODO(ken): return EVMC_CAPABILITY_RV64;
    return 0;
}

static enum evmc_set_option_result rv64_vm_set_option(
    struct evmc_vm *const self, char const *const name, char const *const value)
{
    struct rv64_vm *const vm = (struct rv64_vm *)self;

    if (strcmp(name, "macho") == 0) {
        return set_macho_override_option(vm, value);
    }
    return EVMC_SET_OPTION_INVALID_NAME;
}

int vm_write_log(
    unsigned level, monad_source_location_t const *srcloc, int err,
    char const *format, ...)
{
    int rc;
    va_list ap;

    if (level > s_min_log_level) {
        return err;
    }

    rc = snprintf(
        g_error_buf,
        sizeof g_error_buf,
        "[rv64-vm] %s: ",
        get_priority_name(level));
    MONAD_ASSERT(rc >= 0);
    va_start(ap, format);
    rc = monad_vformat_err(
        g_error_buf + (size_t)rc,
        sizeof g_error_buf - (size_t)rc,
        srcloc,
        err,
        format,
        ap);
    va_end(ap);
    MONAD_ASSERT(rc >= 0);
    (void)fwrite(g_error_buf, strlen(g_error_buf), 1, stderr);
    (void)fputc('\n', stderr);
    return err;
}

__attribute__((visibility("default"))) struct evmc_vm *evmc_create_rv64_vm()
{
    struct rv64_vm *vm;

    elf_version(EV_CURRENT);
    set_log_level();
    vm = (struct rv64_vm *)malloc(sizeof *vm);
    if (vm == nullptr) {
        VM_ERR(errno, "malloc(3) of rv64_vm failed");
        return nullptr;
    }
    *(int *)&vm->self.abi_version = EVMC_ABI_VERSION;
    vm->self.name = "rv64 vm";
    vm->self.version = "1.0";
    vm->self.destroy = rv64_vm_destroy;
    vm->self.execute = rv64_vm_execute;
    vm->self.get_capabilities = rv64_vm_get_capabilities;
    vm->self.set_option = rv64_vm_set_option;

    return host_exec_init(vm) == 0 ? &vm->self : nullptr;
}
