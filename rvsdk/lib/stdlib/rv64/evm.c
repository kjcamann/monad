#include <stddef.h>

#include <category/core/byteview.h>
#include <category/rv/rv64_ecall.h>
#include <category/rv/syscall.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/evm.h>

mrv_err_t mrv_evm_call(struct mrv_evm_call_args const *const args)
{
    return (mrv_err_t)rv64_syscall6(
        (long)args->call_type,
        (long)args->gas,
        (long)args->address,
        (long)args->value,
        (long)args->calldata.begin,
        (long)args->calldata.end,
        MONAD_RV_EVMSYS_CALL);
}

void mrv_evm_exit(
    mrv_evm_exit_type_t const type, void const *const buf, size_t const len)
{
    register long a0 __asm__("a0") = (long)type;
    register long a1 __asm__("a1") = (long)buf;
    register long a2 __asm__("a2") = (long)len;
    register long t0 __asm__("t0") = MONAD_RV_EVMSYS_EXIT;

    // Note: no "memory" clobber needed here, since we'll never return
    asm volatile("ecall" : : "r"(t0), "r"(a0), "r"(a1), "r"(a2));

    __builtin_unreachable();
}

struct monad_bv mrv_evm_calldata()
{
    struct monad_bv bv;
    struct rv64_syscall_rpair const r =
        rv64_syscall0_r2(MONAD_RV_EVMSYS_CALLDATA);
    __builtin_memcpy(&bv, &r, sizeof r);
    return bv;
}

struct monad_bv mrv_evm_returndata()
{
    struct monad_bv bv;
    struct rv64_syscall_rpair const r =
        rv64_syscall0_r2(MONAD_RV_EVMSYS_RETURNDATA);
    __builtin_memcpy(&bv, &r, sizeof r);
    return bv;
}

uint64_t mrv_evm_gas_left()
{
    return (uint64_t)rv64_syscall0(MONAD_RV_EVMSYS_GAS);
}

struct monad_bytes32 *
mrv_evm_keccak(void const *src, size_t n, struct monad_bytes32 *digest)
{
    (void)rv64_syscall3(
        (long)src, (long)n, (long)digest, MONAD_RV_EVMSYS_KECCAK);
    return digest;
}

void mrv_evm_log(
    struct monad_bytes32 const *topics, size_t topic_count,
    struct monad_bv data)
{
    (void)rv64_syscall4(
        (long)topics,
        (long)topic_count,
        (long)data.begin,
        (long)data.end,
        MONAD_RV_EVMSYS_LOG);
}

struct monad_address const *mrv_evm_msg_sender()
{
    return (struct monad_address const *)rv64_syscall0(
        MONAD_RV_EVMSYS_MSG_SENDER);
}

void mrv_evm_sload(struct monad_bytes32 const *key, struct monad_bytes32 *value)
{
    (void)rv64_syscall2((long)key, (long)value, MONAD_RV_EVMSYS_SLOAD);
}

void mrv_evm_sstore(
    struct monad_bytes32 const *key, struct monad_bytes32 const *value)
{
    (void)rv64_syscall2((long)key, (long)value, MONAD_RV_EVMSYS_SSTORE);
}
