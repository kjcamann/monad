#pragma once

#if !defined(__riscv)
    #error This file can only be included by RISCV targets
#endif

#define __asm_syscall_r1(...)                                                  \
    __asm__ __volatile__("ecall\n\t" : "=r"(a0) : __VA_ARGS__ : "memory");     \
    return a0;

#define __asm_syscall_r2(...)                                                  \
    __asm__ __volatile__("ecall\n\t"                                           \
                         : "=r"(a0), "=r"(a1)                                  \
                         : __VA_ARGS__                                         \
                         : "memory");

struct rv64_syscall_rpair
{
    long a;
    long b;
};

static inline struct rv64_syscall_rpair rv64_syscall0_r2(long const n)
{
    register long a0 __asm__("a0");
    register long a1 __asm__("a1");
    register long t0 __asm__("t0") = n;

    __asm_syscall_r2("r"(t0));
    return (struct rv64_syscall_rpair){a0, a1};
}

static inline long rv64_syscall0(long const n)
{
    register long a0 __asm__("a0");
    register long t0 __asm__("t0") = n;

    __asm_syscall_r1("r"(t0))
}

static inline long rv64_syscall1(long const a, long const n)
{
    register long a0 __asm__("a0") = a;
    register long t0 __asm__("t0") = n;

    __asm_syscall_r1("r"(t0), "0"(a0));
}

static inline long rv64_syscall2(long const a, long const b, long const n)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long t0 __asm__("t0") = n;

    __asm_syscall_r1("r"(t0), "0"(a0), "r"(a1));
}

static inline long
rv64_syscall3(long const a, long const b, long const c, long const n)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long t0 __asm__("t0") = n;

    __asm_syscall_r1("r"(t0), "0"(a0), "r"(a1), "r"(a2));
}

static inline long rv64_syscall4(
    long const a, long const b, long const c, long const d, long const n)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a3 __asm__("a3") = d;
    register long t0 __asm__("t0") = n;

    __asm_syscall_r1("r"(t0), "0"(a0), "r"(a1), "r"(a2), "r"(a3));
}

static inline long rv64_syscall5(
    long const a, long const b, long const c, long const d, long const e,
    long const n)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a3 __asm__("a3") = d;
    register long a4 __asm__("a4") = e;
    register long t0 __asm__("t0") = n;
    __asm_syscall_r1("r"(t0), "0"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4))
}

static inline long rv64_syscall6(
    long const a, long const b, long const c, long const d, long const e,
    long const f, long const n)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a3 __asm__("a3") = d;
    register long a4 __asm__("a4") = e;
    register long a5 __asm__("a5") = f;
    register long t0 __asm__("t0") = n;
    __asm_syscall_r1(
        "r"(t0), "0"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5))
}
