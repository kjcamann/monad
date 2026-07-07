#include <category/core/assert.h>
#include <category/rv/rvi_ecall.h>

void monad_assertion_failed(
    char const *expr, char const *function, char const *file, long line,
    char const *msg)
{
    register long a0 __asm__("a0") = (long)expr;
    register long a1 __asm__("a1") = (long)function;
    register long a2 __asm__("a2") = (long)file;
    register long a3 __asm__("a3") = line;
    register long a4 __asm__("a4") = (long)msg;
    register long t0 __asm__("t0") = RVI_ECALL_STD_ASSERT_FAILED;
    asm volatile("ecall"
                 :
                 : "r"(t0), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4));
    __builtin_unreachable();
}
