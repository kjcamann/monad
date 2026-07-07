#include <category/rv/rv64_ecall.h>
#include <category/rv/syscall.h>

#include <mrv/stdlib/uint256.h>

mrv_uint256_t *mrv_uint256_add(mrv_uint256_t *lhs, mrv_uint256_t const *rhs)
{
    (void)rv64_syscall2((long)lhs, (long)rhs, MONAD_RV_STDSYS_UINT256_ADD);
    return lhs;
}

mrv_uint256_t *mrv_uint256_sub(mrv_uint256_t *lhs, mrv_uint256_t const *rhs)
{
    (void)rv64_syscall2((long)lhs, (long)rhs, MONAD_RV_STDSYS_UINT256_SUB);
    return lhs;
}

bool mrv_uint256_lt(mrv_uint256_t const *lhs, mrv_uint256_t const *rhs)
{
    return (bool)rv64_syscall2(
        (long)lhs, (long)rhs, MONAD_RV_STDSYS_UINT256_LT);
}
