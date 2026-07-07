#include <category/core/byteview.h>

#include <mrv/stdlib/evm.h>
#include <mrv/stdlib/rvabi.h>

__attribute__((weak)) extern struct monad_bv init_contract(struct monad_bv)
{
    return MONAD_BV_EMPTY;
}

extern struct monad_bv txn_main(struct monad_bv);

[[noreturn]] MRV_EXPORT void mrv_init()
{
    struct monad_bv const returndata = init_contract(mrv_evm_calldata());
    mrv_evm_return(returndata.begin, monad_bv_len(returndata));
}

[[noreturn]] MRV_EXPORT void mrv_start()
{
    struct monad_bv const returndata = txn_main(mrv_evm_calldata());
    mrv_evm_return(returndata.begin, monad_bv_len(returndata));
}
