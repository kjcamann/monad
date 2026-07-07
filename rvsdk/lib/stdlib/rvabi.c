#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/assert.h>
#include <category/core/likely.h>
#include <category/core/mem/align.h>

#include <mrv/stdlib/error.h>
#include <mrv/stdlib/panic.h>
#include <mrv/stdlib/rvabi.h>

static inline void const *align_ptr(void const *const p, size_t const align)
{
    return (void const *)monad_round_size_to_align((uintptr_t)p, align);
}

monad_abi_t mrv_abi_get_safe(struct mrv_abi_callable const *const c)
{
    monad_abi_t const abi = c->abi;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        [[fallthrough]];
    case MONAD_ABI_RV64_V1:
        return abi;
    case MONAD_ABI_UNSPECIFIED:
        return g_mrv_default_param_abi;
    default:
        MONAD_ABORT_PRINTF("unrecognized ABI code %hhu", abi);
    }
}

mrv_err_t mrv_abi_rv64_decode_calldata(
    struct monad_bv const calldata, struct mrv_abi_rv64_decode_result *const dr)
{
    int rc;
    char const *fn_name_end;
    struct mrv_abi_rv64_header const *header;

    __builtin_memset(dr, 0, sizeof *dr);
    if (MONAD_UNLIKELY(monad_bv_len(calldata) < sizeof *header)) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }
    header = (struct mrv_abi_rv64_header const *)calldata.begin;
    if (MONAD_UNLIKELY(header->magic != MONAD_ABI_RV64_DYNELF)) {
        return MONAD_ABIERR_NOT_RV64_MAGIC;
    }
    switch (header->param_cc) {
    case MONAD_ABI_SOLIDITY:
        [[fallthrough]];
    case MONAD_ABI_RV64_V1:
        break;
    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }

    dr->fn_name = (char const *)(header + 1);
    fn_name_end = dr->fn_name + header->name_length;
    if (MONAD_UNLIKELY(
            (uint8_t const *)fn_name_end > calldata.end ||
            fn_name_end[-1] != '\0')) {
        return EINVAL;
    }

    dr->fn_data.begin = (uint8_t const *)align_ptr(fn_name_end, 16);
    dr->fn_data.end = calldata.end;
    return 0;
}

struct monad_bv mrv_abi_dynelf_txn_main(struct monad_bv const calldata)
{
    mrv_err_t err;
    struct mrv_abi_rv64_decode_result rv64_call;
    mrv_abi_rv64_func_t *fn;

    err = mrv_abi_rv64_decode_calldata(calldata, &rv64_call);
    if (err) {
        MRV_PANIC(err, "mrv_abi_rv64_decode_calldata failed");
    }

#if 0
  mrv_rtld_t contract;
  mrv_rtld_open_contract(&contract, MRV_RTLD_SELF, 0); // dlopen(3)
  mrv_rtld_lookup_symbol(&contract, abi_decode.fn_name, &fn); // dlsym(3)

  return (*fn)(abi_decode.param_cc, abi_decode.fn_data);
#endif
    MRV_PANIC(ENOSYS, "rtld not implemented yet");
}
