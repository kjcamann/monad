#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/strview.h>

#include <mrv/stdlib/evm.h>

#ifdef __cplusplus
extern "C"
{
#endif

[[noreturn]] void
    mrv_exit_with_sv(mrv_evm_exit_type_t, monad_abi_t, struct monad_sv);

[[noreturn]] void mrv_exit_with_uint(
    mrv_evm_exit_type_t, monad_abi_t, void const *, size_t nbytes);

[[gnu::always_inline, noreturn]] static inline void mrv_exit_with_bool(
    mrv_evm_exit_type_t const type, monad_abi_t const abi, bool const b)
{
    uint8_t const u = b ? 1 : 0;
    mrv_exit_with_uint(type, abi, &u, sizeof u);
}

[[gnu::always_inline, noreturn]] static inline void mrv_exit_with_cstr(
    mrv_evm_exit_type_t const type, monad_abi_t const abi, char const *const s)
{
    mrv_exit_with_sv(type, abi, monad_sv_from_cstr(s));
}

[[gnu::always_inline, noreturn]] static inline void
mrv_revert_with_sv(monad_abi_t const abi, struct monad_sv const sv)
{
    mrv_exit_with_sv(MRV_EVM_REVERT, abi, sv);
}

[[gnu::always_inline, noreturn]] static inline void
mrv_revert_with_cstr(monad_abi_t const abi, char const *const s)
{
    mrv_exit_with_sv(MRV_EVM_REVERT, abi, monad_sv_from_cstr(s));
}

[[gnu::always_inline, noreturn]] static inline void
mrv_return_sv(monad_abi_t const abi, struct monad_sv const sv)
{
    mrv_exit_with_sv(MRV_EVM_RETURN, abi, sv);
}

[[gnu::always_inline, noreturn]] static inline void
mrv_return_cstr(monad_abi_t const abi, char const *const s)
{
    mrv_exit_with_sv(MRV_EVM_RETURN, abi, monad_sv_from_cstr(s));
}

[[gnu::always_inline, noreturn]] static inline void
mrv_return_uint(monad_abi_t const abi, void const *const u, size_t const nbytes)
{
    mrv_exit_with_uint(MRV_EVM_RETURN, abi, u, nbytes);
}

[[gnu::always_inline, noreturn]] static inline void
mrv_return_bool(monad_abi_t const abi, bool const b)
{
    mrv_exit_with_bool(MRV_EVM_RETURN, abi, b);
}

#ifdef __cplusplus
} // extern "C"
#endif
