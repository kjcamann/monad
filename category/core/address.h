#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/hex.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_address
{
    uint8_t bytes[20];
};

constexpr struct monad_address MONAD_ADDRESS_ZERO = {};

char const *monad_address_to_hex_static(struct monad_address const *);

[[gnu::always_inline]] static inline int
monad_address_to_hex(struct monad_address const *addr, char *buf, size_t buflen)
{
    return monad_format_hex(
        addr->bytes, sizeof addr->bytes, buf, buflen, MONAD_HEX_DEFAULT);
}

[[gnu::always_inline]] static int monad_address_from_hex(
    char const *buf, size_t buflen, struct monad_address *addr)
{
    int rc;
    size_t s = sizeof *addr;
    rc = monad_parse_hex(buf, buflen, addr, &s);
    // XXX: we don't permit stripping leading zeros, should we?
    return s < sizeof *addr ? EINVAL : rc;
}

[[gnu::always_inline]] static inline int monad_address_cmp(
    struct monad_address const *lhs, struct monad_address const *rhs)
{
    return __builtin_memcmp(lhs, rhs, sizeof *lhs);
}

[[gnu::always_inline]] static inline bool monad_address_eq(
    struct monad_address const *lhs, struct monad_address const *rhs)
{
    return monad_address_cmp(lhs, rhs) == 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
