#include <errno.h>
#include <stddef.h>

#include <category/core/address.h>
#include <category/core/likely.h>

thread_local static char s_hex_addr_buf[sizeof(monad_address) * 2 + 1];

int monad_address_to_hex(
    monad_address const *addr, char *buf, size_t buflen)
{
    if (MONAD_UNLIKELY(buflen < sizeof(*addr) * 2)) {
        return E2BIG;
    }
    monad_address_to_hex_unchecked(addr, buf);
    return 0;
}

char const *monad_address_to_hex_static(monad_address const *addr)
{
    monad_address_to_hex_unchecked(addr, s_hex_addr_buf);
    return s_hex_addr_buf;
}
