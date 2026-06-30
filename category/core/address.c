#include <category/core/address.h>

static char s_hex_addr_buf[sizeof(struct monad_address) * 2 + 1];

char const *monad_address_to_hex_static(struct monad_address const *addr)
{
    (void)monad_address_to_hex(addr, s_hex_addr_buf, sizeof s_hex_addr_buf);
    return s_hex_addr_buf;
}
