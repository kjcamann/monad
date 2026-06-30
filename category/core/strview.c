#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <category/core/strview.h>

int monad_sv_strncpy(char *buf, size_t len, struct monad_sv sv)
{
    size_t const required = monad_sv_len(sv);
    if (len < required + 1) {
        return ERANGE;
    }
    *(char *)mempcpy(buf, sv.begin, required) = '\0';
    return 0;
}
