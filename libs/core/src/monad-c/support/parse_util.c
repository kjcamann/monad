#include <stdlib.h>
#include <monad-c/support/parse_util.h>

monad_result mcl_parse_int(const char *nptr, intptr_t min_val,
                           intptr_t max_val) {
    intptr_t value;
    char *nptr_end;
    value = strtoll(nptr, &nptr_end, 10);
    return monad_ok(value);
}