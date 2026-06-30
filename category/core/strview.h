#pragma once

#include <stddef.h>
#include <string.h>

struct monad_sv
{
    char const *begin;
    char const *end;
};

struct monad_zsv
{
    char const *begin;
    char const *end;
};

constexpr struct monad_sv MONAD_SV_EMPTY = {};

constexpr size_t MONAD_SV_ALL = (size_t)-1UL;

[[gnu::always_inline]] static inline struct monad_sv
monad_sv_from_size(char const *s, size_t len)
{
    return (struct monad_sv){.begin = s, .end = s + len};
}

[[gnu::always_inline]] static inline struct monad_sv
monad_sv_from_pair(char const *b, char const *e)
{
    return (struct monad_sv){.begin = b, .end = e};
}

[[gnu::always_inline]] static inline struct monad_sv
monad_sv_from_cstr(char const *s)
{
    return (struct monad_sv){.begin = s, .end = s + strlen(s)};
}

[[gnu::always_inline]] static inline struct monad_zsv
monad_zsv_from_cstr(char const *s)
{
    const struct monad_sv sv = monad_sv_from_cstr(s);
    return (struct monad_zsv){.begin = sv.begin, .end = sv.end};
}

[[gnu::always_inline]] static inline char const *monad_sv_split_strchr(
    struct monad_sv sv, int chr, struct monad_sv *left, struct monad_sv *right)
{
    char const *const s = strchr(sv.begin, chr);
    if (s == nullptr) {
        *left = sv;
        *right = MONAD_SV_EMPTY;
    }
    else {
        *left = monad_sv_from_pair(sv.begin, s);
        *right = monad_sv_from_pair(s + 1, sv.end);
    }
    return s;
}

[[gnu::always_inline]] static inline size_t monad_sv_len(struct monad_sv sv)
{
    return (size_t)(sv.end - sv.begin);
}

int monad_sv_strncpy(char *buf, size_t len, struct monad_sv sv);
