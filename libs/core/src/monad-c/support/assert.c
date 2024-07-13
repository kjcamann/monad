#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <monad-c/support/assert.h>

static inline const char *get_filename(const char *path) {
    const char *scan;
    if (path == nullptr)
        return "<unknown>";
    scan = path + strlen(path);
    while (scan != path && *scan != '/')
        --scan;
    return scan == path ? "<unknown>" : scan + 1;
}

[[gnu::weak]] void
monad_assert_failed(const struct monad_source_location *srcloc,
                    const char *expr, const char *format, va_list ap) {
    fprintf(stderr, "assertion failed at %s@%s:%u: %s\n", srcloc->function,
            get_filename(srcloc->file), srcloc->line, expr);
    if (format != nullptr) {
        fprintf(stderr, "message: ");
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    }
    abort();
}