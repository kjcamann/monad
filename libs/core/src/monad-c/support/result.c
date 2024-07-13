#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <monad-c/support/result.h>

static char *describe_error(monad_result mr, char *buf, size_t length) {
    if (strlcpy(buf, "<details not available>", length) >= length)
        buf[length - 1] = '\0';
    return buf;
}

void monad_diagnose_value_on_error(monad_result mr) {
    char errbuf[2048];
    fprintf(stderr, "tried to get value from monad_result but contains error: %s",
            describe_error(mr, errbuf, sizeof errbuf));
    abort();
}

void mcl_errc(int eval, monad_result mr, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    mcl_verrc(eval, mr, fmt, ap);
    va_end(ap);
}

void mcl_verrc(int eval, monad_result mr, const char *fmt, va_list ap) {
    char errbuf[2048];
    const char *const progname = getprogname();
    (void)fprintf(stderr, "%s: ", progname);
    if (!monad_is_error(mr)) {
        (void)fprintf(stderr,
                      "called mcl_errc with a result not holding an error\n");
        (void)fprintf(stderr, "%s: ", progname);
    }
    if (fmt != nullptr) {
        (void)vfprintf(stderr, fmt, ap);
        (void)fprintf(stderr, ": ");
    }
    (void)fprintf(stderr, "%s", describe_error(mr, errbuf, sizeof errbuf));
    exit(eval);
}