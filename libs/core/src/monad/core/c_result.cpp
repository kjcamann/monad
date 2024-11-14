#include <bit>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <type_traits>

#include <monad/core/c_result.h>

extern char const *__progname;

extern "C" void monad_verrc(
    int eval, cxx_status_code_system err_code, char const *format,
    std::va_list ap)
{
    using sys_code_t = BOOST_OUTCOME_V2_NAMESPACE::experimental::system_code;
    std::fprintf(stderr, "%s: ", __progname);
    if (format) {
        std::vfprintf(stderr, format, ap);
    }
    auto *cxx_code = std::bit_cast<sys_code_t *>(&err_code);
    std::fprintf(
        stderr,
        ": %s (%s:%ld)\n",
        cxx_code->message().c_str(),
        cxx_code->domain().name().c_str(),
        cxx_code->value());
    std::exit(eval);
}
