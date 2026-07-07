#include <stddef.h>
#include <stdio.h>

void monad_stack_backtrace_capture_and_print(
    char *const buffer, size_t const size, int const fd, unsigned const indent,
    bool const print_async_unsafe_info)
{
    dprintf(fd, "backtrace unimplemented\n");
}
