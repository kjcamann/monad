#include <errno.h>
#include <stddef.h>

#include <category/core/event/event_ring_util.h>
#include <category/core/format_err.h>
#include <category/core/srcloc.h>

// Defined in event_ring.c, so we can share monad_event_ring_get_last_error()
extern thread_local char _g_monad_event_ring_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        _g_monad_event_ring_error_buf,                                         \
        sizeof(_g_monad_event_ring_error_buf),                                 \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

int monad_event_ring_query_flocks(
    int, struct monad_event_flock_info *, size_t *)
{
    return FORMAT_ERRC(ENOSYS, "function not available on non-Linux platforms");
}

int monad_event_ring_wait_for_excl_writer(
    char const *, struct timespec const *, sigset_t const *, int, int *,
    pid_t *)
{
    return FORMAT_ERRC(ENOSYS, "function not available on non-Linux platforms");
}

int monad_check_path_supports_map_hugetlb(char const *, bool *supported)
{
    *supported = false;
    return 0;
}
