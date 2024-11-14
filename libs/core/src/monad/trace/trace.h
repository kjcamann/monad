#pragma once

#include <pthread.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/// Setup the tracer output file, event descriptor ring, and its worker threads
extern int monad_trace_init(char const *file_name, int fd, uint8_t ring_shift,
    struct monad_allocator *, pthread_t *recorder_thread,
    pthread_t *sync_thread);

/// Shut down the tracer
extern void monad_trace_shutdown();

/// Set the domain enable mask for the tracer
extern void monad_trace_set_domain_mask(uint64_t domain_mask);

/// Get information about the last error
extern char const *monad_trace_get_last_error();

#ifdef __cplusplus
} // extern "C"
#endif
