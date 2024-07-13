#include <monad-c/support/result.h>
#include <monad-c/support/thread.h>

#include <pthread.h>
#if defined(__linux__)
#include <unistd.h>
#endif

/*
 * mcl_thread_get_id
 */

#if defined(__APPLE__)
monad_result mcl_thread_get_id() {
    uint64_t id;
    int rc;
    rc = pthread_threadid_np(pthread_self(), &id);
    if (rc != 0)
        return monad_make_sys_error(rc);
    return monad_ok((intptr_t)id);
}
#elif defined(__linux__)
monad_result mcl_thread_get_id() {
    return monad_ok(gettid()); // Call is always successful
}
#else
#error define mcl_thread_get_id for this platform
#endif

/*
 * mcl_thread_set_name
 */

#if defined(__APPLE__)
monad_result mcl_thread_set_name(const char *name) {
    pthread_setname_np(name);
    return monad_ok(0);
}
#elif defined(__linux__)
monad_result mcl_thread_set_name(const char *name) {
    int rc = pthread_setname_np(pthread_self(), name);
    if (rc != 0)
        return monad_make_sys_error(rc);
    return monad_ok(0);
}
#else
#error define mcl_thread_set_name for this platform
#endif
