#include <err.h>
#include <pthread.h>
#include <stdint.h>

#include <monad/core/assert.h>
#include <monad/core/thread.h>

static_assert(sizeof(monad_tid_t) >= sizeof(uint64_t));

__thread monad_tid_t _monad_tl_tid = 0;

void _monad_tl_tid_init()
{
    uint64_t tid;
    int const rc = pthread_threadid_np(pthread_self(), &tid);
    MONAD_ASSERT(rc == 0);
    _monad_tl_tid = (monad_tid_t)tid;
}

int monad_thread_set_name(char const *name)
{
    pthread_setname_np(name);
    return 0;
}
