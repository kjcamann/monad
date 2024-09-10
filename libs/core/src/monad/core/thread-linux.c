#include <pthread.h>
#include <unistd.h>

#include <monad/core/thread.h>

__thread monad_tid_t _monad_tl_tid = 0;

static_assert(sizeof(monad_tid_t) >= sizeof(pid_t));

void _monad_tl_tid_init()
{
    _monad_tl_tid = gettid();
}

int monad_thread_set_name(char const *name)
{
    return pthread_setname_np(pthread_self(), name);
}
