#include <err.h>
#include <pthread.h>
#include <stdint.h>

#include <monad/core/assert.h>
#include <monad/core/thread.h>

static_assert(sizeof(monad_tid_t) >= sizeof(uint64_t));

thread_local monad_tid_t _monad_tl_tid = 0;

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

int monad_thread_get_stack(pthread_t thread, void **stack_addr, size_t *stack_size)
{
    if (stack_addr == nullptr || stack_size == nullptr) {
        return EFAULT;
    }
    *stack_addr = pthread_get_stackaddr_np(thread);
    *stack_size = pthread_get_stacksize_np(thread);
    return 0;
}
