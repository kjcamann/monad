#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include <monad/core/thread.h>

thread_local monad_tid_t _monad_tl_tid = 0;

static_assert(sizeof(monad_tid_t) >= sizeof(pid_t));

void _monad_tl_tid_init()
{
    _monad_tl_tid = gettid();
}

int monad_thread_set_name(char const *name)
{
    return pthread_setname_np(pthread_self(), name);
}

int monad_thread_get_stack(pthread_t thread, void **stack_addr, size_t *stack_size)
{
    int rc;
    pthread_attr_t thread_attrs;

    if (stack_addr == nullptr || stack_size == nullptr) {
        return EFAULT;
    }
    *stack_addr = nullptr;
    *stack_size = 0;
    rc = pthread_getattr_np(thread, &thread_attrs);
    if (rc != 0) {
        return rc;
    }
    rc = pthread_attr_getstack(&thread_attrs, stack_addr, stack_size);
    if (rc != 0) {
        return rc;
    }
    (void)pthread_attr_destroy(&thread_attrs);
    return 0;
}
