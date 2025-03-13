#pragma once

#include <monad/context/config.h>

#include <liburing.h>

// Must come after <liburing.h>, otherwise breaks build on clang
#include <stdatomic.h>

#include "task.h"

#ifdef __cplusplus
extern "C"
{
#endif

//! \brief The public attributes of an executor
typedef struct monad_async_executor_head
{
    // The following are not user modifiable
    MONAD_CONTEXT_PUBLIC_CONST
    MONAD_CONTEXT_ATOMIC(monad_async_task) current_task;
    MONAD_CONTEXT_PUBLIC_CONST
    MONAD_CONTEXT_ATOMIC(size_t) tasks_pending_launch;
    MONAD_CONTEXT_PUBLIC_CONST MONAD_CONTEXT_ATOMIC(size_t) tasks_running;
    MONAD_CONTEXT_PUBLIC_CONST
    MONAD_CONTEXT_ATOMIC(size_t) tasks_suspended_sqe_exhaustion;
    MONAD_CONTEXT_PUBLIC_CONST MONAD_CONTEXT_ATOMIC(size_t) tasks_suspended;

    MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
        total_ticks_in_run;
    MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
        total_ticks_in_task_launch;
    MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
        total_ticks_in_io_uring;
    MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
        total_ticks_sleeping;
    MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
        total_ticks_in_task_completion;

    MONAD_CONTEXT_PUBLIC_CONST uint64_t total_io_submitted, total_io_completed;

    struct
    {
        MONAD_CONTEXT_PUBLIC_CONST size_t total_claimed, total_released;
        MONAD_CONTEXT_PUBLIC_CONST monad_context_cpu_ticks_count_t
            ticks_last_claim,
            ticks_last_release;
    } registered_buffers;
} *monad_async_executor;

//! \brief Returns true if an executor has work before it
static inline bool monad_async_executor_has_work(monad_async_executor ex)
{
#ifdef __cplusplus
    return ex->current_task.load(std::memory_order_acquire) != nullptr ||
           ex->tasks_pending_launch.load(std::memory_order_acquire) > 0 ||
           ex->tasks_running.load(std::memory_order_acquire) > 0 ||
           ex->tasks_suspended_sqe_exhaustion.load(std::memory_order_acquire) >
               0 ||
           ex->tasks_suspended.load(std::memory_order_acquire) > 0;
#else
    return atomic_load_explicit(&ex->current_task, memory_order_acquire) !=
               NULL ||
           atomic_load_explicit(
               &ex->tasks_pending_launch, memory_order_acquire) > 0 ||
           atomic_load_explicit(&ex->tasks_running, memory_order_acquire) > 0 ||
           atomic_load_explicit(
               &ex->tasks_suspended_sqe_exhaustion, memory_order_acquire) > 0 ||
           atomic_load_explicit(&ex->tasks_suspended, memory_order_acquire) > 0;
#endif
}

//! \brief Attributes by which to construct an executor
struct monad_async_executor_attr
{
    struct
    {
        //! \brief If this is zero, this executor will be incapable of doing
        //! i/o! It also no longer initialises io_uring for this executor.
        unsigned entries;
        struct io_uring_params params;

        struct
        {
            //! \brief How many small and large buffers to register.
            unsigned small_count, large_count;
            //! \brief How many of each of small pages and of large pages the
            //! small and large buffer sizes are.
            unsigned small_multiplier, large_multiplier;
            /*! \brief Number of small and large buffers to have io_uring
            allocate during read operations.

            io_uring can allocate i/o buffers at the point of successful read
            which is obviously much more efficient than userspace allocating
            read i/o buffers prior to initiating the read, which ties up i/o
            buffers. However, socket i/o doesn't use the write ring, so if all
            buffers are allocated for read then you would have no buffers for
            writing to sockets. Therefore you may want some of the buffers
            available for userspace allocation, and some for kernel allocation
            depending on use case.

            A further complication is that if you enable this facility, if
            io_uring receives i/o and no buffers remain available to it, it
            will fail the read i/o with a result equivalent to `ENOBUFS`. It
            is 100% on you to free up some buffers and reschedule the read if
            this occurs.

            Note that kernel 6.8 (Ubuntu 24.04) appears to refuse to allocate
            buffers for file i/o only, a future kernel release may fix this.
            https://github.com/axboe/liburing/issues/1214 tracks the feature
            request.
            */
            unsigned small_kernel_allocated_count, large_kernel_allocated_count;
        } registered_buffers;
    } io_uring_ring, io_uring_wr_ring;
};

/*! \brief EXPENSIVE Creates an executor instance. You must create it on the
 kernel thread where it will be used.

Generally, one also needs to create context switcher instances for each
executor instance. This is because the context switcher needs to store how
to resume the executor when a task's execution suspends.

You can optionally create an io_uring instance for the executor by setting
`attr->io_uring_ring.entries` to non-zero. This will then be used to dispatch
work instead of an internal dispatcher.

You may additionally optionally create a second io_uring instance called
"write ring" by setting `attr->io_uring_wr_ring.entries` to non-zero. This
is mandatory if you wish to write to files, otherwise it is not used.

The reason a special io_uring instance is used for operations which modify
files is because a total sequentially consistent order is applied to all file
write operations. This implements a "multi-copy atomic" memory model similar
to that used by ARM microprocessors. This is a weak memory model, but one
sufficient to prevent:

1. Write amplification on the device caused by multiple concurrent writes.

2. Writes appearing to readers not in the order of write submission.

The most efficient way of implementing this weak memory model is a specially
configured io_uring instance, so this is why we have that.

Do NOT use the "write ring" for writes to sockets, it will severely impact
performance!
*/
[[nodiscard]] extern monad_c_result monad_async_executor_create(
    monad_async_executor *ex, struct monad_async_executor_attr *attr);

//! \brief EXPENSIVE Destroys an executor instance.
[[nodiscard]] extern monad_c_result
monad_async_executor_destroy(monad_async_executor ex);

/*! \brief Processes no more than `max_items` work items, returning the number
of items processed. A null `timeout` means wait forever, and a zero timeout will
poll without blocking.

Note that this function is particularly prone to early return i.e. partly
or entirely ignoring timeout. Causes can include being woken externally by
`monad_async_executor_wake()`, there being write i/o pending (as then two
rings need to be checked), and the usual spurious early timeouts from Linux.
If you do complex processing around calling this function, it may be wise
to only do that processing if the value returned is not zero.
*/
[[nodiscard]] extern monad_c_result monad_async_executor_run(
    monad_async_executor ex, size_t max_items, const struct timespec *timeout);

//! \brief THREADSAFE Causes a sleeping executor to wake. Can be called from any
//! kernel thread. `cause_run_to_return` causes `monad_async_executor_run()` to
//! return the result given, otherwise the internal sleep wakes, executor state
//! is examined for new work and the sleep reestablished WHICH MAY NOT CAUSE RUN
//! TO RETURN.
[[nodiscard]] extern monad_c_result monad_async_executor_wake(
    monad_async_executor ex, monad_c_result const *cause_run_to_return);

/*! \brief If new i/o submitted since the last run exceeds
`max_items_in_submission_queue`, invoke io_uring submit now. If submission now
occurs, a positive successful result is returned, otherwise zero.
*/
[[nodiscard]] extern monad_c_result monad_async_executor_submit(
    monad_async_executor ex, size_t max_items_in_nonwrite_submission_queue,
    size_t max_items_in_write_submission_queue);

/*! \brief Return a pointer (as `intptr_t`) to a null terminated string
describing the configuration of this executor. This lets you see what io_uring
features were detected, as well as versions and other config.

\warning You need to call `free()` on the pointer when you are done with it.
*/
[[nodiscard]] extern monad_c_result
monad_async_executor_config_string(
    monad_async_executor ex); // implemented in util.cpp

#ifdef __cplusplus
}
#endif
