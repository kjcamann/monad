# `monad_fiber` design notes

## Goals and overview

### An analogy to threads

The design goal of the `monad_fiber` library can be explained via an
analogy to the UNIX threading model. UNIX threads involve the following:

- **Thread objects** - the POSIX `pthread` library allows an application
  to explicitly create, start, and stop threads
- **Synchronization objects (explicit coordination)** - `pthread` offers
  synchronization primitives, such as `pthread_mutex_t`, that allow threads
  to *explicitly* coordinate with each other
- **I/O operations (implicit coordination)** - the kernel offers blocking
  I/O routines such as `read(2)` and `write(2)`. These routines may start
  long-running operations which cause a thread to yield the CPU and go to
  sleep, allowing other threads to run. This allows threads to *implicitly*
  coordinate
- **Scheduling** - the kernel offers a thread scheduler, which is
  responsible for deciding which threads will run on which CPUs; it also
  communicates with the coordination mechanisms (the synchronization
  primitives and the I/O subsystem) to know when it is time to "wake up"
  a sleeping thread

Needless to say, such a system is complex.

### Simplicity: the goal of `monad_fiber`

Fiber libraries are often full-fledged "frameworks", because they try to
capture all the sophistication and features that an OS-level threading
system has. The `monad_fiber` code makes an effort to be much simpler, and
decidedly does not have many features. It is designed to do only what the
downstream code needs at the current moment. It sacrifices being generic
and extensible in favor of being simple, and thus (hopefully) easy to
change as our internal needs change.

`monad_fiber` offers three things:

1. A fiber object, `monad_fiber_t`, that allows the creation and running
   of fibers
2. A small number of synchronization primitives; these are added (and
   removed) as needed
3. A trivial scheduling model, based on a thread-safe priority queue

The coupling between the three parts is minimal, and occurs in only a few
lines of code.

There is no support for I/O operations. I/O-based voluntary context
switching does exist within the monad codebase, but its scheduling needs
and cooperation mechanism are completely different, so it is handled in a
different part of the system.

The implementation is meant to be clear; ideally a programmer can
understand it fully without much trouble. Take this with a grain of salt
though: context-switching code can be tricky, so understanding all the
implementation details will require some time investment!

### "Hello, world!" using fibers

The following listing shows a "Hello, World!" example written in C that
only uses a fiber object. This example contains no synchronization
primitives and thus does not need any scheduling code (the fiber is
run "manually"). The fiber prints a "Hello, World!" style message three
times, suspending itself after each message is printed. After the last
message, the fiber finishes.

```.c
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#include <monad/core/c_result.h>
#include <monad/fiber/fiber.h>

// This is the function that will run on the fiber
monad_c_result say_hello_fiber_function(monad_fiber_args_t mfa)
{
    // The fiber greets you by your name, which is passed in as the fiber's
    // first function argument
    char const *const name = (char const *)mfa.arg[0];

    // Say hello, then suspend the fiber
    printf("Hello, %s!\n", name);
    monad_fiber_yield(monad_c_make_success(0));

    // When we reach here, we've been run again; we resume from the
    // suspension point of the yield immediately above. We'll say hello
    // again, then suspend again
    printf("Welcome back, %s!\n", name);
    monad_fiber_yield(monad_c_make_success(0));

    // Resumed for the final time; say goodbye, then return. Returning from
    // the fiber function suspends the fiber until it is given a new function
    // to run
    printf("Farewell, %s!\n", name);
    return monad_c_make_success(0);
}

int main(int argc, char **argv)
{
    int rc;
    monad_fiber_t *hello_fiber;
    char const *name;
    monad_allocator_t *const alloc = nullptr; // Use default allocator
    monad_fiber_attr_t const fiber_attr = {
        .stack_size = 1UL << 17, // 128 KiB stack
        .alloc = alloc
    };

    // This application says hello to you using a fiber; it expects your name
    // as the first (and only) positional argument
    if (argc != 2) {
        errx(EX_USAGE, "usage: %s <your-name>", argv[0]);
    }
    name = argv[1];

    // Create the fiber, passing in our creation attributes
    rc = monad_fiber_create(&fiber_attr, &hello_fiber);
    if (rc != 0) {
        errno = rc;
        err(1, "monad_fiber_create failed");
    }

    // Tell the fiber what function to run; the second argument is
    // the scheduling priority, which doesn't matter in this example;
    // the last parameter is passed into the fiber function, as the
    // argument. We pass a pointer to our name
    rc = monad_fiber_set_function(
        hello_fiber,
        MONAD_FIBER_PRIO_HIGHEST,
        say_hello_fiber_function,
        (monad_fiber_args_t){.arg = {(uintptr_t)name}});
    assert(rc == 0);

    // Run the fiber until the first suspension point; this will print
    // "Hello, <name>!", suspend the fiber function, and then our call to
    // monad_fiber_run will return. If nothing goes wrong, the return code
    // will be 0. The second parameter (which is nullptr here) allows us to
    // obtain information about why the fiber suspended; in this example we
    // don't care, so we pass nullptr
    rc = monad_fiber_run(hello_fiber, nullptr);
    assert(rc == 0);

    // Run the fiber again, until it yields again; this will print
    // "Welcome back, <name>!" and then yield back to us once more
    rc = monad_fiber_run(hello_fiber, nullptr);
    assert(rc == 0);

    // Run the fiber a final time. This will print "Farewell, <name>!" and then
    // the fiber function will return. The return won't look much different to
    // us than the yields above: the fiber will suspend and monad_fiber_run will
    // return 0 to us, as before. The difference is, we can't run the fiber
    // again. If, instead of passing nullptr as the second argument, we instead
    // passed a pointer to a `monad_fiber_suspend_info_t`, we could get more
    // information about the suspension. Namely, that it was a return and not a
    // yield, and we could also read the `monad_c_result` return code. However,
    // we don't care in this example.
    rc = monad_fiber_run(hello_fiber, nullptr);
    assert(rc == 0);

    // Try to run the fiber one more time; we can't do it since the fiber
    // function returned, so this will fail and return the errno-domain error
    // code ENXIO
    rc = monad_fiber_run(hello_fiber, nullptr);
    assert(rc == ENXIO);

    // At this point, we could reuse the fiber's resources to run the function
    // a second time. To prepare for a second run, we would reset the function:
    rc = monad_fiber_set_function(
        hello_fiber,
        MONAD_FIBER_PRIO_HIGHEST,
        say_hello_fiber_function,
        (monad_fiber_args_t){.arg = {(uintptr_t)name}});
    assert(rc == 0);

    // However, that's enough for today; destroy the fiber and exit.
    monad_fiber_destroy(hello_fiber);
    return 0;
}
```

## Where is the code?

1. For the fibers themselves:
   - `fiber.h` - defines the interface for fibers, i.e., the public
     functions and the central `monad_fiber_t` structure
   - `fiber_inline.h` - most of the implementation is here, so it can be
     inlined for performance reasons
   - `fiber.c` - implementation file for fiber functions whose performance
     is not critical
   - `fiber_thr.c` - an implementation file which contains the `thread_local`
     state for the `monad_thread_executor_t` objects

2. For the synchronization primitives:
   - To be added in a subsequent commit

3. The "scheduler"
   - `monad_run_queue.h` - defines the interface for a simple thread-safe
     priority queue of `monad_fiber_t*` objects
   - `monad_run_queue.c` - implementation file for `monad_run_queue.h`

### Why is "scheduler" in quotes above?

To keep the design simple and less monolithic, the `monad_fiber` library does
not have a full-fledged scheduler, or any higher-level abstractions such as a
task pool, run-loop, worker threads, etc.

The intention is for the user code to solve its problem directly, creating
complex objects only if it needs them, and using `monad_fiber` as a bare-bones
helper module. The only point of coupling between the three parts of a fiber
system is the priority queue, `monad_run_queue_t`.

A `monad_fiber_t` keeps track of an associated `monad_run_queue_t*`, and when
the fiber is signaled for wakeup by a synchronization primitive, the fiber
"wakes up" by re-enqueueing itself back on this associated priority queue.

The library does not run anything by itself. Instead it offers a single
function (`monad_fiber_run`) to start or resume a fiber, which runs the fiber's
function until that function reaches a suspension point -- at which point
`monad_fiber_run` just returns. The library does little beyond that.

The only other "automatic" thing it does is re-enqueue the fiber on a priority
queue if a synchronization primitive wakes the fiber. The user of the library
must create their own concepts like worker threads, pools, etc. to
enqueue/dequeue fibers from a `monad_run_queue_t`. The exact topology and way
of doing this is not specified by the library.

## `monad_fiber_t` basic design

### How to use `monad_fiber_t`

A fiber is an execution resource for an ordinary function having this
signature type:

```.h
typedef monad_c_result (monad_fiber_ffunc_t)(monad_fiber_args_t);
```

The fiber runs this function until the function decides to suspend itself,
either by yielding, returning, or going to sleep on some synchronization
condition that is not met yet (e.g., waiting for a semaphore to signal).
When the fiber suspends, the current thread will begin executing the code
for a different fiber. The suspended fiber may later be resumed, at which
point execution continues at the point where it left off.

#### Why `monad_fiber_args_t`?

In conventional C programming, a user-provided function takes a single
opaque argument for the user's private data. This usually has type
`void *`, e.g., as in `pthread_create(3)`. Instead of doing this, fibers
take an instance of this structure:

```.h
struct monad_fiber_args
{
    uintptr_t arg[MONAD_FIBER_MAX_ARGS];
};
```

This design is meant to be friendlier to C++ clients of the C library.
C++ has stronger idiomatic use of value types than C does, e.g., types
like `std::string_view` or `std::span<double>`. Because C programs use
value semantics more sparsely, the natural number of function parameters
is usually just one: you either have a fundamental type, or you pass a
pointer to a more complex type.

For C++, there are many useful, value-like types that are the size of two
or three pointers. Forcing these to be located at a stable memory address
just so a memory reference to them can be passed around can be burdensome.
For example, even though a `std::string_view` points to stable,
externally-managed memory, the `std::string_view` object itself is usually
a stack-allocated value type. It is an ephemeral object without a stable
address.

The solution chosen here is to wrap a small set of opaque arguments into
a C value type, which is nonetheless small enough to be passed in registers
after it is disaggregated into scalars during optimization.

#### Running and suspending fibers

Most of the implementation can be understood by thinking about exactly
how and when a fiber performs a context switch. The model we follow is:

- A fiber is started or resumed by calling the `monad_fiber_run`
  function, passing in the `monad_fiber_t*` describing the fiber that the
  user wants to run; that is, the context that _calls_ `monad_fiber_run`
  will switch into the given fiber and begin (or resume) running its
  associated function

- When a fiber suspends or returns, it jumps back to the context that
  was executing previously. This is the context that was running the code
  for `monad_fiber_run` in the first place, so the suspension of a fiber
  appears to the caller of `monad_fiber_run` as the `monad_fiber_run`
  function call returning back to them

- Consequently, the function that calls `monad_fiber_run` is always
  a lightweight scheduler: it decides to run fibers somehow, and typically
  calls `monad_fiber_run` in a loop, with the sequence of fibers it
  wishes to run

- The most obvious design is to use a single global priority queue
  (a `monad_run_queue_t` object). Each worker takes the
  next-highest-priority fiber and runs it until it suspends

Here is an example of how you might build such a worker thread (this
is just an API example, the current implementation is more complex):

```c
int rc;
monad_fiber_t *fiber;
monad_fiber_suspend_info_t suspend_info;
monad_run_queue_t *const run_queue = /* initialize a fiber priority queue*/

while (!atomic_load(&done)) {
    // Poll the priority queue for the highest priority fiber that's ready
    // to run
    fiber = monad_run_queue_try_pop(run_queue);

    if (fiber == nullptr) {
        continue; // Nothing is ready to run, poll again
    }

    // Run the fiber until it suspends
    rc = monad_fiber_run(fiber, &suspend_info);

    if (rc != 0) {
        /* something went wrong */
    }
    if (suspend_info.suspend_type == MONAD_FIBER_SUSPEND_RETURN) {
        /* fiber function returned; can't run it anymore */
    }
}
```
