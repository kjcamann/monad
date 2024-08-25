# Overview of `monad_allocator_t` (the "CMA allocator")

## What is this?

When library code needs to dynamically allocate memory, it should accept
allocation functions from the outside, rather than calling `malloc(3)`
directly. This allows the user of the library to have some say over how
memory will be allocated.

Accepting such allocation functions is a common pattern in C library code.
Instead of directly passing function pointers, we pass an object that uses
C-style inheritance, called `monad_allocator_t`. This design allows us to
create stateful allocators more easily.

## Example code

The following example shows a function `foo` that dynamically allocates
memory using a `monad_allocator_t`. In the example:

- The libc `calloc(3)` is replaced with `monad_cma_calloc` and `free(3)`
  with `monad_cma_dealloc`
- The function which allocates dynamic memory (`foo`) is called twice, with
  two different allocators: the default allocator and one that uses local
  stack space of the function

```.c
void foo(size_t number_of_foos, monad_allocator_t *ma)
{
    int return_code; // errno(3) domain result of trying to allocate memory
    struct foo *f;   // Set to base address of dynamic foo array
    struct foo *end; // Set to end address of dynamic foo array
    monad_memblk_t mem_block; // Descriptor for allocated memory block

    return_code = monad_cma_calloc(
        ma, number_of_foos, sizeof *f, alignof *f, &mem_block);
    if (mem_block.ptr == nullptr) {
        errc(1, return_code, "monad_cma_calloc failed!");
    }

    for (f = mem_block.ptr, end = f + number_of_foos; f != end; ++f) {
        do_something_with_foo(f);
    }

    // We're in C, don't forget to free your memory!
    monad_cma_dealloc(ma, mem_block);
}

void call_foo_with_default_allocator()
{
    // If `nullptr` is passed to the `monad_cma_` functions, they will first
    // call `monad_cma_get_default_allocator()` and you will get the
    // process-wide default allocator (which you may also change)
    monad_allocator_t *const my_allocator = nullptr;

    // This will dynamically allocate memory for 1024 foo objects using
    // the default allocator
    foo(1024, my_allocator);
}

int call_foo_with_stack_allocator(size_t foo_count)
{
    // In this example, we'll use alloca(3) to grab a large block of stack
    // space, then allocate from it. This kind of allocator is sometimes
    // called a "bump pointer allocator".
    monad_memblk_t stack_space;
    struct monad_cma_bump_alloc stack_alloc;
    int rc;

    // Note: the extra alignof factor here is because we don't know if the
    // alloca(3) base address will be suitably aligned, e.g., if `struct foo`
    // is over-aligned type
    stack_space.size = sizeof(struct foo) * foo_count + alignof(struct foo);
    if (stack_space.size > STACK_SPACE_LIMIT) {
        return ENOMEM; // This would alloca(3) too much space
    }

    stack_space.ptr = alloca(stack_space.size);
    rc = monad_cma_bump_alloc_init(&stack_alloc, stack_space);
    if (rc != 0) {
        errc(1, rc, "monad_cma_bump_alloc_init failed!");
    }

    foo(foo_count, &stack_alloc);
}
```

The interface is similar to the `stdlib.h` memory management functions,
except:

- The caller is explicitly given a structure type (`monad_memblk_t` or
  "memory block") that represents the address and total size of the
  allocation (the total size might be larger than requested)

- The allocation functions accept a pointer to a `monad_allocator_t` object,
  which uses C-style inheritance and holds the state of a particular
  allocator

## Implementation details

### Where does the design come from?

Rather than invent a novel interface, the approach used here is a C23
reimplementation of a memory allocation interface originally designed by
Andrei Alexandrescu. It was presented at CppCon 2015 in a talk titled
"std::allocator Is to Allocation what std::vector Is to Vexation". The
presentation can be found on YouTube [here](https://www.youtube.com/watch?v=LIb3L4vKZ7U).

The goal of that approach was to discover a better interface for composing
memory allocation strategies together, thus our implementation uses the name
"composable memory allocator" (or "CMA") in the code.

This is not a complete implementation, and it is also not a straight
reimplementation of the exact system Alexandrescu designed. The fancier
features of the original will be added only if the need arises.
