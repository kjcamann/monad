#pragma once

/**
 * @file
 *
 * This file defines the interface for our lightweight fiber library
 */

#include <stddef.h>
#include <stdint.h>

#include <monad/core/c_result.h>
#include <monad/mem/cma/cma_alloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct monad_fiber monad_fiber_t;
typedef struct monad_fiber_args monad_fiber_args_t;
typedef struct monad_fiber_attr monad_fiber_attr_t;
typedef struct monad_fiber_suspend_info monad_fiber_suspend_info_t;

typedef monad_c_result(monad_fiber_ffunc_t)(monad_fiber_args_t);
typedef int64_t monad_fiber_prio_t;

// TODO(ken): https://github.com/monad-crypto/monad-internal/issues/498
static monad_fiber_prio_t const MONAD_FIBER_PRIO_HIGHEST = INT64_MIN;
static monad_fiber_prio_t const MONAD_FIBER_PRIO_LOWEST = INT64_MAX - 1;
static monad_fiber_prio_t const MONAD_FIBER_PRIO_NO_CHANGE = INT64_MAX;

#define MONAD_FIBER_MAX_ARGS (4)

enum monad_fiber_suspend_type : unsigned
{
    MF_SUSPEND_NONE,
    MF_SUSPEND_YIELD,
    MF_SUSPEND_SLEEP,
    MF_SUSPEND_RETURN
};

/// When a fiber is suspended, monad_fiber_run will fill out one of these
/// structures to describe the reason for the suspension
struct monad_fiber_suspend_info
{
    enum monad_fiber_suspend_type suspend_type; ///< Reason for last suspension
    monad_c_result eval; ///< Value (for YIELD / RETURN)
};

/// Opaque arguments are passed into fiber functions using this structure
struct monad_fiber_args
{
    uintptr_t arg[MONAD_FIBER_MAX_ARGS];
};

/// Creation attributes for monad_fiber_create
struct monad_fiber_attr
{
    size_t stack_size; ///< Size of fiber stack
    monad_allocator_t *alloc; ///< Allocator used for the monad_fiber_t object
};

/*
 * Public interface: functions that are called by users of the library
 */

/// Create a fiber, given a description of its attributes (if nullptr is passed,
/// the default attributes will be used)
int monad_fiber_create(
    monad_fiber_attr_t const *create_attr, monad_fiber_t **fiber);

/// Destroy a fiber previously created with monad_fiber_create
void monad_fiber_destroy(monad_fiber_t *fiber);

/// Set the function that the fiber will run; this may be called multiple times,
/// to reuse the fiber's resources (e.g., its stack) to run new functions
int monad_fiber_set_function(
    monad_fiber_t *fiber, monad_fiber_prio_t priority,
    monad_fiber_ffunc_t *ffunc, monad_fiber_args_t fargs);

/// Returns the structure representing the currently executing fiber; returns
/// nullptr if the current execution context is not a fiber, i.e., if it is an
/// ordinary thread
static monad_fiber_t *monad_fiber_self();

/// Begin running a fiber's function on the calling thread, or resume that
/// function at the suspension point, if it was suspended; this call returns the
/// next time the function suspends, and populates @ref suspend_info with info
/// about that suspension
static int monad_fiber_run(
    monad_fiber_t *next_fiber, monad_fiber_suspend_info_t *suspend_info);

/// Similar to sched_yield(2) or pthread_yield_np(3), but for fibers: yields
/// from the currently-running fiber back to the previously-running fiber
static void monad_fiber_yield(monad_c_result eval);

struct monad_fiber
{
    monad_fiber_prio_t priority; ///< Scheduling priority
};

#if __cplusplus
} // extern "C"
#endif
