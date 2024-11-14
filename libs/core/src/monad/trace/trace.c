#include <stdatomic.h>
#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <unistd.h>

#include <monad/core/likely.h>
#include <monad/core/spinlock.h>
#include <monad/core/srcloc.h>
#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_recorder.h>
#include <monad/event/event_session.h>
#include <monad/event/event_shared.h>
#include <monad/event/event_shmem.h>
#include <monad/mem/align.h>
#include <monad/mem/cma/cma_alloc.h>
#include <monad/trace/trace.h>
#include <monad/trace/trace_file.h>

extern char const *__progname;
static thread_local char g_error_buf[1024];

__attribute__((format(printf, 3, 4))) static int format_errc(
    monad_source_location_t const *srcloc, int err, char const *format, ...)
{
    int rc;
    va_list ap;
    va_start(ap, format);
    rc = _monad_event_vformat_err(
        g_error_buf, sizeof g_error_buf, srcloc, err, format, ap);
    va_end(ap);
    return rc;
}

#define FORMAT_ERRC(ERRC, FORMAT, ...)                                         \
    format_errc(                                                               \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        ERRC,                                                                  \
        FORMAT __VA_OPT__(, ) __VA_ARGS__)

__attribute__((format(printf, 3, 4)))
static void monad_trace_shutdown_internal(monad_source_location_t const *srcloc,
    int error_code, char const *format, ...);

/*
 * Trace page pool
 */

static size_t const TRACE_PAGE_POOL_SIZE = 16;

struct monad_trace_page_pool;

struct monad_trace_page
{
    uint8_t *heap_begin;
    uint8_t *heap_next;
    uint8_t *heap_end;
    uint64_t event_count;
    struct monad_trace_page_pool *page_pool;
    TAILQ_ENTRY(monad_trace_page) page_link;
};

struct monad_trace_page_pool
{
    alignas(64) pthread_mutex_t mtx;
    pthread_cond_t sync_cond;
    struct monad_trace_page *active_page;
    TAILQ_HEAD(, monad_trace_page) sync_pages;
    TAILQ_HEAD(, monad_trace_page) free_pages;
    size_t sync_page_count;
    size_t free_page_count;
    size_t trace_pages_written;
    size_t trace_pages_allocated;
};

// Allocate new trace pages from the system, to populate the page pool's free
// list
static struct monad_trace_page *mmap_trace_page()
{
    struct monad_trace_page *page;
    size_t const PAGE_2MB = 1UL << 21;
#if defined(__linux__)
    int const map_flags = MAP_ANON | MAP_PRIVATE | MAP_HUGETLB;
#else
    int const map_flags = MAP_ANON | MAP_PRIVATE;
#endif

    page = mmap(nullptr, PAGE_2MB, PROT_READ | PROT_WRITE, map_flags, -1, 0);
    if (page == MAP_FAILED) {
        errno = FORMAT_ERRC(errno, "mmap(2) failed, cannot allocate trace page");
        return MAP_FAILED;
    }
    memset(page, 0, sizeof *page);
    page->heap_begin = page->heap_next = (uint8_t *)(page + 1);
    page->heap_end = (uint8_t *)page + PAGE_2MB;

    return page;
}

// Called when the active trace page is full, to deactivate it and allocate a
// fresh page to take its place. This also signals the sync thread's condition
// variable so it can wake up to flush the contents to disk
static struct monad_trace_page *
deactivate_trace_page(struct monad_trace_page *page)
{
    struct monad_trace_page_pool *page_pool = page->page_pool;
    pthread_mutex_lock(&page_pool->mtx);
    TAILQ_INSERT_TAIL(&page_pool->sync_pages, page_pool->active_page, page_link);
    page_pool->active_page = TAILQ_FIRST(&page_pool->free_pages);
    --page_pool->free_page_count;
    ++page_pool->sync_page_count;
    if (MONAD_UNLIKELY(page_pool->active_page == nullptr)) {
        pthread_mutex_unlock(&page_pool->mtx);
        monad_trace_shutdown_internal(&MONAD_SOURCE_LOCATION_CURRENT(), ENOMEM,
            "exhausted all %lu trace pages", TRACE_PAGE_POOL_SIZE);
        return nullptr;
    }
    page_pool->active_page->heap_next = page_pool->active_page->heap_begin;
    page_pool->active_page->event_count = 0;
    pthread_mutex_unlock(&page_pool->mtx);
    pthread_cond_signal(&page_pool->sync_cond);
    return page_pool->active_page;
}

void cleanup_page_pool(struct monad_trace_page_pool *page_pool)
{
    // Free the page pool resources; the page pool mutex is not held when this
    // is called, because all trace worker threads that use the page pool
    // should be shut down when this is called
    struct monad_trace_page *page;
    if (page_pool->active_page != nullptr) {
        TAILQ_INSERT_TAIL(&page_pool->free_pages, page_pool->active_page, page_link);
        page_pool->active_page = nullptr;
    }
    while (!TAILQ_EMPTY(&page_pool->free_pages)) {
        page = TAILQ_FIRST(&page_pool->free_pages);
        TAILQ_REMOVE(&page_pool->free_pages, page, page_link);
        munmap(page, (size_t)(page->heap_end - (uint8_t*)page));
    }
    page_pool->free_page_count = 0;
    pthread_cond_destroy(&page_pool->sync_cond);
    pthread_mutex_destroy(&page_pool->mtx);
}

static int init_page_pool(struct monad_trace_page_pool *page_pool)
{
    int rc;
    int saved_error;
    struct monad_trace_page *page;

    memset(page_pool, 0, sizeof *page_pool);
    if ((rc = pthread_mutex_init(&page_pool->mtx, nullptr)) != 0) {
        return FORMAT_ERRC(rc, "pthread_mutex_init(3) failed");
    }
    if ((rc = pthread_cond_init(&page_pool->sync_cond, nullptr)) != 0) {
        saved_error = FORMAT_ERRC(rc, "pthread_cond_init(3) failed");
        (void)pthread_mutex_destroy(&page_pool->mtx);
        return saved_error;
    }
    TAILQ_INIT(&page_pool->sync_pages);
    TAILQ_INIT(&page_pool->free_pages);
    for (size_t p = 0; p < TRACE_PAGE_POOL_SIZE; ++p) {
        page = mmap_trace_page();
        if (page == MAP_FAILED) {
            saved_error = errno;
            cleanup_page_pool(page_pool);
            return saved_error;
        }
        page->page_pool = page_pool;
        TAILQ_INSERT_TAIL(&page_pool->free_pages, page, page_link);
        ++page_pool->free_page_count;
    }
    page_pool->active_page = TAILQ_FIRST(&page_pool->free_pages);
    --page_pool->free_page_count;
    TAILQ_REMOVE(&page_pool->free_pages, page_pool->active_page, page_link);
    return 0;
}

static int write_recorder_page(struct monad_trace_file *mtf,
                               struct monad_trace_page *page)
{
    struct monad_trace_section_desc section_desc;
    ssize_t rc;
    int errc;
    size_t const heap_length = (size_t)(page->heap_next - page->heap_begin);

    memset(&section_desc, 0, sizeof section_desc);
    section_desc.type = MONAD_TRACE_SECTION_RECORDER_PAGE;
    section_desc.recorder_page.event_count = page->event_count;

    rc = monad_trace_file_write_section(mtf, &section_desc, page->heap_begin,
        heap_length);
    if (rc < 0) {
        errc = (int)-rc;
        monad_trace_shutdown_internal(&MONAD_SOURCE_LOCATION_CURRENT(),
            errc, "I/O error while writing trace file: %s",
            monad_trace_file_get_last_error());
        return errc;
    }
    return 0;
}

/*
 * Global trace state and the tracer threads
 */

struct monad_tracer
{
    alignas(64) pthread_mutex_t mtx;
    struct monad_trace_file *trace_file;
    struct monad_event_session *trace_session;
    char *trace_file_name;
    pthread_t recorder_thread;
    pthread_t sync_thread;
    bool initialized;
    struct monad_trace_page_pool page_pool;
    alignas(64) atomic_bool exit_threads;
};

static bool get_trace_event_alloc_size(
    struct monad_trace_page *page, size_t payload_length, size_t *required_size)
{
    *required_size = payload_length > 0
        ? monad_round_size_to_align(
            sizeof(struct monad_trace_event) + payload_length,
            alignof(struct monad_trace_event))
        : sizeof(struct monad_trace_event);
    if (MONAD_UNLIKELY(page == nullptr)) {
        return false;
    }
    return page->heap_next + *required_size <= page->heap_end;
}

static void record_injected_event(struct monad_trace_event const *trace_event,
    void *payload, size_t payload_size, struct monad_trace_page *trace_page)
{
    size_t required_size;
    if (MONAD_UNLIKELY(get_trace_event_alloc_size(trace_page, payload_size, &required_size) == false)) {
        trace_page = deactivate_trace_page(trace_page);
        if (MONAD_UNLIKELY(trace_page == nullptr)) {
            return; // Out of memory, we're halting
        }
    }
    memcpy(trace_page->heap_next, trace_event, sizeof *trace_event);
    memcpy(trace_page->heap_next + sizeof *trace_event, payload, payload_size);
    trace_page->heap_next += required_size;
    ++trace_page->event_count;
}

// Main function of the "recorder thread", which is consuming event descriptors
// and writing them to the active page
static void *recorder_thread_main(void *arg0)
{
#define TRACER_MAX_EVENTS (16)
    struct monad_tracer *const tracer = arg0;

    struct monad_event_descriptor event_desc[TRACER_MAX_EVENTS];
    struct monad_event_payload_page **payload_pages;
    struct monad_event_payload_page *payload_page;
    struct monad_event_session *session = tracer->trace_session;
    struct monad_trace_event trace_event;
    struct monad_trace_page *trace_page = tracer->page_pool.active_page;
    size_t available_events;
    size_t num_events;
    size_t copy_len;
    uint64_t last_seqno = 0;

    pthread_setname_np(pthread_self(), "trace_record");
    payload_pages = _monad_event_get_payload_page_pool_array(nullptr);
    while (!atomic_load_explicit(&tracer->exit_threads, memory_order_acquire)) {
        num_events = monad_event_ring_read_descriptors(
            &session->event_ring, event_desc, TRACER_MAX_EVENTS, &available_events);
        for (size_t e = 0; e < num_events; ++e) {
            if (MONAD_UNLIKELY(event_desc[e].seqno != last_seqno + 1)) {
                trace_event.type = MONAD_EVENT_TRACE_GAP;
                trace_event.pop_scope = false;
                trace_event.source_id = event_desc[e].source_id;
                trace_event.seqno = last_seqno + 1;
                trace_event.epoch_nanos = monad_event_get_epoch_nanos();
                record_injected_event(&trace_event, nullptr, 0, trace_page);
            }
            last_seqno = event_desc[e].seqno;

            // Special processing for certain events
            // TODO(ken): MONAD_EVENT_SYNC_EVENT_GAP is pretty catastrophic for
            //    tracing, but not clear exactly what to do here

            if (MONAD_UNLIKELY(get_trace_event_alloc_size(trace_page, event_desc[e].length, &copy_len) == false)) {
                trace_page = deactivate_trace_page(trace_page);
                if (MONAD_UNLIKELY(trace_page == nullptr)) {
                    return nullptr; // Out of trace page memory; can't continue
                }
            }

            trace_event.type = event_desc[e].type;
            trace_event.pop_scope = event_desc[e].pop_scope;
            trace_event.source_id = event_desc[e].source_id;
            trace_event.length = event_desc[e].length;
            trace_event.seqno = event_desc[e].seqno;
            trace_event.epoch_nanos = event_desc[e].epoch_nanos;

            payload_page = payload_pages[event_desc[e].payload_page];
            memcpy(trace_page->heap_next, &trace_event, sizeof trace_event);
            memcpy(trace_page->heap_next + sizeof trace_event,
                (uint8_t*)payload_page + event_desc[e].offset,
                trace_event.length);
            if (MONAD_UNLIKELY(atomic_load_explicit(
                &payload_page->page_header.page_generation,
                memory_order_acquire) != event_desc[e].page_generation)) {
                trace_event.type = MONAD_EVENT_TRACE_PAYLOAD_EXPIRED;
                trace_event.source_id = event_desc[e].source_id;
                trace_event.seqno = event_desc[e].seqno;
                trace_event.epoch_nanos = monad_event_get_epoch_nanos();
                record_injected_event(&trace_event, &event_desc[e],
                    sizeof &event_desc[e], trace_page);
            }
            else {
                trace_page->heap_next += copy_len;
                ++trace_page->event_count;
            }
        }
    }

    return nullptr;
}

// Main function of the "sync thread", which is woken up when it is time to
// write recorder pages to the file; once the write finishes, the recorder
// pages are put back on the free list
static void *sync_thread_main(void *arg0)
{
    struct monad_trace_page *sync_page;
    struct monad_tracer *const tracer = arg0;
    struct monad_trace_page_pool *const page_pool = &tracer->page_pool;

    pthread_setname_np(pthread_self(), "trace_sync");
    while (!atomic_load_explicit(&tracer->exit_threads, memory_order_acquire)) {
        pthread_mutex_lock(&page_pool->mtx);
        pthread_cond_wait(&page_pool->sync_cond, &page_pool->mtx);
        if (MONAD_UNLIKELY(page_pool->sync_page_count == 0)) {
            pthread_mutex_unlock(&page_pool->mtx);
            continue;
        }
        sync_page = TAILQ_FIRST(&page_pool->sync_pages);
        TAILQ_REMOVE(&page_pool->sync_pages, sync_page, page_link);
        --page_pool->sync_page_count;
        pthread_mutex_unlock(&page_pool->mtx);

        if (write_recorder_page(tracer->trace_file, sync_page) != 0) {
            // Write error, which triggers a shutdown; exit early because we're
            // racing against code that assumes single-threaded access to the
            // page pool
            return nullptr;
        }
        ++page_pool->trace_pages_written;

        pthread_mutex_lock(&page_pool->mtx);
        TAILQ_INSERT_HEAD(&page_pool->free_pages, sync_page, page_link);
        ++page_pool->free_page_count;
        pthread_mutex_unlock(&page_pool->mtx);
    }

    pthread_mutex_lock(&page_pool->mtx);
    // Finish draining the sync pages
    while ((sync_page = TAILQ_FIRST(&page_pool->sync_pages)) != nullptr) {
        TAILQ_REMOVE(&page_pool->sync_pages, sync_page, page_link);
        --page_pool->sync_page_count;
        (void)write_recorder_page(tracer->trace_file, sync_page);
        TAILQ_INSERT_TAIL(&page_pool->free_pages, sync_page, page_link);
        ++page_pool->free_page_count;
    }
    pthread_mutex_unlock(&page_pool->mtx);

    // Join with the exit of the recorder thread and sync its residual
    // active page
    pthread_join(tracer->recorder_thread, nullptr);
    pthread_mutex_lock(&page_pool->mtx);
    if (page_pool->active_page != nullptr) {
        (void)write_recorder_page(tracer->trace_file, page_pool->active_page);
        TAILQ_INSERT_TAIL(&page_pool->free_pages, page_pool->active_page, page_link);
        ++page_pool->free_page_count;
        page_pool->active_page = nullptr;
    }
    pthread_mutex_unlock(&page_pool->mtx);
    return nullptr;
}

static struct monad_tracer g_monad_tracer;
static bool g_at_exit_registered;

#if 0
static void trace_atexit()
{
    monad_trace_shutdown();
}

static void trace_at_quick_exit()
{
    monad_trace_shutdown();
}
#endif

static void __attribute__((constructor(MONAD_EVENT_SESSION_CTOR_PRIO + 1)))
monad_tracer_ctor()
{
    int const rc = pthread_mutex_init(&g_monad_tracer.mtx, nullptr);
    if (rc != 0) {
        FORMAT_ERRC(rc, "fatal: pthread_mutex_init failed for tracer");
        fprintf(stderr, "%s: %s", __progname, g_error_buf);
        abort();
    }
}

static void __attribute__((destructor(MONAD_EVENT_SESSION_CTOR_PRIO + 1)))
monad_tracer_dtor()
{
    monad_event_recorder_halt();
    monad_trace_shutdown();
    pthread_mutex_destroy(&g_monad_tracer.mtx);
}

static void write_shutdown_section(struct monad_trace_file *mtf, int error_code,
    char const *msg)
{
    struct monad_trace_section_desc section_desc;
    memset(&section_desc, 0, sizeof section_desc);
    section_desc.type = MONAD_TRACE_SECTION_SHUTDOWN_INFO;
    section_desc.shutdown_info.error_code = error_code;
    (void)monad_trace_file_write_section(mtf, &section_desc, msg, strlen(msg));
}

static void monad_trace_shutdown_internal(monad_source_location_t const *srcloc,
    int err, char const *format, ...)
{
    // Called internally by the tracer, when the recorder must be shut down
    // because of an error on one of the worker threads.
    va_list ap;
    va_start(ap, format);
    _monad_event_vformat_err(
        g_error_buf, sizeof g_error_buf, srcloc, err, format, ap);
    va_end(ap);
    write_shutdown_section(g_monad_tracer.trace_file, err, g_error_buf);
    fprintf(stderr, "%s: tracer is shutdown: %s\n", __progname, g_error_buf);
    monad_trace_shutdown();
}

int monad_trace_init(char const *file_name, int fd, uint8_t ring_shift,
    monad_allocator_t *alloc, pthread_t *recorder_thread,
    pthread_t *sync_thread)
{
    int rc;
    int saved_error;
    ssize_t src;
    struct monad_tracer *const tracer = &g_monad_tracer;

    pthread_mutex_lock(&tracer->mtx);
    if (tracer->initialized) {
        saved_error = FORMAT_ERRC(EBUSY, "tracer already initialized");
        pthread_mutex_unlock(&tracer->mtx);
        return saved_error;
    }
    if ((rc = init_page_pool(&tracer->page_pool)) != 0) {
        pthread_mutex_unlock(&tracer->mtx);
        return rc;
    }
    if ((rc = monad_trace_file_create(&tracer->trace_file, alloc)) != 0) {
        saved_error = FORMAT_ERRC(rc, "monad_trace_file_create failed: %s",
            monad_trace_file_get_last_error());
        goto CleanupPagePool;
    }
    if ((rc = monad_trace_file_set_output(tracer->trace_file, fd)) != 0) {
        saved_error = FORMAT_ERRC(rc, "monad_trace_file_set_output failed: %s",
            monad_trace_file_get_last_error());
        goto CleanupTraceFile;
    }
    if ((rc = monad_event_session_open(ring_shift, &tracer->trace_session)) != 0) {
        saved_error = FORMAT_ERRC(rc, "monad_event_open_session failed: %s",
            monad_event_session_get_last_error());
        goto CleanupTraceFile;
    }
    tracer->trace_file_name = strdup(file_name);
    for (size_t d = 0; d < g_monad_event_domain_meta_size; ++d) {
        if (g_monad_event_domain_meta[d].domain == MONAD_EVENT_DOMAIN_NONE) {
            continue;
        }
        if ((src = monad_trace_file_write_domain_metadata(tracer->trace_file,
            &g_monad_event_domain_meta[d])) < 0) {
            saved_error = FORMAT_ERRC((int)-src,
                "monad_trace_file_write_domain_metadata "
                "failed for domain %zu: %s", d,
                monad_trace_file_get_last_error());
            goto CleanupSession;
        }
    }

    if ((rc = pthread_create(&tracer->recorder_thread, nullptr, recorder_thread_main, tracer)) != 0) {
        saved_error = FORMAT_ERRC(rc, "pthread_create could not start "
            "recorder thread");
        goto CleanupSession;
    }
    if ((rc = pthread_create(&tracer->sync_thread, nullptr, sync_thread_main, tracer)) != 0) {
        saved_error = FORMAT_ERRC(rc, "pthread_create could not start "
            "sync thread");
        atomic_store_explicit(&tracer->exit_threads, true, memory_order_release);
        pthread_join(tracer->recorder_thread, nullptr);
        atomic_store_explicit(&tracer->exit_threads, false, memory_order_release);
        goto CleanupSession;
    }
    if (recorder_thread) {
        *recorder_thread = tracer->recorder_thread;
    }
    if (sync_thread) {
        *sync_thread = tracer->sync_thread;
    }
    if (g_at_exit_registered == false) {
#if 0
        atexit(trace_atexit);
        at_quick_exit(trace_at_quick_exit);
        g_at_exit_registered = true;
#endif
    }
    tracer->initialized = true;
    pthread_mutex_unlock(&tracer->mtx);
    return 0;

CleanupSession:
    monad_event_session_close(tracer->trace_session);
    tracer->trace_session = nullptr;
CleanupTraceFile:
    monad_trace_file_destroy(tracer->trace_file);
    tracer->trace_file = nullptr;
CleanupPagePool:
    cleanup_page_pool(&tracer->page_pool);
    pthread_mutex_unlock(&tracer->mtx);
    return saved_error;
}

void monad_trace_shutdown()
{
    uint64_t prod_next;
    uint64_t consume_next;
    struct monad_tracer *const tracer = &g_monad_tracer;
    struct monad_event_session *const session = tracer->trace_session;

    pthread_mutex_lock(&tracer->mtx);
    if (!tracer->initialized) {
        pthread_mutex_unlock(&tracer->mtx);
        return;
    }

    // Stop accepting new events on the session side
    monad_event_session_set_domain_mask(session, 0);

    // Drain the queue
    do {
        prod_next = atomic_load_explicit(
            &session->event_ring.control->prod_next, memory_order_relaxed);
        consume_next = atomic_load_explicit(
            &session->event_ring.control->consume_next, memory_order_relaxed);
    } while (consume_next != prod_next);

    // Stop the worker threads
    atomic_store_explicit(&tracer->exit_threads, true, memory_order_release);
    pthread_cond_signal(&tracer->page_pool.sync_cond);
    pthread_join(tracer->sync_thread, nullptr);
    atomic_store_explicit(&tracer->exit_threads, false, memory_order_release);

    // Cleanup the trace file, session, and trace page pool
    free(tracer->trace_file_name);
    monad_event_session_close(tracer->trace_session);
    tracer->trace_session = nullptr;
    monad_trace_file_destroy(tracer->trace_file);
    tracer->trace_file = nullptr;
    cleanup_page_pool(&tracer->page_pool);

    tracer->initialized = false;
    pthread_mutex_unlock(&tracer->mtx);
}

void monad_trace_set_domain_mask(uint64_t domain_mask)
{
    // Adjust the domain mask to include the internal and perf domains; this
    // ensures we always see THREAD_CREATE and FIBER_SWITCH events, otherwise
    // we can't maintain the thread information tables or the flow ids.
    uint64_t const adjusted_domain_mask = domain_mask
        | MONAD_EVENT_DOMAIN_MASK(MONAD_EVENT_DOMAIN_INTERNAL)
        | MONAD_EVENT_DOMAIN_MASK(MONAD_EVENT_DOMAIN_PERF);
    struct monad_tracer *const tracer = &g_monad_tracer;
    pthread_mutex_lock(&tracer->mtx);
    if (MONAD_LIKELY(tracer->initialized)) {
        monad_event_session_set_domain_mask(tracer->trace_session, adjusted_domain_mask);
    }
    pthread_mutex_unlock(&tracer->mtx);
}

char const *monad_trace_get_last_error()
{
    return g_error_buf;
}
