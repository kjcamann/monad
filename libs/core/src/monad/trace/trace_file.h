#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <monad/mem/cma/cma_alloc.h>

enum monad_event_type : uint16_t;

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Constants and on-disk / mmap'ed structures
 */

static uint16_t const MONAD_TRACE_FILE_VERSION = 1;
static char const MONAD_TRACE_FILE_MAGIC[] = {
    'M', 'O', 'N', 'A', 'D', '_', 'T', 'F'};

struct monad_trace_file_header
{
    char magic[8];
    uint32_t version;
    uint32_t unused;
    uint64_t sectab_offset;
};

enum monad_trace_section_type
{
    MONAD_TRACE_SECTION_NONE,
    MONAD_TRACE_SECTION_LINK,
    MONAD_TRACE_SECTION_DOMAIN_INFO,
    MONAD_TRACE_SECTION_SHUTDOWN_INFO,
    MONAD_TRACE_SECTION_THREAD_INFO,
    MONAD_TRACE_SECTION_RECORDER_PAGE,
    MONAD_TRACE_SECTION_MERGE_PAGE,
    MONAD_TRACE_SECTION_BLOCK_PAGE
};

struct monad_trace_domain_info_desc
{
    uint64_t code;
    uint64_t num_events;
    uint8_t keccak_24[24];
};

struct monad_trace_shutdown_info_desc
{
    int error_code;
};

struct monad_trace_thread_info_desc
{
    size_t thread_count;
};

struct monad_trace_recorder_page_desc
{
    uint64_t event_count;
};

struct monad_trace_merge_page_desc
{
    uint64_t event_count;
    uint64_t block_count;
    uint64_t elapsed_nanos;
    uint64_t txn_count;
    uint64_t total_gas;
};

struct monad_trace_section_desc
{
    uint64_t type;
    uint64_t offset;
    uint64_t length;

    union
    {
        struct monad_trace_domain_info_desc domain_info;
        struct monad_trace_merge_page_desc merge_page;
        struct monad_trace_recorder_page_desc recorder_page;
        struct monad_trace_shutdown_info_desc shutdown_info;
        struct monad_trace_thread_info_desc thread_info;
        uint64_t padding[5];
    };
};

static_assert(sizeof(struct monad_trace_section_desc) == 64);

enum monad_trace_flow_type : uint8_t
{
    MONAD_TRACE_FLOW_NONE,
    MONAD_TRACE_FLOW_BLOCK,
    MONAD_TRACE_FLOW_TXN
};

enum monad_trace_scope_action : uint8_t
{
    MONAD_TRACE_SCOPE_NONE,
    MONAD_TRACE_SCOPE_PUSH,
    MONAD_TRACE_SCOPE_POP,
    MONAD_TRACE_SCOPE_UNKNOWN
};

struct monad_trace_event
{
    enum monad_event_type type;
    bool pop_scope;
    uint8_t source_id;
    uint32_t length;
    uint64_t seqno;
    uint64_t epoch_nanos;
};

/// Event object annotated with originating thread, fiber, and flow id; these
/// only appear in merged trace files
struct monad_trace_merged_event
{
    uint64_t thread_id;
    uint64_t flow_id;
    uint32_t fiber_id;
    enum monad_trace_flow_type flow_type;
    enum monad_trace_scope_action scope_action;
    uint16_t : 16; // unused
    struct monad_trace_event trace_evt;
};

/*
 * Trace file writer API, used by trace.c and the monad_edit_trace utility
 */

struct monad_event_domain_metadata;
struct monad_trace_file;
struct monad_trace_dynamic_section;

int monad_trace_file_create(struct monad_trace_file **, monad_allocator_t *);

void monad_trace_file_destroy(struct monad_trace_file *);

char const *monad_trace_file_get_last_error();

int monad_trace_file_set_output(struct monad_trace_file *, int fd);

ssize_t monad_trace_file_write_domain_metadata(
    struct monad_trace_file *, struct monad_event_domain_metadata const *);

ssize_t monad_trace_file_write_section(
    struct monad_trace_file *, struct monad_trace_section_desc const *,
    void const *buf, size_t nbyte);

int monad_trace_file_open_dynamic_section(
    struct monad_trace_file *, struct monad_trace_dynamic_section **,
    struct monad_trace_section_desc **);

int monad_trace_file_sync_dynamic_section(
    struct monad_trace_file *, struct monad_trace_dynamic_section *,
    void const *buf, size_t size);

int monad_trace_file_close_dynamic_section(struct monad_trace_file *,
    struct monad_trace_dynamic_section *);

#ifdef __cplusplus
} // extern "C"
#endif
