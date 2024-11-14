#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <monad/core/keccak.h>
#include <monad/core/likely.h>
#include <monad/core/srcloc.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_shared.h>
#include <monad/mem/align.h>
#include <monad/mem/cma/cma_alloc.h>
#include <monad/trace/trace_file.h>

struct monad_trace_dynamic_section
{
    struct monad_trace_section_desc *section_desc;
};

struct monad_trace_file
{
    alignas(64) pthread_mutex_t mtx;
    int fd;
    size_t mmap_page_size;
    struct monad_trace_section_desc *sectab_start;
    struct monad_trace_section_desc *sectab_next;
    struct monad_trace_section_desc *sectab_end;
    struct monad_trace_dynamic_section dynamic_section;
    monad_memblk_t self_memblk;
    monad_allocator_t *alloc;
};

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

#define MTF_ERRC(ERRC, FORMAT, ...)                                            \
    format_errc(                                                               \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        ERRC,                                                                  \
        FORMAT __VA_OPT__(, ) __VA_ARGS__)

static int write_trace_file_header(struct monad_trace_file *mtf)
{
    struct monad_trace_file_header header = {
        .version = MONAD_TRACE_FILE_VERSION,
        .unused = 0,
        .sectab_offset = mtf->mmap_page_size};
    memcpy(
        &header.magic, MONAD_TRACE_FILE_MAGIC, sizeof MONAD_TRACE_FILE_MAGIC);
    if (write(mtf->fd, &header, sizeof header) == -1) {
        return MTF_ERRC(errno, "write of trace header failed");
    }
    return 0;
}

// The main index structure within a trace file is called a section table:
// it contains metadata about where the trace data is located within the file.
// Trace data is organized into separate sections, and each is described by
// a "section descriptor", represented by `struct monad_trace_section_desc`.
// The section table is a fixed size array of `monad_trace_section_desc`
// entries which is allocated in the file and then mmap'd into our process.
// When the array fills up, another section table is allocated and linked to
// the previous one.
struct monad_trace_section_desc *map_new_section_table(
    struct monad_trace_file *mtf, uint64_t *new_sectab_file_offset)
{
    void *map_base;
    off_t const cur_offset = lseek(mtf->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        MTF_ERRC(errno, "lseek failed while mapping new section table");
        return nullptr;
    }
    *new_sectab_file_offset =
        monad_round_size_to_align((size_t)cur_offset, mtf->mmap_page_size);
    // Grow the file to include space for the new section table, then update
    // the file descriptor's position to point beyond the end of the table
    if (ftruncate(
            mtf->fd, (off_t)(*new_sectab_file_offset + mtf->mmap_page_size)) ==
            -1 ||
        lseek(mtf->fd, 0, SEEK_END) == -1) {
        MTF_ERRC(
            errno, "growing trace file failed while mapping new section table");
        return nullptr;
    }
    map_base = mmap(
        nullptr,
        mtf->mmap_page_size,
        PROT_WRITE,
        MAP_SHARED,
        mtf->fd,
        (off_t)*new_sectab_file_offset);
    if (map_base == MAP_FAILED) {
        MTF_ERRC(errno, "mmap of new section table failed");
    }
    return map_base;
}

// Allocate a descriptor from the section table to write into; this may also
// allocate a entirely new section table if the current one is out of space
static struct monad_trace_section_desc *
alloc_section_table_descriptor(struct monad_trace_file *mtf)
{
    struct monad_trace_section_desc *new_sectab;
    uint64_t new_sectab_file_offset;

    if (MONAD_UNLIKELY(mtf->sectab_next + 1 == mtf->sectab_end)) {
        // There is only one section table entry remaining. Append a new
        // section table to the end of the file and use the last entry to link
        // to the new one
        new_sectab = map_new_section_table(mtf, &new_sectab_file_offset);
        if (new_sectab == MAP_FAILED) {
            return nullptr;
        }

        // Link the old section table to the new section table, then unmap it
        mtf->sectab_next->type = MONAD_TRACE_SECTION_LINK;
        mtf->sectab_next->offset = new_sectab_file_offset;
        mtf->sectab_next->length = mtf->mmap_page_size;
        (void)munmap(mtf->sectab_start, mtf->mmap_page_size);

        // Reseat the section table pointers
        mtf->sectab_next = mtf->sectab_start = new_sectab;
        mtf->sectab_end =
            mtf->sectab_start +
            mtf->mmap_page_size / sizeof(struct monad_trace_section_desc);
    }

    return mtf->sectab_next++;
}

// Write a section descriptor into the active section table of the file
static int write_section_descriptor(
    struct monad_trace_file *mtf, struct monad_trace_section_desc *desc,
    uint64_t offset, int whence)
{
    off_t cur_offset;
    struct stat stat;
    struct monad_trace_section_desc *slot;

    // Allocate a slot in the table to copy `desc` into; we have to do this
    // first, because it can allocate an entirely new section table and thus
    // change the size of the file
    slot = alloc_section_table_descriptor(mtf);

    // Populate the section table entry
    switch (whence) {
    case SEEK_SET:
        desc->offset = offset;
        break;

    case SEEK_CUR:
        cur_offset = lseek(mtf->fd, 0, SEEK_CUR);
        if (cur_offset == -1) {
            return MTF_ERRC(errno, "lseek failed in write_section_descriptor");
        }
        desc->offset = (uint64_t)cur_offset + offset;
        break;

    case SEEK_END:
        if (fstat(mtf->fd, &stat) == -1) {
            return MTF_ERRC(errno, "could not stat trace file");
        }
        desc->offset = (size_t)stat.st_size + offset;
        break;

    default:
        // XXX: MONAD_ABORT
        fprintf(stderr, "unrecognized whence argument: %d\n", whence);
        abort();
    }
    // For "information only" descriptors which have no payload in the file,
    // e.g., THR_INFO, set the file offset to zero
    if (desc->length == 0) {
        desc->offset = 0;
    }
    memcpy(slot, desc, sizeof *desc);
    return 0;
}

static int check_ready(struct monad_trace_file *mtf)
{
    if (mtf->fd == -1) {
        return MTF_ERRC(ENODEV, "file descriptor is closed");
    }
    if (mtf->dynamic_section.section_desc != nullptr) {
        return MTF_ERRC(EBUSY, "dynamic page is open");
    }
    return 0;
}

static ssize_t
write_aligned(struct monad_trace_file *mtf, void const *buf, size_t size)
{
    off_t cur_file_length;
    off_t aligned_file_length;
    ssize_t wr_bytes;

    wr_bytes = write(mtf->fd, buf, size);
    if (wr_bytes == -1) {
        return -MTF_ERRC(errno, "write of %lu bytes failed", size);
    }
    cur_file_length = lseek(mtf->fd, 0, SEEK_END);
    if (cur_file_length == -1) {
        return -MTF_ERRC(errno, "lseek to end failed");
    }
    aligned_file_length = (off_t)monad_round_size_to_align(
        (size_t)cur_file_length, mtf->mmap_page_size);
    if (aligned_file_length != cur_file_length) {
        if (ftruncate(mtf->fd, aligned_file_length) == -1) {
            return -MTF_ERRC(errno, "ftruncate to grow to alignment failed");
        }
        if (lseek(mtf->fd, 0, SEEK_END) == -1) {
            return -MTF_ERRC(errno, "lseek to end after growing file failed");
        }
        wr_bytes += aligned_file_length - cur_file_length;
    }
    return wr_bytes;
}

int monad_trace_file_create(
    struct monad_trace_file **mtf_p, monad_allocator_t *alloc)
{
    int rc;
    monad_memblk_t mem;
    struct monad_trace_file *mtf;

    *mtf_p = nullptr;
    rc = monad_cma_alloc(alloc, sizeof *mtf, alignof(struct monad_trace_file), &mem);
    if (rc != 0) {
        return MTF_ERRC(errno, "monad_cma_alloc failed");
    }
    mtf = *mtf_p = mem.ptr;
    memset(mtf, 0, sizeof *mtf);
    rc = pthread_mutex_init(&mtf->mtx, nullptr);
    if (rc != 0) {
        return MTF_ERRC(errno, "pthread_mutex_init failed");
    }
    mtf->fd = -1;
    mtf->mmap_page_size = (size_t)getpagesize();
    mtf->self_memblk = mem;
    mtf->alloc = alloc;
    return 0;
}

void monad_trace_file_destroy(struct monad_trace_file *mtf)
{
    if (mtf->sectab_start != nullptr) {
        (void)munmap(mtf->sectab_start, mtf->mmap_page_size);
    }
    (void)close(mtf->fd);
    (void)pthread_mutex_destroy(&mtf->mtx);
    monad_cma_dealloc(mtf->alloc, mtf->self_memblk);
}

char const *monad_trace_file_get_last_error()
{
    return g_error_buf;
}

// Write the header file and the first section table
int monad_trace_file_set_output(struct monad_trace_file *mtf, int fd)
{
    uint64_t new_sectab_file_offset;
    int saved_error;

    pthread_mutex_lock(&mtf->mtx);
    if (mtf->fd != -1) {
        // Close the currently open file
        munmap(mtf->sectab_start, mtf->mmap_page_size);
        mtf->dynamic_section.section_desc = nullptr;
        close(mtf->fd);
    }
    mtf->fd = dup(fd);
    if (mtf->fd == -1) {
        saved_error = MTF_ERRC(errno, "could not dup(2) input file descriptor");
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    if ((saved_error = write_trace_file_header(mtf)) != 0) {
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    mtf->sectab_next = mtf->sectab_start =
        map_new_section_table(mtf, &new_sectab_file_offset);
    if (mtf->sectab_start == MAP_FAILED) {
        saved_error = errno;
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    mtf->sectab_end =
        mtf->sectab_start +
        mtf->mmap_page_size / sizeof(struct monad_trace_section_desc);
    pthread_mutex_unlock(&mtf->mtx);
    return 0;
}

ssize_t monad_trace_file_write_domain_metadata(
    struct monad_trace_file *mtf, struct monad_event_domain_metadata const *edm)
{
    struct monad_trace_section_desc section_desc;
    char *meta_buf;
    size_t meta_buf_sz;
    uint8_t meta_hash[KECCAK256_SIZE];
    ssize_t rc;

    memset(&section_desc, 0, sizeof section_desc);
    section_desc.type = MONAD_TRACE_SECTION_DOMAIN_INFO;
    section_desc.domain_info.code = edm->domain;
    section_desc.domain_info.num_events = edm->num_events;
    if ((rc = monad_event_metadata_serialize(edm, &meta_buf, &meta_buf_sz)) != 0) {
        return -MTF_ERRC((int)rc, "metadata serialization of domain %hhu failed",
            edm->domain);
    }
    keccak256((uint8_t const *)meta_buf, meta_buf_sz, meta_hash);
    memcpy(&section_desc.domain_info.keccak_24, meta_hash,
        sizeof section_desc.domain_info.keccak_24);
    rc = monad_trace_file_write_section(mtf, &section_desc, meta_buf, meta_buf_sz);
    free(meta_buf);
    return rc;
}

ssize_t monad_trace_file_write_section(
    struct monad_trace_file *mtf,
    struct monad_trace_section_desc const *input_section_desc,
    void const *buf,
    size_t nbytes)
{
    struct monad_trace_section_desc section_desc;
    ssize_t rc;

    memcpy(&section_desc, input_section_desc, sizeof section_desc);
    section_desc.length = nbytes;
    pthread_mutex_lock(&mtf->mtx);
    if ((rc = check_ready(mtf)) != 0) {
        pthread_mutex_unlock(&mtf->mtx);
        return -rc;
    }
    if ((rc = write_section_descriptor(mtf, &section_desc, 0, SEEK_CUR)) != 0) {
        pthread_mutex_unlock(&mtf->mtx);
        return -rc;
    }
    rc = write_aligned(mtf, buf, nbytes);
    pthread_mutex_unlock(&mtf->mtx);
    return rc;
}

int monad_trace_file_open_dynamic_section(
    struct monad_trace_file *mtf,
    struct monad_trace_dynamic_section **dynamic_section,
    struct monad_trace_section_desc **sd)
{
    off_t cur_offset;
    int saved_error;

    *dynamic_section = nullptr;
    *sd = nullptr;
    pthread_mutex_lock(&mtf->mtx);
    if ((saved_error = check_ready(mtf)) != 0) {
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    mtf->dynamic_section.section_desc = alloc_section_table_descriptor(mtf);
    if (mtf->dynamic_section.section_desc == nullptr) {
        saved_error = errno;
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    // Get the current position in the file where the dynamic section will
    // start writing; note that this cannot be moved before the call to
    // alloc_section_table_descriptor, which may change the file, e.g., if
    // it needs to add a linked section table
    cur_offset = lseek(mtf->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        saved_error = MTF_ERRC(errno, "could not seek to end for dynamic page");
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    *dynamic_section = &mtf->dynamic_section;
    *sd = mtf->dynamic_section.section_desc;
    memset(*sd, 0, sizeof **sd);
    // Caller can set any fields except for `offset` (only set here), and
    // `length` (only set in monad_trace_file_sync_dynamic_section)
    (*sd)->offset = (uint64_t)cur_offset;
    pthread_mutex_unlock(&mtf->mtx);
    return 0;
}

int monad_trace_file_sync_dynamic_section(
    struct monad_trace_file *mtf,
    struct monad_trace_dynamic_section *dynamic_section,
    void const *buf, size_t size)
{
    int saved_error;

    pthread_mutex_lock(&mtf->mtx);
    if (mtf->fd == -1 || mtf->dynamic_section.section_desc == nullptr) {
        saved_error = MTF_ERRC(ENODEV, "no dynamic page is currently open");
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    if (write(mtf->fd, buf, size) == -1) {
        saved_error = MTF_ERRC(errno, "write of dynamic page contents to disk failed");
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    dynamic_section->section_desc->length += size;
    pthread_mutex_unlock(&mtf->mtx);
    return 0;
}

int monad_trace_file_close_dynamic_section(struct monad_trace_file *mtf,
    struct monad_trace_dynamic_section *dynamic_section)
{
    ssize_t bytes_written;
    int saved_error;

    pthread_mutex_lock(&mtf->mtx);
    if (mtf->fd == -1 || mtf->dynamic_section.section_desc == nullptr) {
        saved_error = MTF_ERRC(ENODEV, "no dynamic page is currently open");
        pthread_mutex_unlock(&mtf->mtx);
        return saved_error;
    }
    // Ensure the file size is rounded off to a mmap page boundary
    if ((bytes_written = write_aligned(mtf, nullptr, 0)) < 0) {
        pthread_mutex_unlock(&mtf->mtx);
        return (int)-bytes_written;
    }
    dynamic_section->section_desc = nullptr;
    pthread_mutex_unlock(&mtf->mtx);
    return 0;
}
