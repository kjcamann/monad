// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <errno.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/format_err.h>
#include <category/core/likely.h>
#include <category/core/srcloc.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>

#include <zstd.h>

/*
 * Operation of the vbuf
 *
 * Each vbuf segment owns an anonymous piece of virtual memory associated with
 * a `memfd_create(2)` file descriptor. At any given time, the vbuf writer has
 * a single segment mapped into the process' virtual memory map, called the
 * active segment.
 *
 * When a write fills up one or more segments, all full segments are returned
 * to the caller. The caller can either sync them to a file, or can buffer
 * them up into a conditional write. The caller is responsible for freeing
 * segments by calling monad_vbuf_segment_free or freeing an entire chain of
 * segments with monad_vbuf_chain_free.
 *
 * A diagram illustrates a basic memcpy operation
 *
 *  ┌─Legend─────────────────────────────────┐
 *  │                                        │
 *  │ ░ Inactive segment (returned to caller)│
 *  │ ▒ Active segment (free space)          │
 *  │ ▓ Active segment (used space)          │
 *  └────────────────────────────────────────┘
 *
 *                                ▣ active segment
 *                                ║
 *  ╔═════════════════════════════╬═════════════════════════════════════════╗
 *  ║ ┌─segment 1─┐ ┌─segment 2─┐ ▼─segment 3─┐┌──────────────────────────┐ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓│▒▒▒▒││                          │ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓│▒▒▒▒││     Future segments      │ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓│▒▒▒▒││                          │ ║
 *  ║ └───────────┘ └───────────┘ └▲─────▲────▲└──────────────────────────┘ ║
 *  ║                              │     │    │                             ║
 *  ╚═Virtual buffer═══════════════╬═════╬════╬═════════════════════════════╝
 *                                 │     │    │
 *                                 ■     ■    ■
 *                               start next  end
 *
 *                                       ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
 *         Suppose the user              ┃▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥┃
 *         provides this buffer to ───▶  ┃▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥┃
 *         memcpy into the vbuf          ┃▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥▥┃
 *                                       ┗━Buffer to memcpy━━━━━━━━━━━━┛
 *
 *  After the memcpy completes the vbuf looks like this:      ▣ active segment
 *                                                            ║
 *  ╔═════════════════════════════════════════════════════════╬═════════════╗
 *  ║ ┌─segment 1─┐ ┌─segment 2─┐ ┌─segment 3─┐ ┌─segment 4─┐ ▼─segment 5─┐ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓▓▓│▒▒│ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓▓▓│▒▒│ ║
 *  ║ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │░░░░░░░░░░░│ │▓▓▓▓▓▓▓▓│▒▒│ ║
 *  ║ └───────────┘ └───────────┘ └───────────┘ └───────────┘ └▲───────▲──▲ ║
 *  ║                                                          │       │  │ ║
 *  ╚═Virtual buffer═══════════════════════════════════════════╬═══════╬══╬═╝
 *                                                             │       │  │
 *                                                             ■       ■  ■
 *                                                           start  next end
 *  The output of the memcpy is that segments 3 and 4, which
 *  were filled, are linked onto an output vbuf chain and their
 *  ownership is transferred to the caller. The residual part
 *  of the memcpy in segment 5 can be returned early with
 *  `monad_vbuf_writer_flush`, if the user is finished writing
 *
 *  ┌─vbuf chain───────────┐ ┌──▶──segment 3───┐ ┌──▶──segment 4───┐
 *  │ size_t length; // = 2│ │  │ ■ int fd;    │ │  │ ■ int fd;    │
 *  │ TAILQ_ENTRY next; ■──┼─┘  │ │ TAILQ_ENTRY│ │  │ │ TAILQ_ENTRY│
 *  └──────────────────────┘    │ │    next; ■─┼─┘  │ │    next; ■─┼─▶nullptr
 *                              └─┼────────────┘    └─┼────────────┘
 *                                │                   │
 *          ┌─────────────────────▼───────┐    ┌──────▼──────────────────────┐
 *          │                             │    │                             │
 *          │ memfd_create(2) memory slab │    │ memfd_create(2) memory slab │
 *          │                             │    │                             │
 *          └─────────────────────────────┘    └─────────────────────────────┘
 */

static thread_local char g_error_buf[1024];

static uint8_t const ZERO_ARRAY[1 << 21] = {};

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        g_error_buf,                                                           \
        sizeof(g_error_buf),                                                   \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

// Memory addresses of a vbuf segment when it is mapped into our address space
struct segment_mapping
{
    uint8_t *base;
    uint8_t *next;
    uint8_t *end;
};

// Captures the state of the active vbuf segment so we can rollback upon failure
struct rollback_state
{
    struct monad_vbuf_segment *segment;
    struct segment_mapping mapping;
};

// All state variables of the writer
struct monad_vbuf_writer
{
    struct monad_vbuf_segment *active_segment;
    struct segment_mapping active_map;
    size_t virtual_offset;
    struct monad_vbuf_writer_options options;
    size_t segment_size;
    size_t segment_count;
};

// When using zstd streaming compression, the vbuf writer is writing the
// stream output (the segments describe a single zstd frame, until it is
// flushed)
struct monad_vbuf_writer_zstd
{
    struct monad_vbuf_writer compressed_vbuf_writer;
    size_t compressed_size;
};

static inline size_t bytes_used(struct segment_mapping const *sm)
{
    return (size_t)(sm->next - sm->base);
}

static inline size_t bytes_free(struct segment_mapping const *sm)
{
    return (size_t)(sm->end - sm->next);
}

static int alloc_vbuf_segment(
    struct monad_vbuf_writer const *vbw, struct monad_vbuf_segment **vs_p)
{
    int rc;
    char name_buf[32];
    struct monad_vbuf_segment *vs;

    // Allocate a new active segment object and its memfd
    (void)snprintf(
        name_buf, sizeof name_buf, "buf_%lu", vbw->segment_count + 1);
    *vs_p = vs = malloc(sizeof *vs);
    if (vs == nullptr) {
        return FORMAT_ERRC(
            errno, "unable to alloc segment descriptor for %s", name_buf);
    }

    vs->base_virtual_offset = vbw->virtual_offset;
    vs->size = 0;
    vs->capacity = vbw->segment_size;
    vs->fd = memfd_create(name_buf, vbw->options.memfd_flags);
    if (vs->fd == -1) {
        rc = FORMAT_ERRC(
            errno, "memfd_create failed for vbuf segment %s", name_buf);
        goto Error;
    }
    if (ftruncate(vs->fd, (off_t)vs->capacity) == -1) {
        rc = FORMAT_ERRC(
            errno, "ftruncate failed for vbuf segment %s", name_buf);
        goto Error;
    }
    return 0;

Error:
    monad_vbuf_segment_free(vs);
    *vs_p = nullptr;
    return rc;
}

static int map_vbuf_segment(
    struct monad_vbuf_segment const *segment, struct segment_mapping *mapping)
{
    mapping->next = mapping->base = mmap(
        nullptr, segment->capacity, PROT_WRITE, MAP_SHARED, segment->fd, 0);
    if (mapping->base == MAP_FAILED) {
        return FORMAT_ERRC(errno, "mmap failed for vbuf segment %p", segment);
    }
    mapping->end = mapping->base + segment->capacity;
    return 0;
}

static void unmap_vbuf_segment(struct segment_mapping const *mapping)
{
    if (mapping->base != nullptr) {
        (void)munmap(mapping->base, (size_t)(mapping->end - mapping->base));
    }
}

static int activate_new_segment(struct monad_vbuf_writer *vbw)
{
    int rc;
    struct monad_vbuf_segment *vs;
    struct segment_mapping new_mapping;

    if ((rc = alloc_vbuf_segment(vbw, &vs)) != 0) {
        return rc;
    }
    if ((rc = map_vbuf_segment(vs, &new_mapping)) != 0) {
        monad_vbuf_segment_free(vs);
        return rc;
    }
    vbw->active_map = new_mapping;
    vbw->active_segment = vs;
    ++vbw->segment_count;
    return 0;
}

// This is called when activate_new_segment failed to create a new segment,
// e.g., it returned ENOMEM. This is not uncommon and does not necessarily
// indicate a catastrophic error in the process, e.g. in the case where the
// user specified MFD_HUGETLB and exhausted the large page pool. In this case,
// we discard all writes that occurred (destroy all new segments that were
// created) and put the old active segment back, resetting our state to what
// it was when monad_vbuf_writer_write_internal was called.
static void rollback_failed_write(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *full_segments,
    struct rollback_state const *rollback)
{
    struct monad_vbuf_segment *scan =
        TAILQ_LAST(&full_segments->segments, monad_vbuf_segment_list);
    while (scan != nullptr) {
        if (scan->base_virtual_offset >
            rollback->segment->base_virtual_offset) {
            // Segment created after the rollback segment; destroy it
            struct monad_vbuf_segment *const remove = scan;
            scan = TAILQ_PREV(scan, monad_vbuf_segment_list, entry);
            monad_vbuf_chain_remove(full_segments, remove);
            monad_vbuf_segment_free(remove);
        }
        else if (scan == rollback->segment) {
            // The rollback segment; remove it from the copy out and stop
            // looking
            monad_vbuf_chain_remove(full_segments, scan);
            break;
        }
        else {
            MONAD_ABORT("scan backwards did not find rollback->segment?");
        }
    }
    vbw->active_segment = rollback->segment;
    if (rollback->mapping.base != vbw->active_map.base) {
        unmap_vbuf_segment(&vbw->active_map);
    }
    vbw->active_map = rollback->mapping;
    vbw->virtual_offset =
        vbw->active_segment->base_virtual_offset + bytes_used(&vbw->active_map);
}

[[nodiscard]] static struct monad_vbuf_segment *
flush_active_segment(struct monad_vbuf_writer *vbw)
{
    struct monad_vbuf_segment *flushed = vbw->active_segment;
    if (flushed != nullptr) {
        flushed->size = bytes_used(&vbw->active_map);
        if (flushed->size == 0) {
            monad_vbuf_segment_free(flushed);
            flushed = nullptr;
        }
        vbw->active_segment = nullptr;
        unmap_vbuf_segment(&vbw->active_map);
        memset(&vbw->active_map, 0, sizeof vbw->active_map);
    }
    return flushed;
}

enum vbuf_write_op_type
{
    WRITE_OP_SKIP,
    WRITE_OP_MEMCPY
};

struct vbuf_write_op
{
    enum vbuf_write_op_type type;
    void const *src;
    size_t residual;
    ZSTD_CCtx *zstd_cctx;
    ZSTD_EndDirective zstd_end_op;
    size_t zbuf_remaining;
};

static bool write_op_is_complete(struct vbuf_write_op const *w)
{
    if (w->zstd_cctx != nullptr && w->zstd_end_op == ZSTD_e_end) {
        return w->zbuf_remaining == 0 && w->residual == 0;
    }
    return w->residual == 0;
}

// memcpy min(n, <buffer-space-available>) bytes from `src` into the active
// vbuf segment, and adjust both `src` and `n` to account for the bytes being
// copied; returns the number of bytes written, which is < n if the active
// segment ran out of space; if write_op == WRITE_OP_SKIP, just move the
// pointers (the memfd_create regions will be zero-filled when demand-paged,
// no need to memset)
static size_t write_to_active_segment_uncompressed(
    struct monad_vbuf_writer *vbw, struct vbuf_write_op *write_op)
{
    size_t const buf_space = bytes_free(&vbw->active_map);
    size_t const n_written =
        write_op->residual <= buf_space ? write_op->residual : buf_space;
    if (write_op->type == WRITE_OP_MEMCPY) {
        memcpy(vbw->active_map.next, write_op->src, n_written);
        write_op->src = (uint8_t const *)write_op->src + n_written;
    }
    write_op->residual -= n_written;
    vbw->active_map.next += n_written;
    vbw->virtual_offset += n_written;
    return n_written;
}

static ssize_t write_to_active_segment_compressed(
    struct monad_vbuf_writer *vbw, struct vbuf_write_op *write_op,
    size_t *compressed_size)
{
TryAgain:
    ZSTD_inBuffer in_buf = {
        .src = write_op->src, .size = write_op->residual, .pos = 0};

    ZSTD_outBuffer out_buf = {
        .dst = vbw->active_map.next,
        .size = bytes_free(&vbw->active_map),
        .pos = 0};

    // The uncompressed skips above can just move the write pointer in the
    // active vbuf segment, but for zstd-compressed skips we have to give it
    // some dummy zero byte array to "compress"
    if (write_op->type == WRITE_OP_SKIP) {
        write_op->src = ZERO_ARRAY;
        in_buf.size = write_op->residual < sizeof ZERO_ARRAY
                          ? write_op->residual
                          : sizeof ZERO_ARRAY;
    }

    write_op->zbuf_remaining = ZSTD_compressStream2(
        vbw->options.zstd_cctx, &out_buf, &in_buf, write_op->zstd_end_op);
    if (ZSTD_isError(write_op->zbuf_remaining)) {
        return -FORMAT_ERRC(
            EIO,
            "ZSTD_compressStream2 failed in vbuf: %s",
            ZSTD_getErrorName(write_op->zbuf_remaining));
    }
    write_op->residual -= in_buf.pos;
    vbw->virtual_offset += in_buf.pos;
    vbw->active_map.next += out_buf.pos;
    *compressed_size += out_buf.pos;
    if (write_op->type == WRITE_OP_MEMCPY) {
        write_op->src = (uint8_t const *)write_op->src + in_buf.pos;
    }
    else if (MONAD_UNLIKELY(
                 write_op->residual > 0 && out_buf.pos != out_buf.size)) {
        // XXX: make sure this can't be an infinite loop
        goto TryAgain;
    }

    return (ssize_t)(in_buf.size - in_buf.pos);
}

static ssize_t write_to_active_segment(
    struct monad_vbuf_writer *vbw, struct vbuf_write_op *write_op)
{
    return write_op->zstd_cctx != nullptr
               ? write_to_active_segment_compressed(
                     vbw,
                     write_op,
                     &((struct monad_vbuf_writer_zstd *)vbw)->compressed_size)
               : (ssize_t)write_to_active_segment_uncompressed(vbw, write_op);
}

static int vbuf_write_internal(
    struct monad_vbuf_writer *vbw, struct vbuf_write_op *write_op,
    struct monad_vbuf_chain *full_segments)
{
    int rc;
    struct rollback_state rollback;
    ssize_t n_written;

    if (vbw->active_segment == nullptr) {
        if ((rc = activate_new_segment(vbw)) != 0) {
            return rc;
        }
    }

    // Configure the rollback in case
    rollback.segment = vbw->active_segment;
    rollback.mapping = vbw->active_map;

    n_written = write_to_active_segment(vbw, write_op);
    if (MONAD_UNLIKELY(n_written < 0)) {
        rollback_failed_write(vbw, full_segments, &rollback);
        return (int)-n_written;
    }
    if (MONAD_LIKELY(write_op_is_complete(write_op))) {
        // Fast path: only required one write op
        return 0;
    }

    // Slow path: at least one additional segment needs to be allocated;
    // this is more complex because of the need to roll back to the initial
    // state if it fails, including the partial write we just did above

    // Retire the active segment manually; in the loop this is done by calling
    // flush_active_segment, but that also removes the active segment's memory
    // mapping; we don't want to unmap the first active segment in case we have
    // to roll back to it
    vbw->active_segment->size = vbw->segment_size;
    monad_vbuf_chain_insert_tail(full_segments, vbw->active_segment);

    if ((rc = activate_new_segment(vbw)) != 0) {
        rollback_failed_write(vbw, full_segments, &rollback);
        return rc;
    }

    while (true) {
        n_written = write_to_active_segment(vbw, write_op);
        if (MONAD_UNLIKELY(n_written < 0)) {
            rollback_failed_write(vbw, full_segments, &rollback);
            return (int)-n_written;
        }
        if (MONAD_LIKELY(write_op_is_complete(write_op))) {
            break;
        }
        monad_vbuf_chain_insert_tail(full_segments, flush_active_segment(vbw));
        if ((rc = activate_new_segment(vbw)) != 0) {
            rollback_failed_write(vbw, full_segments, &rollback);
            return rc;
        }
    }

    // The initial active segment's mapping was not removed, in case we needed
    // to rollback. If we removed it right away, there's a chance that an mmap
    // to put it back could fail, and we would corrupt the state of the object.
    // We left the first active segment mapping in place, and need to tear it
    // down now that the write was successful
    unmap_vbuf_segment(&rollback.mapping);
    return 0;
}

void monad_vbuf_chain_free(struct monad_vbuf_chain *chain)
{
    struct monad_vbuf_segment *s;
    if (chain != nullptr) {
        while ((s = TAILQ_FIRST(&chain->segments))) {
            monad_vbuf_segment_free(monad_vbuf_chain_remove(chain, s));
        }
        chain->segment_count = 0;
        chain->vbuf_length = 0;
    }
}

void monad_vbuf_segment_free(struct monad_vbuf_segment *s)
{
    if (s != nullptr) {
        (void)close(s->fd);
        free(s);
    }
}

int monad_vbuf_writer_create(
    struct monad_vbuf_writer **vbw_p,
    struct monad_vbuf_writer_options const *options)
{
    struct monad_vbuf_writer *vbw;
    unsigned segment_shift;
    size_t alloc_size;
    bool is_zstd;
    unsigned const min_segment_shift =
        stdc_trailing_zeros((unsigned)getpagesize());

    *vbw_p = nullptr;
    is_zstd = options->zstd_cctx != nullptr;
    segment_shift = options->segment_shift;
    if (is_zstd && segment_shift == MONAD_VBUF_ZSTD_SHIFT) {
        segment_shift = stdc_bit_width(ZSTD_CStreamOutSize());
    }
    if (segment_shift < min_segment_shift) {
        return FORMAT_ERRC(
            ERANGE,
            "segment size shift %hhu less than minimum allowed %u",
            segment_shift,
            min_segment_shift);
    }
    alloc_size = is_zstd ? sizeof(struct monad_vbuf_writer_zstd)
                         : sizeof(struct monad_vbuf_writer);
    *vbw_p = vbw = malloc(alloc_size);
    memset(vbw, 0, alloc_size);
    vbw->options = *options;
    vbw->segment_size = 1UL << segment_shift;
    return 0;
}

struct monad_vbuf_writer_options const *
monad_vbuf_writer_get_create_options(struct monad_vbuf_writer const *vbw)
{
    return &vbw->options;
}

size_t monad_vbuf_writer_get_offset(struct monad_vbuf_writer const *vbw)
{
    return vbw->virtual_offset;
}

int monad_vbuf_writer_skip_bytes(
    struct monad_vbuf_writer *vbw, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments)
{
    if (!stdc_has_single_bit(align)) {
        return FORMAT_ERRC(EINVAL, "alignment %lu not a power of 2", align);
    }

    struct vbuf_write_op write_op = {
        .type = WRITE_OP_SKIP,
        .src = nullptr,
        .residual = monad_round_size_to_align(vbw->virtual_offset + n, align) -
                    vbw->virtual_offset,
        .zstd_cctx = vbw->options.zstd_cctx,
        .zstd_end_op = ZSTD_e_continue,
        .zbuf_remaining = 0,
    };

    return vbuf_write_internal(vbw, &write_op, full_segments);
}

int monad_vbuf_writer_memcpy(
    struct monad_vbuf_writer *vbw, void const *src, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments)
{
    // The alignment of a vbuf memcpy is implemented as a skip of zero bytes,
    // with a post-skip alignment of the virtual offset. This is also why we
    // don't promise to roll back the alignment part of the operation, if an
    // aligned memcpy fails
    if (align > 1) {
        int const rc =
            monad_vbuf_writer_skip_bytes(vbw, 0, align, full_segments);
        if (rc != 0) {
            return rc;
        }
    }

    struct vbuf_write_op write_op = {
        .type = WRITE_OP_MEMCPY,
        .src = src,
        .residual = n,
        .zstd_cctx = vbw->options.zstd_cctx,
        .zstd_end_op = ZSTD_e_continue,
        .zbuf_remaining = 0,
    };

    return vbuf_write_internal(vbw, &write_op, full_segments);
}

int monad_vbuf_writer_flush(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain)
{
    int rc;

    if (vbw->options.zstd_cctx != nullptr) {
        struct vbuf_write_op write_op = {
            .type = WRITE_OP_SKIP,
            .src = nullptr,
            .residual = 0,
            .zstd_cctx = vbw->options.zstd_cctx,
            .zstd_end_op = ZSTD_e_end,
            .zbuf_remaining = 0,
        };
        if ((rc = vbuf_write_internal(vbw, &write_op, flush_chain)) != 0) {
            return rc;
        }
    }

    struct monad_vbuf_segment *flushed = flush_active_segment(vbw);
    if (flushed != nullptr) {
        monad_vbuf_chain_insert_tail(flush_chain, flushed);
    }
    return 0;
}

int monad_vbuf_writer_reset(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain,
    size_t *prev_virtual_offset)
{
    int rc;
    if (prev_virtual_offset != nullptr) {
        *prev_virtual_offset = monad_vbuf_writer_get_offset(vbw);
    }
    rc = monad_vbuf_writer_flush(vbw, flush_chain);
    vbw->virtual_offset = 0;
    if (rc == 0 && vbw->options.zstd_cctx != nullptr) {
        size_t const zstd_return =
            ZSTD_CCtx_reset(vbw->options.zstd_cctx, ZSTD_reset_session_only);
        if (ZSTD_isError(zstd_return)) {
            rc = FORMAT_ERRC(
                EIO,
                "ZSTD_CCtx_reset failed: %s",
                ZSTD_getErrorName(zstd_return));
        }
    }
    return rc;
}

int monad_vbuf_writer_destroy(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain)
{
    int rc = 0;
    if (vbw != nullptr) {
        rc = monad_vbuf_writer_flush(vbw, flush_chain);
        ZSTD_freeCCtx(vbw->options.zstd_cctx); // Accepts nullptr
        free(vbw);
    }
    return rc;
}

char const *monad_vbuf_writer_get_last_error()
{
    return g_error_buf;
}
