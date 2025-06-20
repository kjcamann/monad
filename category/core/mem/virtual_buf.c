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
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/format_err.h>
#include <category/core/mem/virtual_buf.h>
#include <category/core/srcloc.h>

/*
 * Operation of the vbuf
 *
 * Each vbuf segment describes a piece of virtual memory that can be used to
 * hold part of the virtual buffer. At any given time, the vbuf writer has
 * a pointer to the "active" vbuf segment, which will receive the next write
 * to the buffer.
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

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        g_error_buf,                                                           \
        sizeof(g_error_buf),                                                   \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

extern void activate_next_segment(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *free_vbufs)
{
    struct monad_vbuf_segment *vs;
    struct monad_vbuf_segment_allocator *const sa = vbw->segment_alloc;
    vs = TAILQ_FIRST(&free_vbufs->segments);
    MONAD_ASSERT(vs);
    monad_vbuf_chain_remove(free_vbufs, vs);
    vs->base_virtual_offset = vbw->virtual_offset;
    if (sa->ops->activate != nullptr) {
        sa->ops->activate(sa, vs);
    }
    vbw->active_segment = vs;
}

[[nodiscard]] extern struct monad_vbuf_segment *
flush_active_segment(struct monad_vbuf_writer *vbw)
{
    struct monad_vbuf_segment_allocator *const sa = vbw->segment_alloc;
    struct monad_vbuf_segment *flushed = vbw->active_segment;
    if (flushed != nullptr) {
        if (sa->ops->deactivate != nullptr) {
            sa->ops->deactivate(sa, flushed);
        }
        if (flushed->written == 0) {
            monad_vbuf_segment_free(flushed);
            flushed = nullptr;
        }
        vbw->active_segment = nullptr;
    }
    return flushed;
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
        struct monad_vbuf_segment_allocator *const sa = s->allocator;
        sa->ops->free(sa, s);
    }
}

int _monad_vbuf_write_internal_slow_path(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_write_op *write_op,
    struct monad_vbuf_chain *full_segments, size_t free_space)
{
    int rc;
    struct monad_vbuf_chain free_vbufs;
    struct monad_vbuf_segment_allocator *sa;

    monad_vbuf_chain_init(&free_vbufs);
    sa = vbw->segment_alloc;
    while (write_op->residual > free_space) {
        struct monad_vbuf_segment *vs;
        rc = sa->ops->allocate(sa, &vs);
        if (rc != 0) {
            FORMAT_ERRC(rc, "vbuf segment allocation failed");
            monad_vbuf_chain_free(&free_vbufs);
            return rc;
        }
        monad_vbuf_chain_insert_tail(&free_vbufs, vs);
        free_space += vs->capacity;
    }
    vbw->segment_count += free_vbufs.segment_count;

    if (vbw->active_segment == nullptr) {
        activate_next_segment(vbw, &free_vbufs);
    }
WriteNextSegment:
    monad_vbuf_write_to_active_segment(vbw, write_op);
    if (write_op->residual == 0) {
        return 0;
    }
    monad_vbuf_chain_insert_tail(full_segments, flush_active_segment(vbw));
    activate_next_segment(vbw, &free_vbufs);
    goto WriteNextSegment;
}

int monad_vbuf_writer_create(
    struct monad_vbuf_writer **vbw_p,
    struct monad_vbuf_segment_allocator *segment_alloc)
{
    struct monad_vbuf_writer *vbw;
    *vbw_p = vbw = malloc(sizeof *vbw);
    memset(vbw, 0, sizeof *vbw);
    vbw->segment_alloc = segment_alloc;
    return 0;
}

struct monad_vbuf_segment_allocator *
monad_vbuf_writer_get_allocator(struct monad_vbuf_writer *vbw)
{
    return vbw->segment_alloc;
}

void monad_vbuf_writer_flush(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain)
{
    struct monad_vbuf_segment *flushed = flush_active_segment(vbw);
    if (flushed != nullptr) {
        monad_vbuf_chain_insert_tail(flush_chain, flushed);
    }
}

size_t monad_vbuf_writer_reset(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain)
{
    size_t const prev_virtual_offset = monad_vbuf_writer_get_offset(vbw);
    monad_vbuf_writer_flush(vbw, flush_chain);
    vbw->virtual_offset = 0;
    return prev_virtual_offset;
}

void monad_vbuf_writer_destroy(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_chain *flush_chain)
{
    if (vbw != nullptr) {
        monad_vbuf_writer_flush(vbw, flush_chain);
        free(vbw);
    }
}

char const *monad_vbuf_writer_get_last_error()
{
    return g_error_buf;
}

struct monad_vbuf_mmap_allocator
{
    struct monad_vbuf_segment_allocator alloc;
    uint8_t segment_shift;
    int mmap_flags;
};

static int mmap_segment_allocate(
    struct monad_vbuf_segment_allocator *a, struct monad_vbuf_segment **vs_p)
{
    struct monad_vbuf_segment *vs;
    struct monad_vbuf_mmap_allocator *const mmap_alloc =
        (struct monad_vbuf_mmap_allocator *)a;
    *vs_p = vs = malloc(sizeof *vs);
    if (vs == nullptr) {
        return errno;
    }
    memset(vs, 0, sizeof *vs);
    vs->capacity = 1UL << mmap_alloc->segment_shift;
    vs->allocator = a;
    vs->map_base = mmap(
        nullptr,
        vs->capacity,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | mmap_alloc->mmap_flags,
        -1,
        0);
    if (vs->map_base == MAP_FAILED) {
        free(vs);
        return errno;
    }
    vs->alloc_private = 0;
    return 0;
}

static void mmap_segment_free(
    struct monad_vbuf_segment_allocator *, struct monad_vbuf_segment *vs)
{
    if (vs != nullptr) {
        if (vs->map_base != nullptr) {
            (void)munmap(vs->map_base, vs->capacity);
        }
        free(vs);
    }
}

static struct monad_vbuf_segment_alloc_ops mmap_alloc_ops = {
    .allocate = mmap_segment_allocate,
    .free = mmap_segment_free,
    .activate = nullptr,
    .deactivate = nullptr,
};

int monad_vbuf_mmap_allocator_create(
    struct monad_vbuf_mmap_allocator **mmap_alloc_p, uint8_t segment_shift,
    int mmap_flags)
{
    struct monad_vbuf_mmap_allocator *mmap_alloc;
    unsigned const min_segment_shift =
        stdc_trailing_zeros((unsigned)getpagesize());
    *mmap_alloc_p = nullptr;
    if (segment_shift < min_segment_shift) {
        return FORMAT_ERRC(
            ERANGE,
            "segment size shift %hhu less than minimum allowed %u",
            segment_shift,
            min_segment_shift);
    }
    *mmap_alloc_p = mmap_alloc = malloc(sizeof *mmap_alloc);
    mmap_alloc->alloc.ops = &mmap_alloc_ops;
    mmap_alloc->segment_shift = segment_shift;
    mmap_alloc->mmap_flags = mmap_flags;
    return 0;
}

void monad_vbuf_mmap_allocator_destroy(
    struct monad_vbuf_mmap_allocator *mmap_alloc)
{
    free(mmap_alloc);
}
