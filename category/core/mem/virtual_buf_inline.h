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

#ifndef MONAD_VIRTUAL_BUF_INTERNAL
    #error This file should only be included directly by virtual_buf.h
#endif

#include <errno.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <category/core/likely.h>
#include <category/core/mem/align.h>

// All state variables of the writer
struct monad_vbuf_writer
{
    struct monad_vbuf_segment *active_segment;
    size_t virtual_offset;
    struct monad_vbuf_segment_allocator *segment_alloc;
    size_t segment_count;
};

typedef enum monad_vbuf_write_op_type
{
    MONAD_VBUF_SKIP,
    MONAD_VBUF_MEMCPY
} monad_vbuf_write_op_type_t;

struct monad_vbuf_write_op
{
    monad_vbuf_write_op_type_t type;
    void const *src;
    size_t residual;
};

#ifdef __cplusplus
extern "C"
{
#endif

int _monad_vbuf_write_internal_slow_path(
    struct monad_vbuf_writer *, struct monad_vbuf_write_op *,
    struct monad_vbuf_chain *, size_t free_space);

#ifdef __cplusplus
} // extern "C"
#endif

static inline size_t monad_vbuf_write_to_active_segment(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_write_op *write_op)
{
    struct monad_vbuf_segment *const vs = vbw->active_segment;
    size_t const buf_space = (size_t)(vs->capacity - vs->written);
    size_t const n_written =
        write_op->residual <= buf_space ? write_op->residual : buf_space;
    if (write_op->type == MONAD_VBUF_MEMCPY) {
        memcpy(vs->map_base + vs->written, write_op->src, n_written);
        write_op->src = (uint8_t const *)write_op->src + n_written;
    }
    write_op->residual -= n_written;
    vs->written += n_written;
    vbw->virtual_offset += n_written;
    return n_written;
}

[[gnu::always_inline]]
static inline int monad_vbuf_write_internal(
    struct monad_vbuf_writer *vbw, struct monad_vbuf_write_op *write_op,
    struct monad_vbuf_chain *full_segments)
{

    size_t const free_space =
        monad_vbuf_segment_bytes_free(vbw->active_segment);
    if (MONAD_UNLIKELY(write_op->residual == 0)) {
        // Explicitly ignoring no-ops removes some special-casing in
        // monad_write_to_active_segment
        return 0;
    }
    if (MONAD_LIKELY(write_op->residual <= free_space)) {
        // Fast path: the entire write will fit in the active segment
        monad_vbuf_write_to_active_segment(vbw, write_op);
        return 0;
    }

    // Slow path: the write will need to allocate additional segments to fit
    // all the data; we pre-allocate as many as will be needed up front, so
    // that the entire write will succeed or fail atomically
    return _monad_vbuf_write_internal_slow_path(
        vbw, write_op, full_segments, free_space);
}

inline size_t monad_vbuf_writer_get_offset(struct monad_vbuf_writer const *vbw)
{
    return vbw->virtual_offset;
}

inline int monad_vbuf_writer_skip_bytes(
    struct monad_vbuf_writer *vbw, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments)
{
#if 0
    if (MONAD_UNLIKELY(!stdc_has_single_bit(align))) {
        return FORMAT_ERRC(EINVAL, "alignment %lu not a power of 2", align);
    }
#endif
    struct monad_vbuf_write_op write_op = {
        .type = MONAD_VBUF_SKIP,
        .src = nullptr,
        .residual = monad_round_size_to_align(vbw->virtual_offset + n, align) -
                    vbw->virtual_offset,
    };
    return monad_vbuf_write_internal(vbw, &write_op, full_segments);
}

inline int monad_vbuf_writer_memcpy(
    struct monad_vbuf_writer *vbw, void const *src, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments)
{
    // The alignment of a vbuf memcpy is implemented as a skip of zero bytes,
    // with a post-skip alignment of the virtual offset.
    if (align > 1) {
        int const rc =
            monad_vbuf_writer_skip_bytes(vbw, 0, align, full_segments);
        if (rc != 0) {
            return rc;
        }
    }
    struct monad_vbuf_write_op write_op = {
        .type = MONAD_VBUF_MEMCPY,
        .src = src,
        .residual = n,
    };
    return monad_vbuf_write_internal(vbw, &write_op, full_segments);
}
