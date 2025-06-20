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

#ifndef MONAD_EVCAP_WRITER_INTERNAL
    #error This file should only be included directly by evcap_writer.h
#endif

#include <category/core/event/event_def.h>
#include <category/core/mem/virtual_buf.h>

inline int monad_evcap_vbuf_append_event(
    struct monad_vbuf_writer *vbuf_writer,
    struct monad_event_descriptor const *event, void const *payload,
    struct monad_vbuf_chain *vbuf_chain)
{
    int rc;
    size_t const initial_offset = monad_vbuf_writer_get_offset(vbuf_writer);

    // Write the event descriptor and payload. The writes may need to insert
    // padding to align the next descriptor to a "safe" file offset:
    //
    //    .--------------.
    //    |  Descriptor  |
    //    .--------------.
    //    |    Payload   |
    //    .--------------.
    //    |  Total size  |
    //    .--------------.
    //    | Tail padding |
    //    .--------------. <-- Aligned to alignof(monad_event_descriptor)
    //
    // This is needed because the reader will mmap this section, and may try
    // to copy the descriptor with an expression like `*copy = *event` rather
    // than memcpy. Event descriptors are over-aligned (to the cache line
    // size), and in optimized binaries this typed copy may be lowered to a
    // 64-byte aligned instruction such as the x64-64 AVX512 `vmovdqa64`. If
    // this happens at an unaligned address, this will fail (and it will appear
    // as a SIGSEGV with si_code set to SI_KERNEL, and the _wrong_ fault
    // address, rather than the expected SIGBUS).
    rc = monad_vbuf_writer_memcpy(
        vbuf_writer,
        event,
        sizeof *event,
        alignof(struct monad_event_descriptor),
        vbuf_chain);
    if (rc != 0) {
        return rc;
    }

    // memcpy to an "unaligned" address since it's slightly faster and we know
    // we're 64-byte aligned already
    rc = monad_vbuf_writer_memcpy(
        vbuf_writer, payload, event->payload_size, 1, vbuf_chain);
    if (rc != 0) {
        return rc;
    }

    // Store the total size, including of the `total_size` value itself, so we
    // can scan backwards; needed to implement monad_evcap_event_iter_prev
    size_t const total_size = monad_vbuf_writer_get_offset(vbuf_writer) -
                              initial_offset + sizeof total_size;
    rc = monad_vbuf_writer_memcpy(
        vbuf_writer,
        &total_size,
        sizeof total_size,
        alignof(size_t),
        vbuf_chain);
    if (rc != 0) {
        return rc;
    }

    // Note: we're not aligned to the next descriptor boundary yet, it is done
    // on the subsequent write; the final event does not necessary have full
    // event descriptor tail padding
    return 0;
}
