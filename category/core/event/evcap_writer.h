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

#pragma once

/**
 * @file
 *
 * This file defines the interface for writing event capture files
 */

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_evcap_dynamic_section;
struct monad_evcap_section_desc;
struct monad_evcap_writer;

struct monad_event_descriptor;
struct monad_event_iterator;
struct monad_event_metadata;

struct monad_vbuf_chain;
struct monad_vbuf_segment;
struct monad_vbuf_writer;

enum monad_evcap_section_type : uint16_t;
enum monad_event_content_type : uint16_t;

int monad_evcap_writer_create(struct monad_evcap_writer **, int fd);

void monad_evcap_writer_destroy(struct monad_evcap_writer *);

int monad_evcap_writer_get_fd(struct monad_evcap_writer const *);

int monad_evcap_writer_alloc_empty_section(
    struct monad_evcap_writer *, enum monad_evcap_section_type, size_t *size,
    struct monad_evcap_section_desc **);

#if 0
ssize_t monad_evcap_writer_new_section(
    struct monad_evcap_writer *, struct monad_evcap_section_desc const *,
    void const *buf, size_t nbyte);
#endif

int monad_evcap_writer_add_schema_section(
    struct monad_evcap_writer *, enum monad_event_content_type,
    uint8_t const *schema_hash);

int monad_evcap_writer_dyn_sec_open(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section **,
    struct monad_evcap_section_desc **);

ssize_t monad_evcap_writer_dyn_sec_write(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section *,
    void const *buf, size_t size);

ssize_t monad_evcap_writer_dyn_sec_sendfile(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section *,
    int in_fd, off_t offset, size_t size);

ssize_t monad_evcap_writer_dyn_sec_sync_vbuf_segment(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section *,
    struct monad_vbuf_segment const *);

ssize_t monad_evcap_writer_dyn_sec_sync_vbuf_chain(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section *,
    struct monad_vbuf_chain const *);

int monad_evcap_writer_dyn_sec_close(
    struct monad_evcap_writer *, struct monad_evcap_dynamic_section *);

int monad_evcap_writer_commit_seqno_index(
    struct monad_evcap_writer *, struct monad_vbuf_chain const *,
    enum monad_evcap_section_compression, size_t uncompressed_length,
    struct monad_evcap_section_desc *event_bundle_desc);

int monad_evcap_vbuf_append_event(
    struct monad_vbuf_writer *, enum monad_event_content_type,
    struct monad_event_descriptor const *, void const *payload,
    struct monad_vbuf_chain *);

char const *monad_evcap_writer_get_last_error();

#ifdef __cplusplus
} // extern "C"
#endif
