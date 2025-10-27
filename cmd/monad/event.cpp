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

#include "event.hpp"

#include <category/core/cleanup.h>
#include <category/core/config.hpp>
#include <category/core/event/event_recorder.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/event/owned_event_ring.hpp>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_event_recorder.hpp>
#include <category/vm/event/evmt_event_ctypes.h>
#include <category/vm/event/evmt_event_recorder.hpp>

#include <charconv>
#include <concepts>
#include <cstdint>
#include <expected>
#include <format>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <quill/LogLevel.h>
#include <quill/Quill.h>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

template <std::integral I>
std::string try_parse_int_token(std::string_view s, I *i)
{
    std::from_chars_result const r = std::from_chars(begin(s), end(s), *i, 10);
    if (r.ptr != data(s) + size(s)) {
        return std::format("{} contains non-integer characters", s);
    }
    if (static_cast<int>(r.ec) != 0) {
        std::error_condition const e{r.ec};
        return std::format(
            "could not parse {} as integer: {} ({})",
            s,
            e.message(),
            e.value());
    }
    return {};
}

int mmap_event_ring(
    monad_event_ring_simple_config const &simple_config, int ring_fd,
    char const *ring_path, std::unique_ptr<OwnedEventRing> &owned_event_ring)
{
    // monad_event_ring_init_simple uses fallocate(2), which is more general
    // but won't shrink the file; that's not appropriate here since we're the
    // exclusive owner; truncate it to zero first
    if (ftruncate(ring_fd, 0) == -1) {
        int const saved_errno = errno;
        LOG_ERROR(
            "ftruncate to zero failed for event ring file `{}` ({})",
            ring_path,
            strerror(saved_errno),
            saved_errno);
        (void)unlink(ring_path);
        return saved_errno;
    }

    // We're the exclusive owner; initialize the event ring file
    if (int const rc = monad_event_ring_init_simple(
            &simple_config, ring_fd, 0, ring_path)) {
        LOG_ERROR(
            "event library error -- {}", monad_event_ring_get_last_error());
        return rc;
    }

    // Check if the underlying filesystem supports MAP_HUGETLB
    bool fs_supports_hugetlb;
    if (int const rc = monad_check_path_supports_map_hugetlb(
            ring_path, &fs_supports_hugetlb)) {
        LOG_ERROR(
            "event library error -- {}", monad_event_ring_get_last_error());
        return rc;
    }
    if (!fs_supports_hugetlb) {
        LOG_WARNING(
            "file system hosting event ring file `{}` does not support "
            "MAP_HUGETLB!",
            ring_path);
    }
    int const mmap_extra_flags =
        fs_supports_hugetlb ? MAP_POPULATE | MAP_HUGETLB : MAP_POPULATE;

    // mmap the event ring into this process' address space
    monad_event_ring event_ring;
    if (int const rc = monad_event_ring_mmap(
            &event_ring,
            PROT_READ | PROT_WRITE,
            mmap_extra_flags,
            ring_fd,
            0,
            ring_path)) {
        LOG_ERROR(
            "event library error -- {}", monad_event_ring_get_last_error());
        return rc;
    }

    // owned_fd isn't closed by us, but given to OwnedEventRing
    int const owned_fd = dup(ring_fd);
    if (owned_fd == -1) {
        int const saved_errno = errno;
        LOG_ERROR(
            "could not dup(2) ring file {} fd: {} {}",
            ring_path,
            strerror(saved_errno),
            saved_errno);
        return saved_errno;
    }
    owned_event_ring =
        std::make_unique<OwnedEventRing>(owned_fd, ring_path, event_ring);
    return 0;
}

int init_owned_event_ring(
    EventRingConfig ring_config, monad_event_content_type content_type,
    uint8_t const *schema_hash, uint8_t default_descriptor_shift,
    uint8_t default_payload_buf_shift,
    std::unique_ptr<OwnedEventRing> &owned_event_ring)
{
    // Create with rw-rw-r--
    constexpr mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    if (!ring_config.event_ring_spec.contains('/')) {
        // The event ring specification does not contain a '/' character; this
        // is interpreted as a filename in the default event ring directory,
        // as computed by `monad_event_open_ring_dir_fd`
        char event_ring_dir_path_buf[PATH_MAX];
        int const rc = monad_event_open_ring_dir_fd(
            nullptr, event_ring_dir_path_buf, sizeof event_ring_dir_path_buf);
        if (rc != 0) {
            LOG_ERROR(
                "open of event ring default directory failed: {}",
                monad_event_ring_get_last_error());
            return rc;
        }
        ring_config.event_ring_spec = std::string{event_ring_dir_path_buf} +
                                      '/' + ring_config.event_ring_spec;
    }

    if (ring_config.descriptors_shift == 0) {
        ring_config.descriptors_shift = default_descriptor_shift;
    }
    if (ring_config.payload_buf_shift == 0) {
        ring_config.payload_buf_shift = default_payload_buf_shift;
    }

    // Open the file and acquire a BSD-style exclusive lock on it; note there
    // is no O_TRUNC here because it might already exist and we might not own
    // it (e.g., if we're racing against another execution daemon started
    // accidentally). In that case we'll either win or lose the race to acquire
    // the lock, and will resize it only if we end up winning
    char const *const ring_path = ring_config.event_ring_spec.c_str();
    int ring_fd [[gnu::cleanup(cleanup_close)]] =
        open(ring_path, O_RDWR | O_CREAT, mode);
    if (ring_fd == -1) {
        int const rc = errno;
        LOG_ERROR(
            "open failed for event ring file `{}`: {} [{}]",
            ring_path,
            strerror(rc),
            rc);
        return rc;
    }
    if (flock(ring_fd, LOCK_EX | LOCK_NB) == -1) {
        int const saved_errno = errno;
        if (saved_errno == EWOULDBLOCK) {
            pid_t owner_pid = 0;
            size_t owner_pid_size = 1;

            // Another process has the exclusive lock; find out who it is
            (void)monad_event_ring_find_writer_pids(
                ring_fd, &owner_pid, &owner_pid_size);
            if (owner_pid == 0) {
                LOG_ERROR(
                    "event ring file `{}` is owned by an unknown other process",
                    ring_path);
            }
            else {
                LOG_ERROR(
                    "event ring file `{}` is owned by pid {}",
                    ring_path,
                    owner_pid);
            }
            return saved_errno;
        }
        LOG_ERROR(
            "flock on event ring file `{}` failed: {} ({})",
            ring_path,
            strerror(saved_errno),
            saved_errno);
        return saved_errno;
    }

    monad_event_ring_simple_config const simple_cfg = {
        .descriptors_shift = ring_config.descriptors_shift,
        .payload_buf_shift = ring_config.payload_buf_shift,
        .context_large_pages = 0,
        .content_type = content_type,
        .schema_hash = schema_hash};
    if (int const rc =
            mmap_event_ring(simple_cfg, ring_fd, ring_path, owned_event_ring)) {
        (void)unlink(ring_path);
        return rc;
    }
    LOG_INFO(
        "{} event ring created: {}",
        g_monad_event_content_type_names[std::to_underlying(content_type)],
        ring_path);
    return 0;
}

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

// These symbols link against the global objects in libmonad_execution_ethereum;
// they remain uninitialized if execution event recording is disabled
extern std::unique_ptr<OwnedEventRing> g_exec_event_ring;
extern std::unique_ptr<ExecutionEventRecorder> g_exec_event_recorder;

// As above, but for the EVM tracer
extern std::unique_ptr<OwnedEventRing> g_exec_event_ring;
extern std::unique_ptr<EvmTraceEventRecorder> g_evmt_event_recorder;

// Parse a configuration string, which has the form
//
//   <ring-name-or-path>[:<descriptor-shift>:<buf-shift>]
//
// A shift can be empty, e.g., <descriptor-shift> in `my-file::30`, in which
// case the default value is used
std::expected<EventRingConfig, std::string>
try_parse_event_ring_config(std::string_view s)
{
    std::vector<std::string_view> tokens;
    EventRingConfig cfg;

    for (auto t : std::views::split(s, ':')) {
        tokens.emplace_back(t);
    }

    if (size(tokens) < 1 || size(tokens) > 3) {
        return std::unexpected(std::format(
            "input `{}` does not have "
            "expected format "
            "<ring-name-or-path>[:<descriptor-shift>:<payload-buffer-shift>]",
            s));
    }
    cfg.event_ring_spec = tokens[0];
    if (size(tokens) < 2 || tokens[1].empty()) {
        cfg.descriptors_shift = 0;
    }
    else if (auto err = try_parse_int_token(tokens[1], &cfg.descriptors_shift);
             !empty(err)) {
        return std::unexpected(
            std::format("parse error in ring_shift `{}`: {}", tokens[1], err));
    }

    if (size(tokens) < 3 || tokens[2].empty()) {
        cfg.payload_buf_shift = 0;
    }
    else if (auto err = try_parse_int_token(tokens[2], &cfg.payload_buf_shift);
             !empty(err)) {
        return std::unexpected(std::format(
            "parse error in payload_buffer_shift `{}`: {}", tokens[2], err));
    }

    return cfg;
}

int init_execution_event_recorder(EventRingConfig ring_config)
{
    if (int const rc = init_owned_event_ring(
            std::move(ring_config),
            MONAD_EVENT_CONTENT_TYPE_EXEC,
            g_monad_exec_event_schema_hash,
            DEFAULT_EXEC_RING_DESCRIPTORS_SHIFT,
            DEFAULT_EXEC_RING_PAYLOAD_BUF_SHIFT,
            g_exec_event_ring)) {
        return rc;
    }
    monad_event_recorder recorder;
    if (int const rc = monad_event_ring_init_recorder(
            g_exec_event_ring->get_event_ring(), &recorder)) {
        LOG_ERROR(
            "event library error -- {}", monad_event_ring_get_last_error());
        return rc;
    }
    g_exec_event_recorder = std::make_unique<ExecutionEventRecorder>(recorder);
    return 0;
}

int init_evm_trace_event_recorder(EventRingConfig ring_config)
{
    if (int const rc = init_owned_event_ring(
            std::move(ring_config),
            MONAD_EVENT_CONTENT_TYPE_EVMT,
            g_monad_evmt_event_schema_hash,
            DEFAULT_EVMT_RING_DESCRIPTORS_SHIFT,
            DEFAULT_EVMT_RING_PAYLOAD_BUF_SHIFT,
            g_evmt_event_ring)) {
        return rc;
    }
    monad_event_recorder recorder;
    if (int const rc = monad_event_ring_init_recorder(
            g_evmt_event_ring->get_event_ring(), &recorder)) {
        LOG_ERROR(
            "event library error -- {}", monad_event_ring_get_last_error());
        return rc;
    }
    g_evmt_event_recorder = std::make_unique<EvmTraceEventRecorder>(recorder);
    return 0;
}

MONAD_NAMESPACE_END
