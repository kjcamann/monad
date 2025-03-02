#pragma once

/**
 * @file
 *
 * This file defines the execution event recorder. It is up to the frontend
 * process to configure the recorder in this library, otherwise recording will
 * remain disabled.
 */

#include <monad/config.hpp>
#include <monad/core/exec_event_ctypes.h>
#include <monad/event/event_recorder.h>
#include <monad/event/event_ring.h>

#include <atomic>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <string.h>

MONAD_NAMESPACE_BEGIN

class ExecutionEventRecorder
{
public:
    static constexpr uint16_t BLOCK_FLOW_SIZE = 4096;

    explicit ExecutionEventRecorder(
        int ring_fd, std::string_view ring_path, monad_event_ring const &);

    ~ExecutionEventRecorder();

    std::pair<uint16_t, monad_exec_block_header *> next_block_flow_id();

    uint16_t get_block_flow_id()
    {
        return block_flow_id_;
    }

    void clear_block_flow_id()
    {
        block_flow_id_ = 0;
    }

    monad_event_descriptor *
    record_reserve(size_t payload_size, uint64_t *seqno, uint8_t **payload)
    {
        if (exiting_.load(std::memory_order::acquire)) [[unlikely]] {
            return nullptr;
        }
        return monad_event_recorder_reserve(
            &exec_recorder_, payload_size, seqno, payload);
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    void record(
        std::optional<uint32_t> opt_txn_num, monad_exec_event_type type,
        T const &payload)
    {
        if (exiting_.load(std::memory_order::acquire)) [[unlikely]] {
            return;
        }

        uint64_t seqno;
        uint8_t *payload_buf;

        monad_exec_flow_info const flow_info = {
            .block_flow_id = block_flow_id_,
            .txn_id = opt_txn_num.value_or(-1) + 1};

        monad_event_descriptor *const event = monad_event_recorder_reserve(
            &exec_recorder_, sizeof payload, &seqno, &payload_buf);
        memcpy(payload_buf, &payload, sizeof payload);
        event->event_type = std::to_underlying(type);
        event->user[0] = std::bit_cast<uint64_t>(flow_info);
        __atomic_store_n(&event->seqno, seqno, __ATOMIC_RELEASE);
    }

    template <typename T, std::same_as<std::span<std::byte const>>... U>
        requires std::is_trivially_copyable_v<T>
    void record(
        std::optional<uint32_t> opt_txn_num, monad_exec_event_type type,
        T const &payload, U... bufs)
    {
        if (exiting_.load(std::memory_order::acquire)) [[unlikely]] {
            return;
        }

        uint64_t seqno;
        uint8_t *payload_buf;
        size_t const payload_size = (size(bufs) + ... + sizeof payload);

        monad_exec_flow_info const flow_info = {
            .block_flow_id = block_flow_id_,
            .txn_id = opt_txn_num.value_or(-1) + 1};

        monad_event_descriptor *const event = monad_event_recorder_reserve(
            &exec_recorder_, payload_size, &seqno, &payload_buf);
        void *p = mempcpy(payload_buf, &payload, sizeof payload);
        ((p = mempcpy(p, data(bufs), size(bufs))), ...);
        event->event_type = std::to_underlying(type);
        event->user[0] = std::bit_cast<uint64_t>(flow_info);
        __atomic_store_n(&event->seqno, seqno, __ATOMIC_RELEASE);
    }

private:
    alignas(64) monad_event_recorder exec_recorder_;
    monad_event_ring exec_ring_;
    std::span<monad_exec_block_header> block_headers_;
    uint64_t block_flow_count_;
    uint16_t block_flow_id_;
    std::string ring_path_;
    int ring_fd_;
    std::atomic<bool> exiting_;
};

inline std::pair<uint16_t, monad_exec_block_header *>
ExecutionEventRecorder::next_block_flow_id()
{
    block_flow_id_ = block_flow_count_++ & 0xFFF;
    if (block_flow_id_ == 0) {
        // 0 is not a valid block id; take another one
        block_flow_id_ = block_flow_count_++ & 0xFFF;
    }
    return {block_flow_id_, &block_headers_[block_flow_id_]};
}

// TODO(ken): could use "magic statics" here, but we don't care as much about
//    initialization races compared to the potential cost of poking at guard
//    variables every time. Is there a better solution?
extern std::unique_ptr<ExecutionEventRecorder> g_exec_event_recorder;

template <typename T>
    requires std::is_trivially_copyable_v<T>
void record_exec_event(
    std::optional<uint32_t> opt_txn_num, monad_exec_event_type type,
    T const &payload)
{
    if (auto *const e = g_exec_event_recorder.get()) {
        return e->record(opt_txn_num, type, payload);
    }
}

template <typename T, std::same_as<std::span<std::byte const>>... U>
    requires std::is_trivially_copyable_v<T>
void record_exec_event(
    std::optional<uint32_t> opt_txn_num, monad_exec_event_type type,
    T const &payload, U &&...bufs)
{
    if (auto *const e = g_exec_event_recorder.get()) {
        e->record(opt_txn_num, type, payload, std::forward<U...>(bufs...));
    }
}

MONAD_NAMESPACE_END
