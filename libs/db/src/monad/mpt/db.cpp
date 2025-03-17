#include <monad/mpt/db.hpp>

#include <monad/async/concepts.hpp>
#include <monad/async/config.hpp>
#include <monad/async/connected_operation.hpp>
#include <monad/async/detail/scope_polyfill.hpp>
#include <monad/async/erased_connected_operation.hpp>
#include <monad/async/io.hpp>
#include <monad/async/sender_errc.hpp>
#include <monad/async/storage_pool.hpp>
#include <monad/core/assert.h>
#include <monad/core/byte_string.hpp>
#include <monad/core/result.hpp>
#include <monad/io/buffers.hpp>
#include <monad/io/ring.hpp>
#include <monad/mpt/config.hpp>
#include <monad/mpt/db_error.hpp>
#include <monad/mpt/find_request_sender.hpp>
#include <monad/mpt/nibbles_view.hpp>
#include <monad/mpt/node.hpp>
#include <monad/mpt/ondisk_db_config.hpp>
#include <monad/mpt/traverse.hpp>
#include <monad/mpt/trie.hpp>
#include <monad/mpt/update.hpp>
#include <monad/mpt/util.hpp>

#include <quill/Quill.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

#undef BLOCK_SIZE // without this concurrentqueue.h gets sad
#include "concurrentqueue.h"

MONAD_MPT_NAMESPACE_BEGIN

namespace detail
{
    struct void_receiver
    {
        void set_value(
            async::erased_connected_operation *, async::result<void>) const
        {
        }
    };
}

struct Db::Impl
{
    virtual ~Impl() = default;

    virtual Node::UniquePtr &root() = 0;
    virtual UpdateAux<> &aux() = 0;
    virtual void upsert_fiber_blocking(
        UpdateList &&, uint64_t, bool enable_compaction, bool can_write_to_fast,
        bool write_root) = 0;
    virtual void copy_trie_fiber_blocking(
        uint64_t src_version, NibblesView src, uint64_t dest_version,
        NibblesView dest, bool blocked_by_write = true) = 0;

    virtual find_cursor_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key, uint64_t version) = 0;
    virtual size_t prefetch_fiber_blocking() = 0;
    virtual NodeCursor load_root_for_version(uint64_t version) = 0;
    virtual size_t poll(bool blocking, size_t count) = 0;
    virtual bool traverse_fiber_blocking(
        Node &, TraverseMachine &, uint64_t version,
        size_t concurrency_limit) = 0;
    virtual void
    move_trie_version_fiber_blocking(uint64_t src, uint64_t dest) = 0;
    virtual void update_finalized_block(uint64_t) = 0;
    virtual void update_verified_block(uint64_t) = 0;
    virtual uint64_t get_latest_finalized_block_id() const = 0;
    virtual uint64_t get_latest_verified_block_id() const = 0;
};

AsyncIOContext::AsyncIOContext(ReadOnlyOnDiskDbConfig const &options)
    : pool{[&] -> async::storage_pool {
        async::storage_pool::creation_flags pool_options;
        pool_options.open_read_only = true;
        pool_options.disable_mismatching_storage_pool_check =
            options.disable_mismatching_storage_pool_check;
        MONAD_ASSERT(!options.dbname_paths.empty());
        return async::storage_pool{
            options.dbname_paths,
            async::storage_pool::mode::open_existing,
            pool_options};
    }()}
    , read_ring{monad::io::RingConfig{
          options.uring_entries, false, options.sq_thread_cpu}}
    , buffers{io::make_buffers_for_read_only(
          read_ring, options.rd_buffers,
          async::AsyncIO::MONAD_IO_BUFFERS_READ_SIZE)}
    , io{pool, buffers}
{
    io.set_capture_io_latencies(options.capture_io_latencies);
    io.set_concurrent_read_io_limit(options.concurrent_read_io_limit);
    io.set_eager_completions(options.eager_completions);
}

AsyncIOContext::AsyncIOContext(OnDiskDbConfig const &options)
    : pool{[&] -> async::storage_pool {
        if (options.dbname_paths.empty()) {
            return async::storage_pool{async::use_anonymous_inode_tag{}};
        }
        // initialize db file on disk
        for (auto const &dbname_path : options.dbname_paths) {
            if (!std::filesystem::exists(dbname_path)) {
                int const fd = ::open(
                    dbname_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
                if (-1 == fd) {
                    throw std::system_error(errno, std::system_category());
                }
                auto unfd =
                    monad::make_scope_exit([fd]() noexcept { ::close(fd); });
                if (-1 ==
                    ::ftruncate(
                        fd,
                        options.file_size_db * 1024 * 1024 * 1024 + 24576)) {
                    throw std::system_error(errno, std::system_category());
                }
            }
        }
        return async::storage_pool{
            options.dbname_paths,
            options.append ? async::storage_pool::mode::open_existing
                           : async::storage_pool::mode::truncate};
    }()}
    , read_ring{{options.uring_entries, options.enable_io_polling, options.sq_thread_cpu}}
    , write_ring{options.wr_buffers}
    , buffers{io::make_buffers_for_segregated_read_write(
          read_ring, *write_ring, options.rd_buffers, options.wr_buffers,
          async::AsyncIO::MONAD_IO_BUFFERS_READ_SIZE,
          async::AsyncIO::MONAD_IO_BUFFERS_WRITE_SIZE)}
    , io{pool, buffers}
{
    io.set_capture_io_latencies(options.capture_io_latencies);
    io.set_concurrent_read_io_limit(options.concurrent_read_io_limit);
    io.set_eager_completions(options.eager_completions);
}

struct Db::ROOnDisk final : public Db::Impl
{
    AsyncIOContext &io_ctx_;
    UpdateAux<> aux_;
    chunk_offset_t last_loaded_root_offset_;
    Node::UniquePtr root_;

    explicit ROOnDisk(AsyncIOContext &io_ctx)
        : io_ctx_(io_ctx)
        , aux_(&io_ctx.io)
        , last_loaded_root_offset_{aux_.get_root_offset_at_version(
              aux_.db_history_max_version())}
        , root_{
              last_loaded_root_offset_ == INVALID_OFFSET
                  ? Node::UniquePtr{}
                  : read_node_blocking(
                        aux_, last_loaded_root_offset_,
                        aux_.db_history_max_version())}
    {
    }

    ~ROOnDisk()
    {
        aux_.unique_lock();
        // must be destroyed before aux is destroyed
        aux_.unset_io();
    }

    virtual Node::UniquePtr &root() override
    {
        return root_;
    }

    virtual UpdateAux<> &aux() override
    {
        return aux_;
    }

    virtual void
    upsert_fiber_blocking(UpdateList &&, uint64_t, bool, bool, bool) override
    {
        MONAD_ASSERT(false);
    }

    virtual find_cursor_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key,
        uint64_t const version) override
    {
        if (!root.is_valid()) {
            return {NodeCursor{}, find_result::unknown};
        }
        // the root we last loaded does not contain the version we want to find
        if (!aux().version_is_valid_ondisk(version)) {
            return {NodeCursor{}, find_result::version_no_longer_exist};
        }
        auto const res = find_blocking(aux(), root, key, version);
        // verify version still valid in history after success
        return aux().version_is_valid_ondisk(version)
                   ? res
                   : find_cursor_result_type{
                         NodeCursor{}, find_result::version_no_longer_exist};
    }

    virtual void move_trie_version_fiber_blocking(uint64_t, uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual size_t prefetch_fiber_blocking() override
    {
        MONAD_ASSERT(false);
    }

    virtual void copy_trie_fiber_blocking(
        uint64_t, NibblesView, uint64_t, NibblesView, bool) override
    {
        MONAD_ASSERT(false);
    }

    virtual size_t poll(bool const blocking, size_t const count) override
    {
        return blocking ? aux_.io->poll_blocking(count)
                        : aux_.io->poll_nonblocking(count);
    }

    virtual bool traverse_fiber_blocking(
        Node &node, TraverseMachine &machine, uint64_t const version,
        size_t const concurrency_limit) override
    {
        return preorder_traverse_ondisk(
            aux(), node, machine, version, concurrency_limit);
    }

    virtual NodeCursor load_root_for_version(uint64_t const version) override
    {
        auto const root_offset = aux().get_root_offset_at_version(version);
        if (root_offset == INVALID_OFFSET) {
            root_ = nullptr;
            last_loaded_root_offset_ = root_offset;
            return NodeCursor{};
        }
        if (last_loaded_root_offset_ != root_offset) {
            last_loaded_root_offset_ = root_offset;
            root_ = read_node_blocking(aux_, root_offset, version);
        }
        return root_ ? NodeCursor{*root_} : NodeCursor{};
    }

    virtual void update_finalized_block(uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual void update_verified_block(uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual uint64_t get_latest_finalized_block_id() const override
    {
        return aux_.get_latest_finalized_version();
    }

    virtual uint64_t get_latest_verified_block_id() const override
    {
        return aux_.get_latest_verified_version();
    }
};

struct Db::InMemory final : public Db::Impl
{
    UpdateAux<> aux_;
    StateMachine &machine_;
    Node::UniquePtr root_;

    explicit InMemory(StateMachine &machine)
        : aux_{nullptr}
        , machine_{machine}
    {
    }

    virtual Node::UniquePtr &root() override
    {
        return root_;
    }

    virtual UpdateAux<> &aux() override
    {
        return aux_;
    }

    virtual void upsert_fiber_blocking(
        UpdateList &&list, uint64_t const version, bool, bool, bool) override
    {
        root_ = aux_.do_update(
            std::move(root_), machine_, std::move(list), version, false);
    }

    virtual void copy_trie_fiber_blocking(
        uint64_t const src_version, NibblesView const src,
        uint64_t const dest_version, NibblesView const dest,
        bool const) override
    {
        // in memory copy_trie only allows moving trie from src to prefix under
        // the same version
        root_ = copy_trie_to_dest(
            aux_, *root_, src, src_version, {}, dest, dest_version, false);
    }

    virtual find_cursor_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key,
        uint64_t const version = 0) override
    {
        return find_blocking(aux(), root, key, version);
    }

    virtual size_t prefetch_fiber_blocking() override
    {
        return 0;
    }

    virtual size_t poll(bool, size_t) override
    {
        return 0;
    }

    virtual bool traverse_fiber_blocking(
        Node &node, TraverseMachine &machine, uint64_t const block_id,
        size_t) override
    {
        return preorder_traverse_blocking(aux_, node, machine, block_id);
    }

    virtual void move_trie_version_fiber_blocking(uint64_t, uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual NodeCursor load_root_for_version(uint64_t) override
    {
        return root() ? NodeCursor{*root()} : NodeCursor{};
    }

    virtual void update_verified_block(uint64_t) override {}

    virtual void update_finalized_block(uint64_t) override {}

    virtual uint64_t get_latest_finalized_block_id() const override
    {
        return INVALID_BLOCK_ID;
    }

    virtual uint64_t get_latest_verified_block_id() const override
    {
        return INVALID_BLOCK_ID;
    }
};

struct Db::RWOnDisk final : public Db::Impl
{
    struct FiberUpsertRequest
    {
        DbSyncObject *sync;
        Node::UniquePtr *new_root;
        Node::UniquePtr prev_root;
        StateMachine &sm;
        UpdateList &&updates;
        uint64_t const version;
        bool const enable_compaction;
        bool const can_write_to_fast;
        bool const write_root;
    };

    struct FiberCopyTrieRequest
    {
        DbSyncObject *sync;
        Node::UniquePtr *new_root;
        Node &src_root;
        NibblesView src;
        uint64_t src_version;
        Node::UniquePtr dest_root;
        NibblesView dest;
        uint64_t dest_version;
        bool blocked_by_write;
    };

    struct FiberLoadAllFromBlockRequest
    {
        DbSyncObject *sync;
        size_t *nodes_loaded;
        NodeCursor root;
        StateMachine &sm;
    };

    struct FiberTraverseRequest
    {
        DbSyncObject *sync;
        bool *is_valid;
        Node &root;
        TraverseMachine &machine;
        uint64_t version;
        size_t concurrency_limit;
    };

    struct MoveSubtrieRequest
    {
        DbSyncObject *sync;
        uint64_t src;
        uint64_t dest;
    };

    struct FiberLoadRootVersionRequest
    {
        DbSyncObject *sync;
        Node::UniquePtr *root;
        uint64_t const version;
    };

    using Comms = std::variant<
        std::monostate, fiber_find_request_t, FiberUpsertRequest,
        FiberLoadAllFromBlockRequest, FiberTraverseRequest, MoveSubtrieRequest,
        FiberLoadRootVersionRequest, FiberCopyTrieRequest>;

    ::moodycamel::ConcurrentQueue<Comms> comms_;

    std::mutex lock_;
    std::condition_variable cond_;

    struct TrieDbWorker
    {
        RWOnDisk *parent;
        UpdateAuxImpl &aux;
        AsyncIOContext async_io;
        bool const compaction;
        std::atomic<bool> sleeping{false}, done{false};

        TrieDbWorker(
            RWOnDisk *parent, UpdateAuxImpl &aux, OnDiskDbConfig const &options)
            : parent(parent)
            , aux(aux)
            , async_io(options)
            , compaction{options.compaction}
        {
        }

        // Runs in the triedb worker thread
        void run()
        {
            inflight_map_t inflights;
            /* In case you're wondering why we use a vector for a single
            element, it's because for some odd reason the MoodyCamel concurrent
            queue only supports move only types via its iterator interface. No
            that makes no sense to me either, but it is what it is.
            */
            std::vector<Comms> request;
            request.reserve(1);
            unsigned did_nothing_count = 0;
            while (!done.load(std::memory_order_acquire)) {
                bool did_nothing = true;
                request.clear();
                if (parent->comms_.try_dequeue_bulk(
                        std::back_inserter(request), 1) > 0) {
                    if (auto *req = std::get_if<1>(&request.front())) {
                        find_notify_fiber_future(aux, inflights, *req);
                    }
                    else if (auto *req = std::get_if<2>(&request.front())) {
                        *req->new_root = aux.do_update(
                            std::move(req->prev_root),
                            req->sm,
                            std::move(req->updates),
                            req->version,
                            compaction && req->enable_compaction,
                            req->can_write_to_fast,
                            req->write_root);
                        req->sync->release();
                    }
                    else if (auto *req = std::get_if<3>(&request.front())) {
                        *req->nodes_loaded =
                            mpt::load_all(aux, req->sm, req->root);
                        req->sync->release();
                    }
                    else if (auto *req = std::get_if<4>(&request.front())) {
                        // verify version is valid
                        if (aux.version_is_valid_ondisk(req->version)) {
                            *req->is_valid = preorder_traverse_ondisk(
                                aux,
                                req->root,
                                req->machine,
                                req->version,
                                req->concurrency_limit);
                        }
                        else {
                            *req->is_valid = false;
                        }
                        req->sync->release();
                    }
                    else if (auto *req = std::get_if<5>(&request.front())) {
                        aux.move_trie_version_forward(req->src, req->dest);
                        req->sync->release();
                    }
                    else if (auto *req = std::get_if<6>(&request.front())) {
                        auto const root_offset =
                            aux.get_root_offset_at_version(req->version);
                        MONAD_ASSERT(root_offset != INVALID_OFFSET);
                        *req->root =
                            read_node_blocking(aux, root_offset, req->version);
                        req->sync->release();
                    }
                    else if (auto *req = std::get_if<7>(&request.front())) {
                        *req->new_root = copy_trie_to_dest(
                            aux,
                            req->src_root,
                            req->src,
                            req->src_version,
                            std::move(req->dest_root),
                            req->dest,
                            req->dest_version,
                            req->blocked_by_write);
                        req->sync->release();
                    }
                    did_nothing = false;
                }
                async_io.io.poll_nonblocking(1);
                if (did_nothing && async_io.io.io_in_flight() > 0) {
                    did_nothing = false;
                }
                if (did_nothing) {
                    did_nothing_count++;
                }
                else {
                    did_nothing_count = 0;
                }
                if (did_nothing_count > 1000000) {
                    std::unique_lock g(parent->lock_);
                    sleeping.store(true, std::memory_order_release);
                    parent->cond_.wait_for(g, std::chrono::seconds(1), [this] {
                        return done.load(std::memory_order_acquire) ||
                               parent->comms_.size_approx() > 0;
                    });
                    sleeping.store(false, std::memory_order_release);
                }
            }
        }
    };

    UpdateAux<> aux_;
    std::unique_ptr<TrieDbWorker> worker_;
    std::thread worker_thread_;
    StateMachine &machine_;
    Node::UniquePtr root_; // owned by worker thread
    uint64_t root_version_{INVALID_BLOCK_ID};
    uint64_t unflushed_version_{INVALID_BLOCK_ID};

    RWOnDisk(OnDiskDbConfig const &options, StateMachine &machine)
        : worker_thread_([&] {
            {
                std::unique_lock const g(lock_);
                worker_ = std::make_unique<TrieDbWorker>(this, aux_, options);
                // This bit is unfortunately nasty, but we have to initialise
                // aux_ from this thread
                aux_.~UpdateAux<>();
                new (&aux_) UpdateAux<>{
                    &worker_->async_io.io, options.fixed_history_length};
                if (options.rewind_to_latest_finalized) {
                    auto const latest_block_id =
                        aux_.get_latest_finalized_version();
                    if (latest_block_id == INVALID_BLOCK_ID) {
                        aux_.clear_ondisk_db();
                    }
                    else {
                        aux_.rewind_to_version(latest_block_id);
                    }
                }
            }
            worker_->run();
            std::unique_lock const g(lock_);
            worker_.reset();
        })
        , machine_{machine}
        , root_([&] {
            comms_.enqueue({});
            while (comms_.size_approx() > 0) {
                std::this_thread::yield();
            }
            std::unique_lock const g(lock_);
            MONAD_ASSERT(worker_);
            return aux_.get_latest_root_offset() != INVALID_OFFSET
                       ? read_node_blocking(
                             aux_,
                             aux_.get_latest_root_offset(),
                             aux_.db_history_max_version())
                       : Node::UniquePtr{};
        }())
        , root_version_(aux_.db_history_max_version())
        , unflushed_version_{INVALID_BLOCK_ID}
    {
    }

    ~RWOnDisk()
    {
        aux_.unique_lock();
        // must be destroyed before aux is destroyed
        aux_.unset_io();
        {
            std::unique_lock const g(lock_);
            worker_->done.store(true, std::memory_order_release);
            cond_.notify_one();
        }
        worker_thread_.join();
    }

    virtual Node::UniquePtr &root() override
    {
        return root_;
    }

    virtual UpdateAux<> &aux() override
    {
        return aux_;
    }

    // threadsafe
    virtual find_cursor_result_type find_fiber_blocking(
        NodeCursor const &start, NibblesView const &key, uint64_t = 0) override
    {
        DbSyncObject sync;
        find_cursor_result_type result;

        fiber_find_request_t const req{
            .sync = &sync, .result = &result, .start = start, .key = key};
        comms_.enqueue(req);
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        return result;
    }

    // threadsafe
    virtual void upsert_fiber_blocking(
        UpdateList &&updates, uint64_t const version,
        bool const enable_compaction, bool const can_write_to_fast,
        bool const write_root) override
    {
        if (unflushed_version_ != INVALID_BLOCK_ID) {
            if (unflushed_version_ != version) {
                LOG_WARNING_CFORMAT(
                    "Update version %lu while db hasn't flushed the last "
                    "update on "
                    "version %lu, the unflushed progress will be lost after "
                    "this point",
                    version,
                    unflushed_version_);
            }
            if (write_root) {
                unflushed_version_ = INVALID_BLOCK_ID;
            }
        }
        // reload root to handle out-of-order upserts
        if (version != root_version_ &&
            (version != root_version_ + 1 ||
             aux().version_is_valid_ondisk(version))) {
            load_root_for_version(version);
        }
        DbSyncObject sync;
        comms_.enqueue(FiberUpsertRequest{
            .sync = &sync,
            .new_root = &root_,
            .prev_root = std::move(root_),
            .sm = machine_,
            .updates = std::move(updates),
            .version = version,
            .enable_compaction = enable_compaction,
            .can_write_to_fast = can_write_to_fast,
            .write_root = write_root});
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        root_version_ = version;
        if (!write_root) {
            unflushed_version_ = version;
        }
    }

    virtual void move_trie_version_fiber_blocking(
        uint64_t const src, uint64_t const dest) override
    {
        DbSyncObject sync;
        comms_.enqueue(
            MoveSubtrieRequest{.sync = &sync, .src = src, .dest = dest});
        // promise is racily emptied after this point
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        root_version_ = dest;
    }

    // threadsafe
    virtual size_t prefetch_fiber_blocking() override
    {
        MONAD_ASSERT(root());
        DbSyncObject sync;
        size_t nodes_loaded;

        comms_.enqueue(FiberLoadAllFromBlockRequest{
            .sync = &sync,
            .nodes_loaded = &nodes_loaded,
            .root = *root(),
            .sm = machine_});
        // promise is racily emptied after this point
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        return nodes_loaded;
    }

    virtual size_t poll(bool, size_t) override
    {
        return 0;
    }

    // threadsafe
    virtual bool traverse_fiber_blocking(
        Node &node, TraverseMachine &machine, uint64_t const version,
        size_t const concurrency_limit) override
    {
        DbSyncObject sync;
        bool is_valid;

        comms_.enqueue(FiberTraverseRequest{
            .sync = &sync,
            .is_valid = &is_valid,
            .root = node,
            .machine = machine,
            .version = version,
            .concurrency_limit = concurrency_limit});
        // promise is racily emptied after this point
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        return is_valid;
    }

    virtual NodeCursor load_root_for_version(uint64_t const version) override
    {
        if (version != root_version_) {
            if (!aux().version_is_valid_ondisk(version)) {
                root_ = nullptr;
                root_version_ = version;
                return NodeCursor{};
            }
            DbSyncObject sync;
            comms_.enqueue(FiberLoadRootVersionRequest{
                .sync = &sync, .root = &root_, .version = version});
            if (worker_->sleeping.load(std::memory_order_acquire)) {
                std::unique_lock const g(lock_);
                cond_.notify_one();
            }
            sync.acquire();
            root_version_ = version;
        }
        return root() ? NodeCursor{*root()} : NodeCursor{};
    }

    virtual void copy_trie_fiber_blocking(
        uint64_t const src_version, NibblesView const src,
        uint64_t const dest_version, NibblesView const dest,
        bool const blocked_by_write = true) override
    {
        if (src_version != root_version_) {
            root_ = read_node_blocking(
                aux_,
                aux_.get_root_offset_at_version(src_version),
                src_version);
            root_version_ = src_version;
        }
        Node &src_root = *root_;
        Node::UniquePtr dest_root{};
        if (src_version == dest_version) {
            dest_root = std::move(root_);
        }
        else if (auto const root_offset =
                     aux_.get_root_offset_at_version(dest_version);
                 root_offset != INVALID_OFFSET) {
            dest_root = read_node_blocking(aux_, root_offset, dest_version);
        }

        DbSyncObject sync;
        comms_.enqueue(FiberCopyTrieRequest{
            .sync = &sync,
            .new_root = &root_,
            .src_root = src_root,
            .src = src,
            .src_version = src_version,
            .dest_root = std::move(dest_root),
            .dest = dest,
            .dest_version = dest_version,
            .blocked_by_write = blocked_by_write});
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        root_version_ = dest_version;
    }

    virtual void update_finalized_block(uint64_t const block_id) override
    {
        aux_.set_latest_finalized_version(block_id);
    }

    virtual void update_verified_block(uint64_t const block_id) override
    {
        MONAD_ASSERT(block_id <= aux_.db_history_max_version());
        aux_.set_latest_verified_version(block_id);
    }

    virtual uint64_t get_latest_finalized_block_id() const override
    {
        return aux_.get_latest_finalized_version();
    }

    virtual uint64_t get_latest_verified_block_id() const override
    {
        return aux_.get_latest_verified_version();
    }
};

Db::Db(StateMachine &machine)
    : impl_{std::make_unique<InMemory>(machine)}
{
}

Db::Db(StateMachine &machine, OnDiskDbConfig const &config)
    : impl_{std::make_unique<RWOnDisk>(config, machine)}
{
    MONAD_DEBUG_ASSERT(impl_->aux().is_on_disk());
}

Db::Db(AsyncIOContext &io_ctx)
    : impl_{std::make_unique<ROOnDisk>(io_ctx)}
{
}

Db::~Db() = default;

Result<NodeCursor>
Db::find(NodeCursor root, NibblesView const key, uint64_t const block_id) const
{
    MONAD_ASSERT(impl_);
    auto const [it, result] = impl_->find_fiber_blocking(root, key, block_id);
    if (result != find_result::success) {
        return DbError::key_not_found;
    }
    MONAD_DEBUG_ASSERT(it.node != nullptr);
    MONAD_DEBUG_ASSERT(it.node->has_value());
    return it;
}

NodeCursor Db::load_root_for_version(uint64_t const block_id) const
{
    MONAD_ASSERT(impl_);
    return impl_->load_root_for_version(block_id);
}

Result<NodeCursor>
Db::find(NibblesView const key, uint64_t const block_id) const
{
    MONAD_ASSERT(impl_);
    auto cursor = impl_->load_root_for_version(block_id);
    return find(cursor, key, block_id);
}

Result<byte_string_view>
Db::get(NibblesView const key, uint64_t const block_id) const
{
    auto res = find(key, block_id);
    if (!res.has_value() || !res.value().node->has_value()) {
        return DbError::key_not_found;
    }
    return res.value().node->value();
}

Result<byte_string_view> Db::get_data(
    NodeCursor root, NibblesView const key, uint64_t const block_id) const
{
    auto res = find(root, key, block_id);
    if (!res.has_value()) {
        return DbError::key_not_found;
    }
    MONAD_DEBUG_ASSERT(res.value().node != nullptr);
    return res.value().node->data();
}

Result<byte_string_view>
Db::get_data(NibblesView const key, uint64_t const block_id) const
{
    auto res = find(key, block_id);
    if (!res.has_value()) {
        return DbError::key_not_found;
    }
    MONAD_DEBUG_ASSERT(res.value().node != nullptr);
    return res.value().node->data();
}

void Db::upsert(
    UpdateList list, uint64_t const block_id, bool const enable_compaction,
    bool const can_write_to_fast, bool const write_root)
{
    MONAD_ASSERT(impl_);
    impl_->upsert_fiber_blocking(
        std::move(list),
        block_id,
        enable_compaction,
        can_write_to_fast,
        write_root);
}

void Db::copy_trie(
    uint64_t const src_version, NibblesView const src,
    uint64_t const dest_version, NibblesView const dest,
    bool const blocked_by_write)
{
    MONAD_ASSERT(impl_);
    impl_->copy_trie_fiber_blocking(
        src_version, src, dest_version, dest, blocked_by_write);
}

void Db::move_trie_version_forward(uint64_t const src, uint64_t const dest)
{
    MONAD_ASSERT(impl_);
    impl_->move_trie_version_fiber_blocking(src, dest);
    return;
}

bool Db::traverse(
    NodeCursor const cursor, TraverseMachine &machine, uint64_t const block_id,
    size_t const concurrency_limit)
{
    MONAD_ASSERT(impl_);
    MONAD_ASSERT(cursor.is_valid());
    return impl_->traverse_fiber_blocking(
        *cursor.node, machine, block_id, concurrency_limit);
}

bool Db::traverse_blocking(
    NodeCursor const cursor, TraverseMachine &machine, uint64_t const block_id)
{
    MONAD_ASSERT(impl_);
    MONAD_ASSERT(cursor.is_valid());
    return preorder_traverse_blocking(
        impl_->aux(), *cursor.node, machine, block_id);
}

NodeCursor Db::root() const noexcept
{
    MONAD_ASSERT(impl_);
    return impl_->root() ? NodeCursor{*impl_->root()} : NodeCursor{};
}

void Db::update_finalized_block(uint64_t const block_id)
{
    MONAD_ASSERT(impl_);
    impl_->update_finalized_block(block_id);
}

void Db::update_verified_block(uint64_t const block_id)
{
    MONAD_ASSERT(impl_);
    impl_->update_verified_block(block_id);
}

void Db::update_voted_metadata(uint64_t const block_id, uint64_t const round)
{
    MONAD_ASSERT(impl_);
    impl_->aux().set_latest_voted(block_id, round);
}

uint64_t Db::get_latest_finalized_block_id() const
{
    MONAD_ASSERT(impl_);
    return impl_->get_latest_finalized_block_id();
}

uint64_t Db::get_latest_verified_block_id() const
{
    MONAD_ASSERT(impl_);
    return impl_->get_latest_verified_block_id();
}

uint64_t Db::get_latest_voted_round() const
{
    MONAD_ASSERT(impl_);
    return impl_->aux().get_latest_voted_round();
}

uint64_t Db::get_latest_voted_block_id() const
{
    MONAD_ASSERT(impl_);
    return impl_->aux().get_latest_voted_version();
}

uint64_t Db::get_latest_block_id() const
{
    MONAD_ASSERT(impl_);
    if (impl_->aux().is_on_disk()) {
        return impl_->aux().db_history_max_version();
    }
    else {
        return impl_->root() ? 0 : INVALID_BLOCK_ID;
    }
}

uint64_t Db::get_earliest_block_id() const
{
    MONAD_ASSERT(impl_);
    if (impl_->aux().is_on_disk()) {
        return impl_->aux().db_history_min_valid_version();
    }
    else {
        return impl_->root() ? 0 : INVALID_BLOCK_ID;
    }
}

size_t Db::prefetch()
{
    MONAD_ASSERT(impl_);
    if (get_latest_block_id() == INVALID_BLOCK_ID) {
        return 0;
    }
    return impl_->prefetch_fiber_blocking();
}

size_t Db::poll(bool const blocking, size_t const count)
{
    MONAD_ASSERT(impl_);
    return impl_->poll(blocking, count);
}

bool Db::is_on_disk() const
{
    MONAD_ASSERT(impl_);
    return impl_->aux().is_on_disk();
}

bool Db::is_read_only() const
{
    MONAD_ASSERT(impl_);
    return is_on_disk() && impl_->aux().io->is_read_only();
}

uint64_t Db::get_history_length() const
{
    return is_on_disk() ? impl_->aux().version_history_length() : 1;
}

AsyncContext::AsyncContext(Db &db, size_t lru_size)
    : aux(db.impl_->aux())
    , root_cache(lru_size, chunk_offset_t::invalid_value())
{
}

AsyncContextUniquePtr async_context_create(Db &db)
{
    return std::make_unique<AsyncContext>(db);
}

namespace detail
{

    // Reads root nodes from on disk, and supports other inflight async requests
    // from the same sender.
    template <typename T>
    struct load_root_receiver_t
    {
        static constexpr bool lifetime_managed_internally = true;

        chunk_offset_t offset;
        DbGetSender<T> *sender;
        async::erased_connected_operation *const io_state;
        chunk_offset_t rd_offset{0, 0};
        unsigned bytes_to_read;
        uint16_t buffer_off;

        constexpr load_root_receiver_t(
            chunk_offset_t offset_, DbGetSender<T> *sender_,
            async::erased_connected_operation *io_state_)
            : offset(offset_)
            , sender(sender_)
            , io_state(io_state_)
        {
            auto const num_pages_to_load_node =
                node_disk_pages_spare_15{offset_}.to_pages();
            bytes_to_read =
                static_cast<unsigned>(num_pages_to_load_node << DISK_PAGE_BITS);
            rd_offset = offset_;
            auto const new_offset =
                round_down_align<DISK_PAGE_BITS>(offset_.offset);
            MONAD_DEBUG_ASSERT(new_offset <= chunk_offset_t::max_offset);
            rd_offset.offset = new_offset & chunk_offset_t::max_offset;
            buffer_off = uint16_t(offset_.offset - rd_offset.offset);
        }

        template <class ResultType>
        void set_value(
            monad::async::erased_connected_operation *, ResultType buffer_)
        {
            MONAD_ASSERT(buffer_);

            auto &inflights = sender->context.inflight_roots;
            auto it = inflights.find(sender->block_id);
            auto pendings = std::move(it->second);
            inflights.erase(it);
            std::shared_ptr<Node> root{};
            bool const block_alive_after_read =
                sender->context.aux.version_is_valid_ondisk(sender->block_id);
            if (block_alive_after_read) {
                sender->root = detail::deserialize_node_from_receiver_result(
                    std::move(buffer_), buffer_off, io_state);
                root = sender->root;
                sender->res_root = {
                    NodeCursor{*sender->root.get()}, find_result::success};
                {
                    AsyncContext::TrieRootCache::ConstAccessor acc;
                    MONAD_ASSERT(
                        sender->context.root_cache.find(acc, offset) == false);
                }
                sender->context.root_cache.insert(offset, sender->root);
            }
            else {
                sender->res_root = {
                    NodeCursor{}, find_result::version_no_longer_exist};
            }

            for (auto &invoc : pendings) {
                // Calling invoc() may invoke user code which deletes `sender`.
                // It is no longer safe to rely on the `sender` lifetime
                invoc(root);
            }
        }
    };

    // Processes results from find_request_sender, proxying the result back to
    // the DbGetSender.
    template <return_type T>
    struct find_request_receiver_t
    {
        find_result_type<T> &get_result;
        async::erased_connected_operation *const io_state;
        uint64_t const version;
        UpdateAux<> &aux;

        enum : bool
        {
            lifetime_managed_internally = true
        };

        void set_value(
            async::erased_connected_operation *const this_io_state,
            find_request_sender<T>::result_type res)
        {
            if (!res) {
                io_state->completed(
                    async::result<void>(std::move(res).as_failure()));
                delete this_io_state;
                return;
            }
            get_result = aux.version_is_valid_ondisk(version)
                             ? std::move(res).assume_value()
                             : find_result_type<T>{
                                   T{}, find_result::version_no_longer_exist};

            io_state->completed(async::success());
            delete this_io_state;
        }
    };

    template <return_type T>
    async::result<void> DbGetSender<T>::operator()(
        async::erased_connected_operation *io_state) noexcept
    {
        switch (op_type) {
        case op_t::op_get1:
        case op_t::op_get_data1:
        case op_t::op_get_node1: {
            chunk_offset_t const offset =
                context.aux.get_root_offset_at_version(block_id);
            AsyncContext::TrieRootCache::ConstAccessor acc;
            if (context.root_cache.find(acc, offset)) {
                // found in LRU - no IO necessary
                root = acc->second->val;
                res_root = {NodeCursor{*root.get()}, find_result::success};
                io_state->completed(async::success());
                return async::success();
            }
            if (offset == INVALID_OFFSET) {
                // root is no longer valid
                res_root = {NodeCursor{}, find_result::version_no_longer_exist};
                io_state->completed(async::success());
                return async::success();
            }

            auto cont = [this, io_state](std::shared_ptr<Node> root_) {
                if (!root_) {
                    res_root = {
                        NodeCursor{}, find_result::version_no_longer_exist};
                }
                else {
                    root = root_;
                    res_root = {NodeCursor{*root.get()}, find_result::success};
                }
                io_state->completed(async::success());
            };
            auto &inflights = context.inflight_roots;
            if (auto it = inflights.find(block_id); it != inflights.end()) {
                it->second.emplace_back(cont);
            }
            else {
                inflights[block_id].emplace_back(cont);
                async_read(
                    context.aux, load_root_receiver_t{offset, this, io_state});
            }
            return async::success();
        }
        case op_t::op_get2:
        case op_t::op_get_data2:
        case op_t::op_get_node2: {
            // verify version is valid in db history before doing anything
            if (!context.aux.version_is_valid_ondisk(block_id)) {
                get_result = {T{}, find_result::version_no_longer_exist};
                io_state->completed(async::success());
                return async::success();
            }

            auto *state = new auto(async::connect(
                find_request_sender<T>(
                    context.aux,
                    context.inflight_nodes,
                    cur,
                    nv,
                    op_type == op_t::op_get2,
                    cached_levels),
                find_request_receiver_t<T>{
                    get_result, io_state, block_id, context.aux}));
            state->initiate();
            return async::success();
        }
        }
        abort();
    }

    template <return_type T>
    DbGetSender<T>::result_type DbGetSender<T>::completed(
        async::erased_connected_operation *, async::result<void> r) noexcept
    {
        BOOST_OUTCOME_TRY(std::move(r));
        auto const res_msg = (op_type == op_get1 || op_type == op_get_data1 ||
                              op_type == op_get_node1)
                                 ? res_root.second
                                 : get_result.second;
        MONAD_ASSERT(res_msg != find_result::unknown);
        if (res_msg != find_result::success) {
            return DbError::key_not_found;
        }
        switch (op_type) {
        case op_t::op_get1:
        case op_t::op_get_data1:
        case op_t::op_get_node1: {
            // Restart this op
            cur = std::move(res_root.first);
            switch (op_type) {
            case op_t::op_get1:
                op_type = op_get2;
                break;
            case op_t::op_get_data1:
                op_type = op_get_data2;
                break;
            case op_t::op_get_node1:
                op_type = op_get_node2;
                break;
            default:
                MONAD_ASSERT(false);
            }
            return async::sender_errc::operation_must_be_reinitiated;
        }
        case op_t::op_get2:
        case op_t::op_get_data2:
        case op_t::op_get_node2:
            return {std::move(get_result.first)};
        }
        abort();
    }

    template struct DbGetSender<byte_string>;
    template struct DbGetSender<Node::UniquePtr>;
}

MONAD_MPT_NAMESPACE_END
