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
        UpdateList &&, uint64_t, bool enable_compaction,
        bool can_write_to_fast) = 0;

    virtual find_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key, uint64_t version) = 0;
    virtual size_t prefetch_fiber_blocking() = 0;
    virtual NodeCursor load_root_for_version(uint64_t version) = 0;
    virtual size_t poll(bool blocking, size_t count) = 0;
    virtual bool
    traverse_fiber_blocking(Node &, TraverseMachine &, uint64_t version) = 0;
    virtual void
    move_trie_version_fiber_blocking(uint64_t src, uint64_t dest) = 0;
};

struct Db::ROOnDisk final : public Db::Impl
{
    async::storage_pool pool_;
    io::Ring ring_;
    io::Buffers rwbuf_;
    async::AsyncIO io_;
    UpdateAux<> aux_;
    chunk_offset_t last_loaded_root_offset_;
    Node::UniquePtr root_;

    explicit ROOnDisk(ReadOnlyOnDiskDbConfig const &options)
        : pool_{[&] -> async::storage_pool {
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
        , ring_{monad::io::RingConfig{
              options.uring_entries, false, options.sq_thread_cpu}}
        , rwbuf_{io::make_buffers_for_read_only(
              ring_, options.rd_buffers,
              async::AsyncIO::MONAD_IO_BUFFERS_READ_SIZE)}
        , io_{pool_, rwbuf_}
        , aux_{&io_}
        , last_loaded_root_offset_{aux_.get_latest_root_offset()}
        , root_{
              last_loaded_root_offset_ == INVALID_OFFSET
                  ? Node::UniquePtr{}
                  : read_node_blocking(pool_, last_loaded_root_offset_)}
    {
        io_.set_capture_io_latencies(options.capture_io_latencies);
        io_.set_concurrent_read_io_limit(options.concurrent_read_io_limit);
        io_.set_eager_completions(options.eager_completions);
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
    upsert_fiber_blocking(UpdateList &&, uint64_t, bool, bool) override
    {
        MONAD_ASSERT(false);
    }

    virtual find_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key,
        uint64_t const version) override
    {
        if (!root.is_valid()) {
            return {NodeCursor{}, find_result::unknown};
        }
        // db we last loaded does not contain the version we want to find
        if (!aux().version_is_valid_ondisk(version)) {
            return {NodeCursor{}, find_result::version_no_longer_exist};
        }
        try {
            auto const res = find_blocking(aux(), root, key);
            // verify version still valid in history after success
            return aux().version_is_valid_ondisk(version)
                       ? res
                       : find_result_type{
                             NodeCursor{},
                             find_result::version_no_longer_exist};
        }
        catch (std::exception const &e) { // exception implies UB
            return {NodeCursor{}, find_result::version_no_longer_exist};
        }
    }

    virtual void move_trie_version_fiber_blocking(uint64_t, uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual size_t prefetch_fiber_blocking() override
    {
        MONAD_ASSERT(false);
    }

    virtual size_t poll(bool const blocking, size_t const count) override
    {
        return blocking ? aux_.io->poll_blocking(count)
                        : aux_.io->poll_nonblocking(count);
    }

    virtual bool traverse_fiber_blocking(
        Node &node, TraverseMachine &machine, uint64_t const version) override
    {
        return preorder_traverse(
            aux(), node, machine, [this, version]() -> bool {
                return aux().version_is_valid_ondisk(version);
            });
    }

    virtual NodeCursor load_root_for_version(uint64_t const version) override
    {
        auto const root_offset = aux().get_root_offset_at_version(version);
        if (root_offset == INVALID_OFFSET) {
            return NodeCursor{};
        }
        if (last_loaded_root_offset_ != root_offset) {
            last_loaded_root_offset_ = root_offset;
            root_ = read_node_blocking(pool_, root_offset);
        }
        return root_ ? NodeCursor{*root_} : NodeCursor{};
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
        UpdateList &&list, uint64_t block_id, bool, bool) override
    {
        root_ = aux_.do_update(
            std::move(root_), machine_, std::move(list), block_id, false);
    }

    virtual find_result_type find_fiber_blocking(
        NodeCursor const &root, NibblesView const &key, uint64_t = 0) override
    {
        return find_blocking(aux(), root, key);
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
        Node &node, TraverseMachine &machine, uint64_t) override
    {
        return preorder_traverse(aux(), node, machine, [] { return true; });
    }

    virtual void move_trie_version_fiber_blocking(uint64_t, uint64_t) override
    {
        MONAD_ASSERT(false);
    }

    virtual NodeCursor load_root_for_version(uint64_t) override
    {
        return root() ? NodeCursor{*root()} : NodeCursor{};
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
        FiberLoadRootVersionRequest>;

    ::moodycamel::ConcurrentQueue<Comms> comms_;

    std::mutex lock_;
    std::condition_variable cond_;

    struct TrieDbWorker
    {
        RWOnDisk *parent;
        UpdateAuxImpl &aux;

        async::storage_pool pool;
        io::Ring ring1, ring2;
        io::Buffers rwbuf;
        async::AsyncIO io;
        bool const compaction;
        std::atomic<bool> sleeping{false}, done{false};

        TrieDbWorker(
            RWOnDisk *parent, UpdateAuxImpl &aux, OnDiskDbConfig const &options)
            : parent(parent)
            , aux(aux)
            , pool{[&] -> async::storage_pool {
                if (options.dbname_paths.empty()) {
                    return async::storage_pool{
                        async::use_anonymous_inode_tag{}};
                }
                // initialize db file on disk
                for (auto const &dbname_path : options.dbname_paths) {
                    if (!std::filesystem::exists(dbname_path)) {
                        int const fd = ::open(
                            dbname_path.c_str(),
                            O_CREAT | O_RDWR | O_CLOEXEC,
                            0600);
                        if (-1 == fd) {
                            throw std::system_error(
                                errno, std::system_category());
                        }
                        auto unfd = monad::make_scope_exit(
                            [fd]() noexcept { ::close(fd); });
                        if (-1 ==
                            ::ftruncate(
                                fd,
                                options.file_size_db * 1024 * 1024 * 1024 +
                                    24576)) {
                            throw std::system_error(
                                errno, std::system_category());
                        }
                    }
                }
                return async::storage_pool{
                    options.dbname_paths,
                    options.append ? async::storage_pool::mode::open_existing
                                   : async::storage_pool::mode::truncate};
            }()}
            , ring1{{options.uring_entries, options.enable_io_polling, options.sq_thread_cpu}}
            , ring2{options.wr_buffers}
            , rwbuf{io::make_buffers_for_segregated_read_write(
                  ring1, ring2, options.rd_buffers, options.wr_buffers,
                  async::AsyncIO::MONAD_IO_BUFFERS_READ_SIZE,
                  async::AsyncIO::MONAD_IO_BUFFERS_WRITE_SIZE)}
            , io{pool, rwbuf}
            , compaction{options.compaction}
        {
            io.set_capture_io_latencies(options.capture_io_latencies);
            io.set_concurrent_read_io_limit(options.concurrent_read_io_limit);
            io.set_eager_completions(options.eager_completions);
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
                            req->can_write_to_fast);
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
                            *req->is_valid = preorder_traverse(
                                aux, req->root, req->machine, [&] {
                                    return true;
                                });
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
                        auto root = (root_offset != INVALID_OFFSET)
                                        ? Node::UniquePtr{read_node_blocking(
                                            pool, root_offset)}
                                        : Node::UniquePtr{};
                        req->sync->release();
                    }
                    did_nothing = false;
                }
                io.poll_nonblocking(1);
                if (did_nothing && io.io_in_flight() > 0) {
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
    Node::UniquePtr reader_root_; // lifetime for reads on a different block

    RWOnDisk(OnDiskDbConfig const &options, StateMachine &machine)
        : worker_thread_([&] {
            {
                std::unique_lock const g(lock_);
                worker_ = std::make_unique<TrieDbWorker>(this, aux_, options);
                // This bit is unfortunately nasty, but we have to initialise
                // aux_ from this thread
                aux_.~UpdateAux<>();
                new (&aux_)
                    UpdateAux<>{&worker_->io, options.fixed_history_length};
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
                             worker_->pool, aux_.get_latest_root_offset())
                       : Node::UniquePtr{};
        }())
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
    virtual find_result_type find_fiber_blocking(
        NodeCursor const &start, NibblesView const &key, uint64_t = 0) override
    {
        DbSyncObject sync;
        find_result_type result;

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
        bool const enable_compaction, bool const can_write_to_fast) override
    {
        DbSyncObject sync;
        comms_.enqueue(FiberUpsertRequest{
            .sync = &sync,
            .new_root = &root_,
            .prev_root = std::move(root_),
            .sm = machine_,
            .updates = std::move(updates),
            .version = version,
            .enable_compaction = enable_compaction,
            .can_write_to_fast = can_write_to_fast});
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
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
        Node &node, TraverseMachine &machine, uint64_t const version) override
    {
        DbSyncObject sync;
        bool is_valid;

        comms_.enqueue(FiberTraverseRequest{
            .sync = &sync,
            .is_valid = &is_valid,
            .root = node,
            .machine = machine,
            .version = version});
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
        if (MONAD_LIKELY(version == aux().db_history_max_version())) {
            return root() ? NodeCursor{*root()} : NodeCursor{};
        }

        DbSyncObject sync;
        comms_.enqueue(FiberLoadRootVersionRequest{
            .sync = &sync, .root = &reader_root_, .version = version});
        // promise is racily emptied after this point
        if (worker_->sleeping.load(std::memory_order_acquire)) {
            std::unique_lock const g(lock_);
            cond_.notify_one();
        }
        sync.acquire();
        return reader_root_ ? NodeCursor{*reader_root_} : NodeCursor{};
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

Db::Db(ReadOnlyOnDiskDbConfig const &config)
    : impl_{std::make_unique<ROOnDisk>(config)}
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
    bool const can_write_to_fast)
{
    MONAD_ASSERT(impl_);
    impl_->upsert_fiber_blocking(
        std::move(list), block_id, enable_compaction, can_write_to_fast);
}

void Db::move_trie_version_forward(uint64_t const src, uint64_t const dest)
{
    MONAD_ASSERT(impl_);
    impl_->move_trie_version_fiber_blocking(src, dest);
    return;
}

bool Db::traverse(
    NodeCursor const cursor, TraverseMachine &machine, uint64_t const block_id)
{
    MONAD_ASSERT(impl_);
    MONAD_ASSERT(cursor.is_valid());
    return impl_->traverse_fiber_blocking(*cursor.node, machine, block_id);
}

bool Db::traverse_blocking(
    NodeCursor const cursor, TraverseMachine &machine, uint64_t const block_id)
{
    MONAD_ASSERT(impl_);
    MONAD_ASSERT(cursor.is_valid());
    return preorder_traverse_blocking(
        impl_->aux(), *cursor.node, machine, [this, block_id] {
            return impl_->aux().is_on_disk()
                       ? impl_->aux().version_is_valid_ondisk(block_id)
                       : true;
        });
}

NodeCursor Db::root() const noexcept
{
    MONAD_ASSERT(impl_);
    return impl_->root() ? NodeCursor{*impl_->root()} : NodeCursor{};
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
    , root_cache(lru_size)
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

        DbGetSender<T> *sender;
        async::erased_connected_operation *const io_state;
        chunk_offset_t rd_offset{0, 0};
        unsigned bytes_to_read;
        uint16_t buffer_off;

        constexpr load_root_receiver_t(
            chunk_offset_t offset_, DbGetSender<T> *sender_,
            async::erased_connected_operation *io_state_)
            : sender(sender_)
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
                try {
                    sender->root =
                        detail::deserialize_node_from_receiver_result(
                            std::move(buffer_), buffer_off, io_state);
                    root = sender->root;
                    sender->res_root = {
                        NodeCursor{*sender->root.get()}, find_result::success};
                    {
                        AsyncContext::TrieRootCache::ConstAccessor acc;
                        MONAD_ASSERT(
                            sender->context.root_cache.find(
                                acc, sender->block_id) == false);
                    }
                    sender->context.root_cache.insert(
                        sender->block_id, sender->root);
                }
                catch (std::exception const &) {
                    sender->res_root = {
                        NodeCursor{}, find_result::version_no_longer_exist};
                }
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
    struct find_request_receiver_t
    {
        find_bytes_result_type &res_bytes;
        async::erased_connected_operation *const io_state;
        uint64_t const version;
        UpdateAux<> &aux;

        enum : bool
        {
            lifetime_managed_internally = true
        };

        void set_value(
            async::erased_connected_operation *const this_io_state,
            find_request_sender::result_type res)
        {
            if (!res) {
                io_state->completed(
                    async::result<void>(std::move(res).as_failure()));
                return;
            }
            try {
                // verify version still valid in history after success
                res_bytes = aux.version_is_valid_ondisk(version)
                                ? std::move(res).assume_value()
                                : find_bytes_result_type{
                                      byte_string{},
                                      find_result::version_no_longer_exist};
            }
            catch (std::exception const &e) { // exception implies UB
                res_bytes = {
                    byte_string{}, find_result::version_no_longer_exist};
            }
            io_state->completed(async::success());
            delete this_io_state;
        }
    };

    template <class T>
    async::result<void> DbGetSender<T>::operator()(
        async::erased_connected_operation *io_state) noexcept
    {
        switch (op_type) {
        case op_t::op_get1:
        case op_t::op_get_data1: {
            AsyncContext::TrieRootCache::ConstAccessor acc;
            if (context.root_cache.find(acc, block_id)) {
                // found in LRU - no IO necessary
                root = acc->second->val;
                res_root = {NodeCursor{*root.get()}, find_result::success};
                io_state->completed(async::success());
                return async::success();
            }

            chunk_offset_t const offset =
                context.aux.get_root_offset_at_version(block_id);
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
        case op_t::op_get_data2: {
            // verify version is valid in db history before doing anything
            if (!context.aux.version_is_valid_ondisk(block_id)) {
                res_bytes = {
                    byte_string{}, find_result::version_no_longer_exist};
                io_state->completed(async::success());
                return async::success();
            }

            auto *state = new auto(async::connect(
                find_request_sender(
                    context.aux,
                    context.inflight_nodes,
                    cur,
                    nv,
                    op_type == op_t::op_get2,
                    cached_levels),
                find_request_receiver_t{
                    res_bytes, io_state, block_id, context.aux}));
            state->initiate();
            return async::success();
        }
        }
        abort();
    }
    template struct DbGetSender<byte_string>;

    template <>
    DbGetSender<byte_string>::result_type DbGetSender<byte_string>::completed(
        async::erased_connected_operation *, async::result<void> r) noexcept
    {
        BOOST_OUTCOME_TRY(std::move(r));
        auto const res_msg = (op_type == op_get1 || op_type == op_get_data1)
                                 ? res_root.second
                                 : res_bytes.second;
        MONAD_ASSERT(res_msg != find_result::unknown);
        if (res_msg != find_result::success) {
            return DbError::key_not_found;
        }
        switch (op_type) {
        case op_t::op_get1:
        case op_t::op_get_data1: {
            // Restart this op
            cur = std::move(res_root.first);
            op_type =
                (op_type == op_t::op_get1) ? op_t::op_get2 : op_t::op_get_data2;
            return async::sender_errc::operation_must_be_reinitiated;
        }
        case op_t::op_get2:
        case op_t::op_get_data2:
            return res_bytes.first;
        }
        abort();
    }

}

MONAD_MPT_NAMESPACE_END
