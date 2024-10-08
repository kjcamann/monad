#include <monad/fiber/priority_pool.hpp>

#include <monad/core/assert.h>
#include <monad/fiber/config.hpp>
#include <monad/fiber/priority_algorithm.hpp>
#include <monad/fiber/priority_properties.hpp>
#include <monad/fiber/priority_task.hpp>

#include <boost/fiber/channel_op_status.hpp>
#include <boost/fiber/fiber.hpp>
#include <boost/fiber/mutex.hpp>
#include <boost/fiber/operations.hpp>
#include <boost/fiber/properties.hpp>
#include <boost/fiber/protected_fixedsize_stack.hpp>

#include <cstdio>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <monad/core/thread.h>

MONAD_FIBER_NAMESPACE_BEGIN

PriorityPool::PriorityPool(unsigned const n_threads, unsigned const n_fibers)
{
    MONAD_ASSERT(n_threads);
    MONAD_ASSERT(n_fibers);

    threads_.reserve(n_threads);
    for (unsigned i = n_threads - 1; i > 0; --i) {
        auto thread = std::thread([this, i] {
            char name[16];
            std::snprintf(name, 16, "worker %u", i);
            monad_thread_set_name(name);
            boost::fibers::use_scheduling_algorithm<PriorityAlgorithm>(queue_);
            std::unique_lock<boost::fibers::mutex> lock{mutex_};
            cv_.wait(lock, [this] { return done_; });
        });
        threads_.push_back(std::move(thread));
    }

    fibers_.reserve(n_fibers);
    auto thread = std::thread([this, n_fibers] {
        monad_thread_set_name("worker 0");
        boost::fibers::use_scheduling_algorithm<PriorityAlgorithm>(queue_);
        for (unsigned i = 0; i < n_fibers; ++i) {
            auto *const properties = new PriorityProperties{nullptr};
            boost::fibers::fiber fiber{
                static_cast<boost::fibers::fiber_properties *>(properties),
                std::allocator_arg,
                boost::fibers::protected_fixedsize_stack{8 * 1024 * 1024},
                [this, properties] {
                    PriorityTask task;
                    while (channel_.pop(task) ==
                           boost::fibers::channel_op_status::success) {
                        properties->set_priority(task.priority);
                        boost::this_fiber::yield();
                        task.task();
                        properties->set_priority(0);
                    }
                }};
            fibers_.push_back(std::move(fiber));
        }
        start_.set_value();
        std::unique_lock<boost::fibers::mutex> lock{mutex_};
        cv_.wait(lock, [this] { return done_; });
    });
    threads_.push_back(std::move(thread));
}

PriorityPool::~PriorityPool()
{
    channel_.close();

    start_.get_future().wait();

    while (fibers_.size()) {
        auto &fiber = fibers_.back();
        fiber.join();
        fibers_.pop_back();
    }

    {
        std::unique_lock<boost::fibers::mutex> const lock{mutex_};
        done_ = true;
    }

    cv_.notify_all();

    while (threads_.size()) {
        auto &thread = threads_.back();
        thread.join();
        threads_.pop_back();
    }
}

MONAD_FIBER_NAMESPACE_END
