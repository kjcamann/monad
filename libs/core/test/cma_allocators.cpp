#include <bit>
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#include <monad/mem/cma/cma_bump_alloc.h>

TEST(cma_malloc, basic)
{
    constexpr std::size_t array_size = 256;
    alignas(int) std::byte buf[sizeof(int) * array_size];
    monad_memblk_t const stack_memblk = {.ptr = buf, .size = sizeof buf};
    monad_memblk_t alloc_desc;
    monad_cma_bump_alloc allocator;

    monad_cma_bump_alloc_init(&allocator, stack_memblk);
    int rc = monad_cma_calloc(
        (monad_allocator_t *)&allocator,
        array_size,
        sizeof(int),
        alignof(int),
        &alloc_desc);
    ASSERT_EQ(0, rc);

    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size, alloc_desc.size);
    ASSERT_EQ(0, std::bit_cast<std::uintptr_t>(alloc_desc.ptr) % alignof(int));

    monad_memblk_t other_blk;
    rc = monad_cma_alloc(
        (monad_allocator_t *)&allocator, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(ENOMEM, rc);
    ASSERT_EQ(nullptr, other_blk.ptr);
    ASSERT_EQ(0, other_blk.size);

    monad_cma_dealloc((monad_allocator_t *)&allocator, alloc_desc);
    rc = monad_cma_alloc(
        (monad_allocator_t *)&allocator, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(stack_memblk.ptr, other_blk.ptr);
    ASSERT_EQ(sizeof(int), other_blk.size);
}
