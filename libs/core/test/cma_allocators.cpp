#include <bit>
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#include <monad/mem/cma/cma_bump_alloc.h>

TEST(cma_malloc, basic)
{
    constexpr size_t array_size = 256;
    alignas(int) std::byte buf[sizeof(int) * array_size];
    monad_memblk_t const stack_memblk = {.ptr = buf, .size = sizeof buf};
    monad_memblk_t alloc_desc;
    monad_cma_bump_alloc block_allocator;
    monad_allocator_t *alloc;

    monad_cma_bump_alloc_init(&block_allocator, stack_memblk, &alloc);

    // Allocate all the memory
    int rc = monad_cma_calloc(
        alloc, array_size, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);

    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size, alloc_desc.size);
    ASSERT_EQ(0, std::bit_cast<std::uintptr_t>(alloc_desc.ptr) % alignof(int));

    // Check that we get ENOMEM now that the memory is gone
    monad_memblk_t other_blk;
    rc = monad_cma_alloc(alloc, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(ENOMEM, rc);
    ASSERT_EQ(nullptr, other_blk.ptr);
    ASSERT_EQ(0, other_blk.size);

    // Use a shrinking reallocarray to get some of the memory back
    rc = monad_cma_reallocarray(
        alloc, array_size / 2, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size / 2, alloc_desc.size);

    // Use a growing realloc to go back to the way things were
    rc = monad_cma_reallocarray(
        alloc, array_size, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size, alloc_desc.size);

    // Check that we get ENOMEM again
    rc = monad_cma_alloc(alloc, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(ENOMEM, rc);
    ASSERT_EQ(nullptr, other_blk.ptr);
    ASSERT_EQ(0, other_blk.size);

    // Give the memory back via de-allocation
    monad_cma_dealloc(alloc, alloc_desc);

    // Check that we can get memory again after deallocating, and also that
    // realloc on nullptr works correctly
    memset(&alloc_desc, 0, sizeof alloc_desc);
    rc = monad_cma_reallocarray(
        alloc, array_size / 2, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size / 2, alloc_desc.size);

    // Take the rest of the memory in another allocation. For the rest of these
    // tests, `alloc_desc` holds the first allocation, and `other_blk` holds
    // the second
    rc = monad_cma_calloc(
        alloc, array_size / 2, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(
        std::bit_cast<std::byte const *>(stack_memblk.ptr) +
            stack_memblk.size / 2,
        other_blk.ptr);
    ASSERT_EQ(stack_memblk.size / 2, other_blk.size);

    // Check that we cannot grow the first allocation, because it would need
    // to realloc, and there's no space to do it. Also check that alloc_desc
    // is not changed by this failure
    rc = monad_cma_reallocarray(
        alloc, array_size, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(ENOMEM, rc);
    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size / 2, alloc_desc.size);

    // We can shrink the allocation, as before; it changes the size of the
    // block to increase compatibility with other allocators (which actually
    // do it) but it does not really free this memory
    rc = monad_cma_reallocarray(
        alloc, array_size / 4, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(stack_memblk.ptr, alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size / 4, alloc_desc.size);

    // We can also give the memory back, but it does not really free it
    monad_cma_dealloc(alloc, alloc_desc);
    rc = monad_cma_reallocarray(
        alloc, array_size / 2 + 1, sizeof(int), alignof(int), &other_blk);
    ASSERT_EQ(ENOMEM, rc);
    ASSERT_EQ(
        std::bit_cast<std::byte const *>(stack_memblk.ptr) +
            stack_memblk.size / 2,
        other_blk.ptr);
    ASSERT_EQ(stack_memblk.size / 2, other_blk.size);

    // Free the second block. This will actually free it since it was the last
    // one, but because of the other of freeing and the lack of history, we
    // can only get array_size / 2 bytes now
    monad_cma_dealloc(alloc, other_blk);
    rc = monad_cma_calloc(
        alloc, array_size / 2 + 1, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(ENOMEM, rc);

    rc = monad_cma_calloc(
        alloc, array_size / 2, sizeof(int), alignof(int), &alloc_desc);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(
        std::bit_cast<std::byte const *>(stack_memblk.ptr) +
            stack_memblk.size / 2,
        alloc_desc.ptr);
    ASSERT_EQ(stack_memblk.size / 2, alloc_desc.size);
}
