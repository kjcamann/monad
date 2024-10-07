#include <errno.h>
#include <string.h>

#include <monad/core/likely.h>
#include <monad/mem/cma/cma_alloc.h>
#include <monad/mem/cma/cma_fallback.h>

static int fallback_alloc(
    struct monad_cma_fallback_alloc *ma, size_t size, size_t align,
    monad_memblk_t *blk)
{
    int rc;
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    rc = monad_cma_alloc(ma->primary, size, align, blk);
    if (MONAD_UNLIKELY(blk->ptr == nullptr)) {
        return monad_cma_alloc(ma->secondary, size, align, blk);
    }
    return rc;
}

static int cross_alloc_move(
    monad_allocator_t *from, monad_allocator_t *to, size_t size, size_t align,
    monad_memblk_t *old_blk)
{
    int rc;
    monad_memblk_t new_blk;

    rc = to->vtable->alloc(to, size, align, &new_blk);
    if (rc != 0) {
        return rc;
    }
    memcpy(
        new_blk.ptr, old_blk->ptr, size > old_blk->size ? size : old_blk->size);
    from->vtable->dealloc(from, *old_blk);
    *old_blk = new_blk;
    return 0;
}

static int fallback_realloc(
    struct monad_cma_fallback_alloc *ma, size_t size, size_t align,
    monad_memblk_t *blk)
{
    if (MONAD_UNLIKELY(blk == nullptr)) {
        return EFAULT;
    }
    // For the rationale here, see Alexandrescu's original implementation in
    // `fallback_allocator.d`
    if (blk->ptr == nullptr || ma->primary->vtable->owns(ma->primary, *blk)) {
        return ma->primary->vtable->realloc(ma->primary, size, align, blk) ||
               cross_alloc_move(ma->primary, ma->secondary, size, align, blk);
    }
    return ma->secondary->vtable->realloc(ma->secondary, size, align, blk) ||
           cross_alloc_move(ma->secondary, ma->primary, size, align, blk);
}

static void
fallback_dealloc(struct monad_cma_fallback_alloc *ma, monad_memblk_t blk)
{
    if (ma->primary->vtable->owns(ma->primary, blk) == MONAD_CMA_OWNS_TRUE) {
        return monad_cma_dealloc(ma->primary, blk);
    }
    return monad_cma_dealloc(ma->secondary, blk);
}

static bool
fallback_owns(struct monad_cma_fallback_alloc *ma, monad_memblk_t blk)
{
    return ma->primary->vtable->owns(ma->primary, blk) ||
           ma->secondary->vtable->owns(ma->secondary, blk);
}

static struct monad_allocator_ops g_fallback_alloc_owns_ops = {
    .alloc = (monad_cma_alloc_fn *)fallback_alloc,
    .realloc = (monad_cma_realloc_fn *)fallback_realloc,
    .dealloc = (monad_cma_dealloc_fn *)fallback_dealloc,
    .owns = (monad_cma_owns_fn *)fallback_owns};

static struct monad_allocator_ops g_fallback_alloc_no_owns_ops = {
    .alloc = (monad_cma_alloc_fn *)fallback_alloc,
    .realloc = (monad_cma_realloc_fn *)fallback_realloc,
    .dealloc = (monad_cma_dealloc_fn *)fallback_dealloc,
    .owns = nullptr};

int monad_cma_fallback_alloc_init(
    struct monad_cma_fallback_alloc *fallback, monad_allocator_t *primary,
    monad_allocator_t *secondary, monad_allocator_t **ma)
{
    if (MONAD_UNLIKELY(fallback == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(primary == secondary)) {
        return EINVAL;
    }
    fallback->primary = primary;
    if (fallback->primary == nullptr) {
        fallback->primary = monad_cma_get_default_allocator();
    }
    if (MONAD_UNLIKELY(fallback->primary->vtable->owns == nullptr)) {
        return ENOTSUP;
    }
    fallback->secondary = secondary;
    if (fallback->secondary == nullptr) {
        fallback->secondary = monad_cma_get_default_allocator();
    }
    // The fallback allocator cannot function unless the primary allocator
    // supports the "owns" operation. However, the fallback itself cannot
    // support "owns" unless both of its allocators support it.
    if (fallback->secondary->vtable->owns != nullptr) {
        fallback->self.vtable = &g_fallback_alloc_owns_ops;
    }
    else {
        fallback->self.vtable = &g_fallback_alloc_no_owns_ops;
    }
    if (ma != nullptr) {
        *ma = &fallback->self;
    }
    return 0;
}
