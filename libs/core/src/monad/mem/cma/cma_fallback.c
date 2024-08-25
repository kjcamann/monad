#include <errno.h>

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
    .dealloc = (monad_cma_dealloc_fn *)fallback_dealloc,
    .owns = (monad_cma_owns_fn *)fallback_owns};

static struct monad_allocator_ops g_fallback_alloc_no_owns_ops = {
    .alloc = (monad_cma_alloc_fn *)fallback_alloc,
    .dealloc = (monad_cma_dealloc_fn *)fallback_dealloc,
    .owns = nullptr};

int monad_cma_fallback_alloc_init(
    struct monad_cma_fallback_alloc *ma, monad_allocator_t *primary,
    monad_allocator_t *secondary)
{
    if (MONAD_UNLIKELY(ma == nullptr)) {
        return EFAULT;
    }
    if (MONAD_UNLIKELY(primary == secondary)) {
        return EINVAL;
    }
    ma->primary = primary;
    if (ma->primary == nullptr) {
        ma->primary = monad_cma_get_default_allocator();
    }
    if (MONAD_UNLIKELY(ma->primary->vtable->owns == nullptr)) {
        return EOPNOTSUPP;
    }
    ma->secondary = secondary;
    if (ma->secondary == nullptr) {
        ma->secondary = monad_cma_get_default_allocator();
    }
    if (ma->primary->vtable->owns != nullptr &&
        ma->secondary->vtable->owns != nullptr) {
        ma->self.vtable = &g_fallback_alloc_owns_ops;
    }
    else {
        ma->self.vtable = &g_fallback_alloc_no_owns_ops;
    }
    return 0;
}
