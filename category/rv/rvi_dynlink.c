#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/queue.h>

#include "rv_vm_internal.h"
#include "rvi_addr_space.h"
#include "rvi_dynlink.h"
#include "rvi_elf.h"

typedef enum object_type
{
    OT_SHARED,
    OT_CONTRACT,
} object_type_t;

// clang-format on

struct shared_object
{
    struct monad_rv_link_map_entry
        *lm_entry;                   ///< Our entry in the link map
    struct rvi_elf *elf;             ///< ELF descriptor for shared object
    struct shared_object **deps;     ///< Dependency list on other objects
    unsigned deps_count;             ///< # of entries in `deps`
    STAILQ_ENTRY(shared_object) next_topo;
};

struct rvi_dynlink
{
    struct monad_rv_vm *vm;
    void *shared_seg_base;
    struct shared_object *shared_obj;
    unsigned shared_obj_count;
};

// clang-format off

static int populate_dependencies(struct rvi_dynlink *const dynlink,
    struct shared_object *const so)
{
    // XXX: for each ELF note, compute the dependencies
    return ENOSYS;
}

// When this called, the link map entry `object_bytes` field is pointing to
// read-only mmap'ed data from the archive file; copy those bytes into the
// real buffer that holds the code, and reset the byte view to point there
static int load_shared_objects(struct rvi_dynlink *const dynlink)
{
    struct monad_rv_link_map *const link_map = &dynlink->vm->link_map;
    struct monad_rv_vm *const vm = dynlink->vm;
    struct monad_rv_link_map_entry *lm_entry;
    unsigned load_count = 0;

    STAILQ_FOREACH(lm_entry, &link_map->entries, next)
    {
        int rc;
        struct shared_object *so;
        size_t so_size;
        uint64_t so_seg_offset;
        void *so_base_addr;

        so_size = monad_bv_len(lm_entry->object_bytes);
        so_seg_offset = lm_entry->rv_vaddr - RVI_BASE_SYSTEM_CODE_ADDR;
        so_base_addr = (uint8_t *)dynlink->shared_seg_base + so_seg_offset;

        // Copy the object into place and reseat the `object_bytes` member
        memcpy(so_base_addr, lm_entry->object_bytes.begin, so_size);
        lm_entry->object_bytes = monad_bv_from_size(so_base_addr, so_size);

        so = &dynlink->shared_obj[load_count++];
        so->lm_entry = lm_entry;

        // Now that it's properly aligned, load the ELF file
        rc = rvi_elf_open(&so->elf, so_base_addr, so_size);
        if (rc != 0) {
            return rc;
        }
        rc = populate_dependencies(dynlink, so);
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

// Topologically sort the objects by their dependency relationships, to
// compute the order we'll visit them in
static int compute_visit_order(struct rvi_dynlink *const dynlink)
{
    return ENOSYS;
}

static int export_shared_object_symbols(struct rvi_dynlink *const dynlink, struct shared_object *const so)
{
    return ENOSYS;
}

static int relocate_object(struct rvi_dynlink *const dynlink, struct rvi_elf *const elf, object_type_t const obj_type)
{
    return ENOSYS;
}

static int init_dynlink(struct rvi_dynlink *const dynlink, bool use_hugepages)
{
    int rc;
    struct shared_object *so;
    int mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE;
    struct monad_rv_link_map *const link_map = &dynlink->vm->link_map;
    struct monad_rv_vm *const vm = dynlink->vm;

#ifdef MAP_HUGETLB
    mmap_flags |= use_hugepages ? MAP_HUGETLB : 0:
#endif

    // Allocate an array to hold the shared objects
    dynlink->shared_obj_count = link_map->entries_count;
    dynlink->shared_obj = (struct shared_object *)calloc(dynlink->shared_obj_count, sizeof(struct shared_object));
    if (dynlink->shared_obj == nullptr) {
        rc = errno;
        return VM_ERR(rc, "calloc(3) for shared_objects failed"), rc;
    }

#if 0
    // Earlier in the startup process, we computed the link map, which describes
    // the address space for the shared objects. Allocate enough memory to hold
    // them.
    dynlink->shared_seg_base = mmap(nullptr, link_map->segment_size, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
    if (dynlink->shared_seg_base == MAP_FAILED) {
        rc = errno;
        return VM_ERR(rc, "mmap(2) of %zu bytes for shared objects failed", link_map->segment_size), rc;
    }
#endif

    // Step 1: load the shared objects into the memory we just allocated
    rc = load_shared_objects(dynlink);
    if (rc != 0) {
        return rc;
    }

    // Step 2: compute the order we need to visit the dependencies in
    rc = compute_visit_order(dynlink);
    if (rc != 0) {
        return rc;
    }

#if 0
    // Step 3: visit each shared object in topologically sorted order, add its
    // exported symbols, and relocate any of its missing symbols
    STAILQ_FOREACH(so, &dynlink->topo_list, next_topo)
    {
        rc = export_shared_object_symbols(dynlink, so);
        if (rc != 0) {
            return rc;
        }
        rc = relocate_object(dynlink, so->elf, OT_SHARED);
        if (rc != 0) {
            return rc;
        }
    }
#endif

    return 0;
}

int rvi_dynlink_create(
    struct rvi_dynlink **const dynlink_p, struct monad_rv_vm *const vm, bool use_hugepages)
{
    int rc;
    struct rvi_dynlink *dynlink;

    *dynlink_p = dynlink = malloc(sizeof *dynlink);
    if (dynlink == nullptr) {
        rc = errno;
        return VM_ERR(rc, "malloc(3) of rvi_dynlink failed"), rc;
    }
    memset(dynlink, 0, sizeof *dynlink);
    dynlink->vm = vm;

#if 0
    // First build the shared object link map from the information in the
    // system archive file; this computes the address layout for the system
    // code, which is shared across contracts
    rc = rvi_link_map_build(&vm->link_map, vm_config->sys_archive, vm_config->no_system_libs, vm->log_wr);
    if (rc != 0) {
        return rc;
    }
#endif

    rc = init_dynlink(dynlink, use_hugepages);
    if (rc != 0) {
        rvi_dynlink_destroy(dynlink);
    }
    return rc;
}

void rvi_dynlink_destroy(struct rvi_dynlink *dynlink)
{
    if (dynlink != nullptr) {
        if (dynlink->shared_seg_base != MAP_FAILED && dynlink->shared_seg_base != nullptr) {
            (void)munmap(dynlink->shared_seg_base, dynlink->vm->link_map.segment_size);
        }
        free(dynlink);
    }
}

int rvi_dynlink_relocate(struct rvi_dynlink *const dynlink, struct rvi_elf *const elf)
{
    return relocate_object(dynlink, elf, OT_CONTRACT);
}
