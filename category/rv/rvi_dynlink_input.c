#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <endian.h>

#include <category/core/byteview.h>
#include <category/core/mem/align.h>
#include <category/rv/rv_link_map.h>

#include <ar.h>

#include "rv_vm_internal.h"
#include "rvi_dynlink.h"

constexpr char GNU_SYMTAB_NAME[] = "/";
constexpr char GNU_LONG_FILE_TABLE_NAME[] = "//";
constexpr char BSD_LONG_FILE_ESCAPE_NAME[] = "#1";
constexpr char UNEXPECTED_END_MSG[] = "unexpected end of system archive";

// The parsed form of the on-disk `struct ar`; this further parses the file
// name into a library name and ABI version, for our libraries
struct parsed_ar_header
{
    struct monad_rv_syslib_meta syslib_meta;
    unsigned size;
    uint8_t const *data;
};

// Describes a GNU archive symbol table
struct ar_symtab
{
    uint32_t symbol_count;
    uint32_t const *obj_offset_array;
    uint8_t const *strtab;
};

// The GNU symbol table annotates a symbol's containing object by recording
// that object's offset (the file offset in the archive); this structure is the
// pair (offset, ar_obj), and we use it to look up the object descriptor
// associated with the offset by doing a linear scan through an array of these
// pairs
struct offset_object_pair
{
    uint32_t offset;
    struct rvi_dynlink_ar_object *ar_obj;
};

static void const *try_consume(
    uint8_t const **const p, size_t const length, uint8_t const *const end,
    rvi_log_writer_t const log_wr)
{
    uint8_t const *r = *p;
    uint8_t const *const new_end = r + length;
    if (new_end > end) {
        return LW_ERRX(UNEXPECTED_END_MSG), nullptr;
    }
    *p = new_end;
    return r;
}

// Parse the on-disk archive header pointed to by `ar`
static int parse_ar_header(
    struct parsed_ar_header *const parsed, struct ar_hdr const *const ar,
    struct monad_bv const sys_archive, rvi_log_writer_t const log_wr)
{
    constexpr char SYMDEF[] = "__.SYMDEF";
    int rc;
    char *name_end;
    char term_char;
    unsigned long ul;
    struct monad_rv_syslib_meta *const name_meta = &parsed->syslib_meta;

    __builtin_memset(parsed, 0, sizeof *parsed);
    parsed->data = (uint8_t const *)(ar + 1);

    // Perform a few sanity checks
    if (parsed->data > sys_archive.end) {
        return LW_ERR(ENOEXEC, UNEXPECTED_END_MSG);
    }
    if (memcmp(ar->ar_fmag, ARFMAG, sizeof ar->ar_fmag) != 0) {
        return LW_ERR(
            ENOEXEC,
            "ar_fmag is %hx, system archive corrupt?",
            *(uint16_t const *)ar->ar_fmag);
    }

    // Parse the size and check for overflow
    ul = strtoul(ar->ar_size, nullptr, 10);
    if (parsed->data + ul > sys_archive.end) {
        return LW_ERR(ENOEXEC, UNEXPECTED_END_MSG);
    }
    parsed->size = (unsigned)ul;

    __builtin_memcpy(name_meta->abi_name, ar->ar_name, sizeof ar->ar_name);
    // Most names are terminated by '/', except the GNU special file names,
    // which start with a '/' and are terminated by the first padding space
    term_char = ar->ar_name[0] == '/' ? ' ' : '/';
    name_end = (char *)memchr(
        name_meta->abi_name, term_char, sizeof name_meta->abi_name);
    if (name_end == nullptr) {
        return LW_ERR(ENOEXEC, "corrupt system archive or unsupported format");
    }
    *name_end = '\0';
    if (strcmp(name_meta->abi_name, GNU_LONG_FILE_TABLE_NAME) == 0 ||
        strcmp(name_meta->abi_name, BSD_LONG_FILE_ESCAPE_NAME) == 0) {
        return LW_ERR(
            ENOEXEC, "system archive does not support long file names");
    }
    if (strcmp(name_meta->abi_name, GNU_SYMTAB_NAME) == 0) {
        strncpy(
            name_meta->lib_name,
            name_meta->abi_name,
            sizeof name_meta->lib_name);
        return 0;
    }
    // For any other type of file, we expect the object name to parse as
    // <name>.<version>
    rc = sscanf(
        name_meta->abi_name,
        "%16[^.].%u",
        name_meta->lib_name,
        &name_meta->abi_version);
    if (rc != 2) {
        return LW_ERR(
            ENOEXEC,
            "could not parse archive file name `%s` as <name>.<version>, "
            "sscanf(3) returned %d",
            name_meta->abi_name,
            rc);
    }
    return 0;
}

// Parse the contents of the GNU archive symbols special file described by the
// given ar header
static int parse_ar_symtab(
    struct ar_symtab *const symtab,
    struct parsed_ar_header const *const symtab_hdr,
    struct monad_bv sys_archive, rvi_log_writer_t const log_wr)
{
    uint32_t const *symbol_count_p;
    uint8_t const *p = symtab_hdr->data;

    symbol_count_p = (uint32_t const *)try_consume(
        &p, sizeof *symbol_count_p, sys_archive.end, log_wr);
    if (symbol_count_p == nullptr) {
        return LW_ERR(ENOEXEC, UNEXPECTED_END_MSG);
    }
    symtab->symbol_count = be32toh(*symbol_count_p);
    symtab->obj_offset_array = (uint32_t const *)try_consume(
        &p, symtab->symbol_count * sizeof(uint32_t), sys_archive.end, log_wr);
    if (symtab->obj_offset_array == nullptr) {
        return LW_ERR(ENOEXEC, UNEXPECTED_END_MSG);
    }
    symtab->strtab = p;
    return 0;
}

static int insert_link_input(
    struct rvi_dynlink_input *const dl_input,
    struct offset_object_pair **const obj_lookup, uint32_t const obj_offset,
    rvi_log_writer_t const log_wr, struct rvi_dynlink_ar_object **ar_obj_p)
{
    struct rvi_dynlink_ar_object *ar_obj;

    *ar_obj_p = ar_obj = calloc(1, sizeof *ar_obj);
    if (ar_obj == nullptr) {
        return LW_ERR(errno, "calloc(3) of archive link input entry failed");
    }
    *obj_lookup = realloc(
        *obj_lookup, (dl_input->ar_objs_count + 1) * sizeof **obj_lookup);
    if (*obj_lookup == nullptr) {
        return LW_ERR(errno, "realloc(3) in object lookup map failed");
    }
    (*obj_lookup)[dl_input->ar_objs_count].offset = obj_offset;
    (*obj_lookup)[dl_input->ar_objs_count].ar_obj = ar_obj;
    STAILQ_INSERT_TAIL(&dl_input->ar_objs, ar_obj, next);
    ++dl_input->ar_objs_count;
    return 0;
}

// This counts the symbols in each object member of the archive, but the real
// purpose is that it will "get or create" a link input entry associated with
// that symbol's object, which is only communicated via an integer offset to the
// header of the associated object; this routine is what actually creates the
// link input entries as we iterate through the archive symbol table
static int increment_object_symbol_count(
    struct rvi_dynlink_input *const dl_input,
    struct offset_object_pair **const obj_lookup, uint32_t const obj_offset,
    struct monad_bv const sys_archive, rvi_log_writer_t const log_wr)
{
    struct ar_hdr const *ar;
    struct parsed_ar_header obj_hdr;
    struct rvi_dynlink_ar_object *ar_obj;
    int rc;

    for (uint32_t i = 0; i < dl_input->ar_objs_count; ++i) {
        if ((*obj_lookup)[i].offset == obj_offset) {
            // This object is already known; increment symbol count and return
            ++(*obj_lookup)[i].ar_obj->meta.symbol_count;
            ++dl_input->symbol_count;
            return 0;
        }
    }

    // We have not seen this object before, create a new input descriptor for
    // it; this also populates the lookup structure used above
    rc = insert_link_input(dl_input, obj_lookup, obj_offset, log_wr, &ar_obj);
    if (rc != 0) {
        return rc;
    }

    // Parse the metadata of the new object
    ar = (struct ar_hdr const *)(sys_archive.begin + obj_offset);
    rc = parse_ar_header(&obj_hdr, ar, sys_archive, log_wr);
    if (rc != 0) {
        return rc;
    }
    ar_obj->ar_bytes = monad_bv_from_size(obj_hdr.data, obj_hdr.size);
    ++ar_obj->meta.symbol_count;
    ++dl_input->symbol_count;
    return 0;
}

static int create_link_inputs(
    struct rvi_dynlink_input *const dl_input,
    struct parsed_ar_header const *const symtab_hdr,
    struct monad_bv const sys_archive, rvi_log_writer_t const log_wr)
{
    int rc;
    struct ar_symtab symtab;
    struct offset_object_pair *obj_lookup = nullptr;

    rc = parse_ar_symtab(&symtab, symtab_hdr, sys_archive, log_wr);
    if (rc != 0) {
        return rc;
    }
    for (uint32_t i = 0; i < symtab.symbol_count; ++i) {
        uint32_t const obj_offset = be32toh(symtab.obj_offset_array[i]);

        rc = increment_object_symbol_count(
            dl_input, &obj_lookup, obj_offset, sys_archive, log_wr);
        if (rc != 0) {
            goto Done;
        }
    }
Done:
    free(obj_lookup);
    return rc;
}

int rvi_dynlink_build_input(
    struct rvi_dynlink_input *const dl_input, struct monad_bv const sys_archive,
    bool const bare_metal, rvi_log_writer_t const log_wr)
{
    int rc;
    struct ar_hdr const *ar;
    struct parsed_ar_header symtab_hdr;

    __builtin_memset(dl_input, 0, sizeof *dl_input);
    STAILQ_INIT(&dl_input->ar_objs);
    if (bare_metal) {
        // In bare metal mode, there are no system libraries; leave the input
        // map empty
        return 0;
    }

    // Check for archive magic number
    if (monad_bv_len(sys_archive) < SARMAG ||
        __builtin_memcmp(sys_archive.begin, ARMAG, SARMAG) != 0) {
        return LW_ERR(
            ENOEXEC, "system library archive missing ar(5) magic %s", ARMAG);
    }

    // The process is driven by examining the GNU-style archive symbol table,
    // rather than scanning through the whole archive. If the symbol table
    // exists it must be the first file; make sure it's there.
    ar = (struct ar_hdr const *)(sys_archive.begin + SARMAG);
    rc = parse_ar_header(&symtab_hdr, ar, sys_archive, log_wr);
    if (rc != 0) {
        return rc;
    }
    if (strcmp(symtab_hdr.syslib_meta.lib_name, GNU_SYMTAB_NAME) != 0) {
        return LW_ERR(
            ENOEXEC,
            "system archive starts with `%s`, expected GNU symbol table name "
            "`%s`",
            symtab_hdr.syslib_meta.lib_name,
            GNU_SYMTAB_NAME);
    }

    // Visit every symbol in the archive's symbol table, and make sure an
    // associated linker input is created for each unique object referenced
    // within it
    return create_link_inputs(dl_input, &symtab_hdr, sys_archive, log_wr);
}
