#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <elf.h>
#include <endian.h>

#include <zstd.h>

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

#include "rvi_elf.h"
#include "rvi_zstd.h"

alignas(4096) static thread_local uint8_t
    s_validate_code_buf[MONAD_RV_CODE_MAX_SIZE];

struct monad_rv_zstd_decomp
{
    struct rvi_zstd_decomp decomp;
};

int monad_rv_zstd_decomp_create(struct monad_rv_zstd_decomp **zd_p)
{
    int rc;
    struct monad_rv_zstd_decomp *zd;

    *zd_p = zd = malloc(sizeof *zd);
    if (zd == nullptr) {
        return errno;
    }
    rc = rvi_zstd_decomp_init(&zd->decomp);
    if (rc != 0) {
        monad_rv_zstd_decomp_destroy(zd);
        return rc;
    }
    return 0;
}

void monad_rv_zstd_decomp_destroy(struct monad_rv_zstd_decomp *zd)
{
    if (zd != nullptr) {
        rvi_zstd_decomp_cleanup(&zd->decomp);
        free(zd);
    }
}

char const *
monad_rv_describe_validate_code_result(monad_rv_validate_code_result_t r)
{
    switch (r) {
#define ERR_DEF(ENUM, STRING)                                                  \
    case ENUM:                                                                 \
        return STRING;

#include "validate_err.def"
#undef ERR_DEF

    default:
        return "Unknown RV64 code validation error";
    }
}

monad_rv_validate_code_result_t monad_rv_parse_create_txn_data(
    struct monad_bv data, struct monad_rv_code_create_sections *sections)
{
    struct monad_rv_code_header const *code_header;
    size_t data_len;

    // Layout of transaction data for a contract creation transaction:
    //
    //   .--------------. <--- struct monad_rv_code_header
    //   |  0xAE 00 01  |
    //   |     ====     |
    //   |  code length | ---.
    //   .--------------.    |
    //   |              |    | gives length of section
    //   |     code     | <--.
    //   |    section   |
    //   |              |
    //   .--------------. <--- everything after code is init data
    //   |              |
    //   |     init     |
    //   |     data     |
    //   |  (optional)  |
    //   |              |
    //   .--------------.
    //
    // `*code_header` is the first section
    //
    // `db_blob` is a byteview of the first two sections, and is what is
    //           recorded to the code database (the hash of `db_blob` is the
    //           code_hash of the smart contract account)
    //
    // `code_blob` is only the code payload section; it is either is an ELF
    //             binary, or a ZSTD compressed frame whose decompressed
    //             contents contain an ELF binary
    //
    // `init_blob` is the init data section, to be passed to the contract
    //             constructor
    data_len = monad_bv_len(data);
    sections->code_header = code_header =
        (struct monad_rv_code_header const *)data.begin;

    if (data_len < sizeof MONAD_RV_CODE_PREFIX ||
        __builtin_memcmp(
            data.begin, MONAD_RV_CODE_PREFIX, sizeof MONAD_RV_CODE_PREFIX) !=
            0) {
        return MONAD_RV_VCODE_NO_PREFIX;
    }
    if (data_len < sizeof *code_header) {
        return MONAD_RV_VCODE_BAD_HEADER;
    }
    if (code_header->code_length > MONAD_RV_CODE_MAX_SIZE) {
        return MONAD_RV_VCODE_OVERFLOW;
    }
    sections->db_blob =
        monad_bv_sub(data, 0, sizeof *code_header + code_header->code_length);
    sections->code_blob =
        monad_bv_sub(data, sizeof *code_header, code_header->code_length);
    if (sections->code_blob.end > data.end) {
        // code_length points outside the data buffer
        return MONAD_RV_VCODE_POINTS_OUTSIDE;
    }
    if (monad_bv_len(sections->code_blob) < sizeof(uint32_t)) {
        // Code is expected to start with the ELF or ZSTD magic numbers,
        // but it's too small to contain either one
        return MONAD_RV_VCODE_INVALID_FORMAT;
    }
    sections->init_blob = monad_bv_sub(
        data, sizeof *code_header + code_header->code_length, MONAD_BV_ALL);
    if (le32toh(*(uint32_t const *)sections->code_blob.begin) ==
        ZSTD_MAGICNUMBER) {
        return MONAD_RV_VCODE_HAS_ZSTD_MAGIC;
    }
    if (__builtin_memcmp(sections->code_blob.begin, ELFMAG, SELFMAG) == 0) {
        return MONAD_RV_VCODE_HAS_ELF_MAGIC;
    }
    return MONAD_RV_VCODE_INVALID_FORMAT;
}

monad_rv_validate_code_result_t monad_rv_decompress_code(
    struct monad_rv_zstd_decomp *const zd, struct monad_bv const zstd_frame,
    uint8_t *const buf, size_t *const buflen, size_t *const zstd_rc_p,
    char const **const zstd_err_p)
{
    return rvi_zstd_decompress_code(
        &zd->decomp, zstd_frame, buf, buflen, zstd_rc_p, zstd_err_p);
}

monad_rv_validate_code_result_t monad_rv_validate_create_txn_data(
    struct monad_bv const data, struct monad_rv_zstd_decomp *const zd,
    enum monad_rv_elf_type *const elf_type, bool const allow_uncompressed)
{
    struct monad_rv_code_create_sections sections;
    monad_rv_validate_code_result_t vcode_result;
    void const *code;
    size_t codelen;

    vcode_result = monad_rv_parse_create_txn_data(data, &sections);
    if (vcode_result == MONAD_RV_VCODE_HAS_ZSTD_MAGIC) {
        code = s_validate_code_buf;
        codelen = sizeof s_validate_code_buf;
        vcode_result = monad_rv_decompress_code(
            zd,
            sections.code_blob,
            s_validate_code_buf,
            &codelen,
            nullptr,
            nullptr);
        if (vcode_result != MONAD_RV_VCODE_HAS_ELF_MAGIC) {
            return vcode_result;
        }
    }
    else if (vcode_result == MONAD_RV_VCODE_HAS_ELF_MAGIC) {
        if (!allow_uncompressed) {
            return MONAD_RV_VCODE_INVALID_FORMAT;
        }
        // The ELF file is not compressed, just examine it in place
        code = sections.code_blob.begin;
        codelen = monad_bv_len(sections.code_blob);
    }
    else {
        return MONAD_RV_VCODE_INVALID_FORMAT;
    }

    return rvi_elf_validate(code, codelen, elf_type);
}
