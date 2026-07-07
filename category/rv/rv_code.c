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

alignas(4096) static thread_local uint8_t
    s_validate_code_buf[MONAD_RV_CODE_MAX_SIZE];

struct monad_rv_zstd_decomp
{
    ZSTD_DCtx *dctx;
    uint8_t *outbuf;
    size_t outbuf_size;
};

int monad_rv_zstd_decomp_create(struct monad_rv_zstd_decomp **zd_p)
{
    int rc;
    struct monad_rv_zstd_decomp *zd;

    *zd_p = nullptr;
    zd = malloc(sizeof *zd);
    if (zd == nullptr) {
        return errno;
    }
    __builtin_memset(zd, 0, sizeof *zd);
    zd->dctx = ZSTD_createDCtx();
    if (zd->dctx == nullptr) {
        rc = errno != 0 ? errno : EIO;
        monad_rv_zstd_decomp_destroy(zd);
        return rc;
    }
    zd->outbuf_size = ZSTD_DStreamOutSize();
    zd->outbuf = malloc(zd->outbuf_size);
    if (zd->outbuf == nullptr) {
        monad_rv_zstd_decomp_destroy(zd);
        return ENOMEM;
    }
    *zd_p = zd;
    return 0;
}

void monad_rv_zstd_decomp_destroy(struct monad_rv_zstd_decomp *zd)
{
    if (zd != nullptr) {
        ZSTD_freeDCtx(zd->dctx);
        free(zd->outbuf);
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
    struct monad_bv zstd_frame, uint8_t *buf, size_t *buflen,
    struct monad_rv_zstd_decomp *decomp, size_t *zstd_rc_p,
    char const **zstd_err_p)
{
    monad_rv_validate_code_result_t vcode_result;
    uint64_t n_blocks = 0;
    size_t decomp_size = 0;
    size_t zstd_rc = 0;
    ZSTD_inBuffer zbuf_in = {
        .src = zstd_frame.begin, .size = monad_bv_len(zstd_frame), .pos = 0};

    while (zbuf_in.pos < zbuf_in.size || zstd_rc > 0) {
        ZSTD_outBuffer zbuf_out = {
            .dst = decomp->outbuf,
            .size = decomp->outbuf_size,
            .pos = 0,
        };
        zstd_rc = ZSTD_decompressStream(decomp->dctx, &zbuf_out, &zbuf_in);
        if (ZSTD_isError(zstd_rc)) {
            if (zstd_rc_p != nullptr) {
                *zstd_rc_p = zstd_rc;
            }
            if (zstd_err_p != nullptr) {
                *zstd_err_p = ZSTD_getErrorName(zstd_rc);
            }
            return MONAD_RV_VCODE_LIBZSTD_ERR;
        }
        if (n_blocks++ == 0 &&
            (zbuf_out.pos < SELFMAG ||
             __builtin_memcmp(zbuf_out.dst, ELFMAG, SELFMAG) != 0)) {
            // This is the first decompressed block, but the decompressed
            // data does not have the ELF magic number
            return MONAD_RV_VCODE_INVALID_FORMAT;
        }
        if (decomp_size + zbuf_out.pos <= *buflen) {
            memcpy(buf + decomp_size, zbuf_out.dst, zbuf_out.pos);
        }
        decomp_size += zbuf_out.pos;
    }

    vcode_result = *buflen >= decomp_size ? MONAD_RV_VCODE_HAS_ELF_MAGIC
                                          : MONAD_RV_VCODE_OVERFLOW;
    *buflen = decomp_size;
    return vcode_result;
}

monad_rv_validate_code_result_t monad_rv_validate_create_txn_data(
    struct monad_bv data, struct monad_rv_zstd_decomp *decomp,
    enum monad_rv_elf_type *elf_type, bool allow_uncompressed)
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
            sections.code_blob,
            s_validate_code_buf,
            &codelen,
            decomp,
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

    // XXX: return monad_rv_elf_validate(code, codelen, elf_type);
    return MONAD_RV_VCODE_ELF_NOT_RV64;
}
