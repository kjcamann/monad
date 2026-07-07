#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <elf.h>
#include <zstd.h>

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

#include "rvi_zstd.h"

int rvi_zstd_decomp_init(struct rvi_zstd_decomp *const zd)
{
    int rc;

    __builtin_memset(zd, 0, sizeof *zd);
    zd->dctx = ZSTD_createDCtx();
    if (zd->dctx == nullptr) {
        rc = errno != 0 ? errno : EIO;
        rvi_zstd_decomp_cleanup(zd);
        return rc;
    }
    zd->outbuf_size = ZSTD_DStreamOutSize();
    zd->outbuf = malloc(zd->outbuf_size);
    if (zd->outbuf == nullptr) {
        rc = errno;
        rvi_zstd_decomp_cleanup(zd);
        return rc;
    }
    return 0;
}

void rvi_zstd_decomp_cleanup(struct rvi_zstd_decomp *const zd)
{
    ZSTD_freeDCtx(zd->dctx);
    free(zd->outbuf);
    __builtin_memset(zd, 0, sizeof *zd);
}

monad_rv_validate_code_result_t rvi_zstd_decompress_code(
    struct rvi_zstd_decomp *const zd, struct monad_bv const zstd_frame,
    uint8_t *const buf, size_t *const buflen, size_t *const zstd_rc_p,
    char const **const zstd_err_p)
{
    monad_rv_validate_code_result_t vcode_result;
    uint64_t n_blocks = 0;
    size_t decomp_size = 0;
    size_t zstd_rc = 0;
    ZSTD_inBuffer zbuf_in = {
        .src = zstd_frame.begin, .size = monad_bv_len(zstd_frame), .pos = 0};

    while (zbuf_in.pos < zbuf_in.size || zstd_rc > 0) {
        ZSTD_outBuffer zbuf_out = {
            .dst = zd->outbuf,
            .size = zd->outbuf_size,
            .pos = 0,
        };
        zstd_rc = ZSTD_decompressStream(zd->dctx, &zbuf_out, &zbuf_in);
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
