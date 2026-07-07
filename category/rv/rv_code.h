#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

#ifdef __cplusplus
extern "C"
{
#endif

constexpr uint8_t MONAD_RV_CODE_PREFIX[] = {0xAE, 0x00, 0x01};
constexpr uint32_t MONAD_RV_CODE_MAX_SIZE = 1U << 18; // 256 KiB

// clang-format off

typedef enum monad_rv_elf_type
{
    MONAD_RV_ELF_TYPE_INVALID, ///< Not an ELF file format the VM supports
    MONAD_RV_ELF_TYPE_RV64,    ///< ELF64 with RISC-V machine code
    MONAD_RV_ELF_TYPE_HOST,    ///< ELF shared object compiled for host arch
} monad_rv_elf_type_t;

/// Structure that appears at the start of on-chain contract code
struct monad_rv_code_header
{
    uint8_t prefix[3];    ///< Magic byte sequence 0xAE, 0x00, 0x01
    uint32_t code_length; ///< Length of code blob following this header (LE32)
} __attribute__((packed));

/// A contract creation transaction for RV64 code contains several sections,
/// which are described by this structure
struct monad_rv_code_create_sections
{
    struct monad_rv_code_header const
        *code_header;          ///< Header describing the code blob
    struct monad_bv db_blob;   ///< Binary stored in db (header + code_blob)
    struct monad_bv code_blob; ///< zstd frame containing ELF file
    struct monad_bv init_blob; ///< Init data for contract creation
};

/// RV64 code validation errors; RV64 code validation must go through several
/// stages, including parsing the transaction data, zstd decompression, and
/// validating the ELF image
typedef enum monad_rv_validate_code_result
{
    MONAD_RV_VCODE_UNKNOWN,        ///< Zero initialization -> invalid
    MONAD_RV_VCODE_NO_PREFIX,      ///< 0xAE0001 prefix was not present
    MONAD_RV_VCODE_BAD_HEADER,     ///< Malformed monad_rvc_header
    MONAD_RV_VCODE_OVERFLOW,       ///< Code exceeds MONAD_RV_CODE_MAX_SIZE
    MONAD_RV_VCODE_POINTS_OUTSIDE, ///< code_length points past buffer end
    MONAD_RV_VCODE_INVALID_FORMAT, ///< Code not in a recognized format
    MONAD_RV_VCODE_LIBZSTD_ERR,    ///< libzstd could not decompress code
    MONAD_RV_VCODE_HAS_ELF_MAGIC,  ///< Partially checked; has ELF magic number
    MONAD_RV_VCODE_HAS_ZSTD_MAGIC, ///< Partially checked; has ZSTD magic number
    MONAD_RV_VCODE_ELF_NOT_RV64,   ///< ELF image is not RV64
    MONAD_RV_VCODE_NO_INIT_FN,     ///< init_contract function missing
    MONAD_RV_VCODE_NO_MAIN_FN,     ///< txn_main function missing
    MONAD_RV_VCODE_OK,             ///< Code has passed static validation
} monad_rv_validate_code_result_t;

// clang-format on

/// Opaque handle to a RISC-V code decompressor
struct monad_rv_zstd_decomp;

/// Create a code decompressor object; use one decompressor object per thread
/// if parallel decompression is needed
int monad_rv_zstd_decomp_create(struct monad_rv_zstd_decomp **);

/// Destroy a code decompressor object
void monad_rv_zstd_decomp_destroy(struct monad_rv_zstd_decomp *);

/// Return a string explanation of a code validation error
char const *
    monad_rv_describe_validate_code_result(monad_rv_validate_code_result_t);

/// Parse the raw data of a contract creation transaction into sections
///
/// This can fail with many kinds of validation errors, or it can return
/// one of two possible "success" codes:
///
///   1. MONAD_RV_VCODE_HAS_ELF_MAGIC -- parsed successfully and the
///      `sections->code_blob` section contains the magic number of an ELF
///      file; this does not check if the ELF file contents are valid or not
///
///   2. MONAD_RV_VCODE_HAS_ZSTD_MAGIC -- parsed successfully and the
///      `sections->code_blob` section contains the magic number of a zstd
///      frame; this does not check if the zstd frame contents are valid or not
monad_rv_validate_code_result_t monad_rv_parse_create_txn_data(
    struct monad_bv, struct monad_rv_code_create_sections *sections);

/// Given a byteview of a ZSTD frame, try to decompress its contents into
/// the provided buffer
///
/// On input, `buflen` describes the available buffer size and upon output
/// `buflen` is modified to describe the actual decompressed size. Possible
/// return codes are:
///
///   - MONAD_RV_VCODE_LIBZSTD_ERR -- decompression error from libzstd;
///       error details are available in zstd_rc and zstd_err
///
///   - MONAD_RV_VCODE_INVALID_FORMAT -- decompressed successfully, but
///       the contents were invalid (did not find an ELF magic number)
///
///   - MONAD_RV_VCODE_OVERFLOW -- decompressed successfully, but the resulting
///       code payload is too large; `buflen` will be set to the actual size,
///       but the decompressed contents are invalid
///
///   - MONAD_RV_VCODE_HAS_ELF_MAGIC -- the "success" code; decompression
///       was successful, and the payload contains an ELF magic number; it is
///       not known if the ELF contents are completely valid
monad_rv_validate_code_result_t monad_rv_decompress_code(
    struct monad_rv_zstd_decomp *, struct monad_bv zstd_frame, uint8_t *buf,
    size_t *buflen, size_t *zstd_rc, char const **zstd_err);

/// Performs all steps of validation; this can be used to validate a
/// transaction during block construction
monad_rv_validate_code_result_t monad_rv_validate_create_txn_data(
    struct monad_bv, struct monad_rv_zstd_decomp *, monad_rv_elf_type_t *,
    bool allow_uncompressed);

#ifdef __cplusplus
} // extern "C"
#endif
