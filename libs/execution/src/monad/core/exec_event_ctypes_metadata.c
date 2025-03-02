#include <stddef.h>

#include <monad/core/exec_event_ctypes.h>
#include <monad/event/event_metadata.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_event_metadata const g_monad_exec_event_metadata[16] = {
    [MONAD_EXEC_NONE] =
        {.event_type = MONAD_EXEC_NONE,
         .c_name = "MONAD_EXEC_NONE",
         .description = "reserved code so that 0 remains invalid"},

    [MONAD_EXEC_BLOCK_START] =
        {.event_type = MONAD_EXEC_BLOCK_START,
         .c_name = "BLOCK_START",
         .description = "Event recorded at the start of block execution"},

    [MONAD_EXEC_BLOCK_END] =
        {.event_type = MONAD_EXEC_BLOCK_END,
         .c_name = "BLOCK_END",
         .description = "Event recorded upon successful block execution"},

    [MONAD_EXEC_BLOCK_QC] =
        {.event_type = MONAD_EXEC_BLOCK_QC,
         .c_name = "BLOCK_QC",
         .description = "Event recorded when a proposed block obtains a quorum "
                        "certificate"},

    [MONAD_EXEC_BLOCK_FINALIZED] =
        {.event_type = MONAD_EXEC_BLOCK_FINALIZED,
         .c_name = "BLOCK_FINALIZED",
         .description = "Event recorded when consensus finalizes a block"},

    [MONAD_EXEC_BLOCK_VERIFIED] =
        {.event_type = MONAD_EXEC_BLOCK_VERIFIED,
         .c_name = "BLOCK_VERIFIED",
         .description = "Event recorded when consensus verifies the state root "
                        "of a finalized block"},

    [MONAD_EXEC_BLOCK_REJECT] =
        {.event_type = MONAD_EXEC_BLOCK_REJECT,
         .c_name = "BLOCK_REJECT",
         .description =
             "Event recorded when a block is rejected (i.e., is invalid)"},

    [MONAD_EXEC_TXN_START] =
        {.event_type = MONAD_EXEC_TXN_START,
         .c_name = "TXN_START",
         .description = "Event recorded when transaction processing starts"},

    [MONAD_EXEC_TXN_REJECT] =
        {.event_type = MONAD_EXEC_TXN_REJECT,
         .c_name = "TXN_REJECT",
         .description = "Event recorded when a transaction is rejected (i.e., "
                        "is invalid)"},

    [MONAD_EXEC_TXN_RECEIPT] =
        {.event_type = MONAD_EXEC_TXN_RECEIPT,
         .c_name = "TXN_RECEIPT",
         .description = "Event recorded when transaction execution halts"},

    [MONAD_EXEC_TXN_LOG] =
        {.event_type = MONAD_EXEC_TXN_LOG,
         .c_name = "TXN_LOG",
         .description = "Event recorded when a transaction emits a LOG"},

    [MONAD_EXEC_TXN_CALL_FRAME] =
        {.event_type = MONAD_EXEC_TXN_CALL_FRAME,
         .c_name = "TXN_CALL_FRAME",
         .description = "Event recorded when a call frame is emitted."},

    [MONAD_EXEC_ACCOUNT_ACCESS_LIST_HEADER] =
        {.event_type = MONAD_EXEC_ACCOUNT_ACCESS_LIST_HEADER,
         .c_name = "ACCOUNT_ACCESS_LIST_HEADER",
         .description = "Header event that precedes a variably-sized list of "
                        "account_access objects"},

    [MONAD_EXEC_ACCOUNT_ACCESS] =
        {.event_type = MONAD_EXEC_ACCOUNT_ACCESS,
         .c_name = "ACCOUNT_ACCESS",
         .description = "Event emitted when an account is read or written"},

    [MONAD_EXEC_STORAGE_ACCESS] =
        {.event_type = MONAD_EXEC_STORAGE_ACCESS,
         .c_name = "STORAGE_ACCESS",
         .description =
             "Event emitted for each account storage key that is accessed"},

    [MONAD_EXEC_EVM_ERROR] =
        {.event_type = MONAD_EXEC_EVM_ERROR,
         .c_name = "EVM_ERROR",
         .description =
             "Error occurred in execution process (not a validation error)"},
};

uint8_t const g_monad_exec_event_metadata_hash[32] = {
    0x64, 0xfb, 0xe5, 0xa7, 0x85, 0x1e, 0x99, 0xad, 0x74, 0xec, 0xf6,
    0x56, 0x11, 0x8e, 0xa3, 0x41, 0x5f, 0xb9, 0xe6, 0x6c, 0x81, 0xed,
    0xf4, 0x33, 0x4a, 0xa2, 0x5d, 0xee, 0x87, 0x6b, 0x65, 0xdf,
};

#ifdef __cplusplus
} // extern "C"
#endif
