#pragma once

#include <monad/core/address.hpp>
#include <monad/core/receipt.hpp>
#include <monad/execution/trace/call_frame.hpp>
#include <vector>

#include <monad/config.hpp>

MONAD_NAMESPACE_BEGIN

/// Type which holds all the results calculated during transaction execution.
///
/// These are only produced for valid transactions that execute "without error".
/// "Without error" does not mean "success": it means the transaction produced
/// a receipt and can be included in a block. This includes "failed"
/// transactions, which are valid transactions that reach an exceptional
/// halting state in the EVM (e.g., out of gas) and report the EIP-658 status
/// "failed" status code.
///
/// "With error" means something went wrong elsewhere: an invalid transaction
/// or an internal system error. In this case, an instance of this type should
/// not be constructed.
struct TxnExecOutput
{
    Receipt receipt;
    Address sender;
    std::vector<CallFrame> call_frames;
};

MONAD_NAMESPACE_END
