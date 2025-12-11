#pragma once

#include <cstdint>

enum class EvmOpcode : uint8_t
{
    STOP = 0,
    ADD = 1,
    MUL = 2,
};

struct EvmOpcodeInfoEntry
{
    char const *name;
    uint8_t imm_bytes;
    uint8_t stack_args;
};

constexpr EvmOpcodeInfoEntry EvmOpcodeInfoTable[256] =
{
    // 0x00
    {.name = "STOP", .imm_bytes = 0, .stack_args = 0},
    {.name = "ADD", .imm_bytes = 0, .stack_args = 2},
    {.name = "MUL", .imm_bytes = 0, .stack_args = 2},
    {.name = "SUB", .imm_bytes = 0, .stack_args = 2},
    {.name = "DIV", .imm_bytes = 0, .stack_args = 2},
    {.name = "SDIV", .imm_bytes = 0, .stack_args = 2},
    {.name = "MOD", .imm_bytes = 0, .stack_args = 2},
    {.name = "SMOD", .imm_bytes = 0, .stack_args = 2},
    // 0x08
    {.name = "ADDMOD", .imm_bytes = 0, .stack_args = 2},
    {.name = "MULMOD", .imm_bytes = 0, .stack_args = 2},
    {.name = "EXP", .imm_bytes = 0, .stack_args = 2},
    {.name = "SIGNEXTEND", .imm_bytes = 0, .stack_args = 2},
    {},
    {},
    {},
    {},

    // 0x10
    {.name = "LT", .imm_bytes = 0, .stack_args = 2},
    {.name = "GT", .imm_bytes = 0, .stack_args = 2},
    {.name = "SLT", .imm_bytes = 0, .stack_args = 2},
    {.name = "SGT", .imm_bytes = 0, .stack_args = 2},
    {.name = "EQ", .imm_bytes = 0, .stack_args = 2},
    {.name = "ISZERO", .imm_bytes = 0, .stack_args = 1},
    {.name = "AND", .imm_bytes = 0, .stack_args = 2},
    {.name = "OR", .imm_bytes = 0, .stack_args = 2},
    // 0x18
    {.name = "XOR", .imm_bytes = 0, .stack_args = 2},
    {.name = "NOT", .imm_bytes = 0, .stack_args = 1},
    {.name = "BYTE", .imm_bytes = 0, .stack_args = 2},
    {.name = "SHL", .imm_bytes = 0, .stack_args = 2},
    {.name = "SHR", .imm_bytes = 0, .stack_args = 2},
    {.name = "SAR", .imm_bytes = 0, .stack_args = 1},
    {},
    {},

    // 0x20
    {.name = "KECCAK256", .imm_bytes = 0, .stack_args = 2},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        // 0x28
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},

    // 0x30
    {.name = "ADDRESS", .imm_bytes = 0, .stack_args = 0},
    {.name = "BALANCE", .imm_bytes = 0, .stack_args = 0},
    {.name = "ORIGIN", .imm_bytes = 0, .stack_args = 0},
    {.name = "CALLER", .imm_bytes = 0, .stack_args = 0},
    {.name = "CALLVALUE", .imm_bytes = 0, .stack_args = 0},
    {.name = "CALLDATALOAD", .imm_bytes = 0, .stack_args = 1},
    {.name = "CALLDATASIZE", .imm_bytes = 0, .stack_args = 0},
    {.name = "CALLDATACOPY", .imm_bytes = 0, .stack_args = 3},
        // 0x38
        {.name = "CODESIZE", .imm_bytes = 0, .stack_args = 0},
        {.name = "CODECOPY", .imm_bytes = 0, .stack_args = 0},
        {.name = "GASPRICE", .imm_bytes = 0, .stack_args = 0},
        {.name = "EXTCODESIZE", .imm_bytes = 0, .stack_args = 1},
        {.name = "EXTCODECOPY", .imm_bytes = 0, .stack_args = 4},
        {.name = "RETURNDATASIZE", .imm_bytes = 0, .stack_args = 1},
        {.name = "RETURNDATACOPY3", .imm_bytes = 0, .stack_args = 3},
        {.name = "EXTCODEHASH", .imm_bytes = 0, .stack_args = 0},

        // 0x40
        {.name = "BLOCKHASH", .imm_bytes = 0, .stack_args = 1},
        {.name = "COINBASE", .imm_bytes = 0, .stack_args = 0},
        {.name = "TIMESTAMP", .imm_bytes = 0, .stack_args = 0},
        {.name = "NUMBER", .imm_bytes = 0, .stack_args = 0},
        {.name = "PREVRANDAO", .imm_bytes = 0, .stack_args = 0},
        {.name = "GASLIMIT", .imm_bytes = 0, .stack_args = 0},
        {.name = "CHAINID", .imm_bytes = 0, .stack_args = 0},
        {.name = "SELFBALANCE", .imm_bytes = 0, .stack_args = 0},
        // 0x48
        {.name = "BASEFEE", .imm_bytes = 0, .stack_args = 0},
        {.name = "BLOBHASH", .imm_bytes = 0, .stack_args = 1},
        {.name = "BLOBBASEFEE", .imm_bytes = 0, .stack_args = 0},
        {},
        {},
        {},
        {},
        {},

        // 0x50
        {.name = "POP", .imm_bytes = 0, .stack_args = 1},
        {.name = "MLOAD", .imm_bytes = 0, .stack_args = 1},
        {.name = "MSTORE", .imm_bytes = 0, .stack_args = 2},
        {.name = "MSTORE8", .imm_bytes = 0, .stack_args = 2},
        {.name = "SLOAD", .imm_bytes = 0, .stack_args = 1},
        {.name = "SSTORE", .imm_bytes = 0, .stack_args = 2},
        {.name = "JUMP", .imm_bytes = 0, .stack_args = 1},
        {.name = "JUMPI", .imm_bytes = 0, .stack_args = 2},
        // 0x58
        {.name = "PC", .imm_bytes = 0, .stack_args = 0},
        {.name = "MSIZE", .imm_bytes = 0, .stack_args = 0},
        {.name = "GAS", .imm_bytes = 0, .stack_args = 0},
        {.name = "JUMPDEST", .imm_bytes = 0, .stack_args = 0},
        {.name = "TLOAD", .imm_bytes = 0, .stack_args = 1},
        {.name = "TSTORE", .imm_bytes = 0, .stack_args = 2},
        {.name = "MCOPY", .imm_bytes = 0, .stack_args = 3},
        {.name = "PUSH0", .imm_bytes = 0, .stack_args = 0},

        // 0x60
        {.name = "PUSH1", .imm_bytes = 1, .stack_args = 0},
        {.name = "PUSH2", .imm_bytes = 2, .stack_args = 0},
        {.name = "PUSH3", .imm_bytes = 3, .stack_args = 0},
        {.name = "PUSH4", .imm_bytes = 4, .stack_args = 0},
        {.name = "PUSH5", .imm_bytes = 5, .stack_args = 0},
        {.name = "PUSH6", .imm_bytes = 6, .stack_args = 0},
        {.name = "PUSH7", .imm_bytes = 7, .stack_args = 0},
        {.name = "PUSH8", .imm_bytes = 8, .stack_args = 0},

        // 0x68
        {.name = "PUSH9", .imm_bytes = 9, .stack_args = 0},
        {.name = "PUSH10", .imm_bytes = 10, .stack_args = 0},
        {.name = "PUSH11", .imm_bytes = 11, .stack_args = 0},
        {.name = "PUSH12", .imm_bytes = 12, .stack_args = 0},
        {.name = "PUSH13", .imm_bytes = 13, .stack_args = 0},
        {.name = "PUSH14", .imm_bytes = 14, .stack_args = 0},
        {.name = "PUSH15", .imm_bytes = 15, .stack_args = 0},
        {.name = "PUSH16", .imm_bytes = 16, .stack_args = 0},

        // 0x70
        {.name = "PUSH17", .imm_bytes = 17, .stack_args = 0},
        {.name = "PUSH18", .imm_bytes = 18, .stack_args = 0},
        {.name = "PUSH19", .imm_bytes = 19, .stack_args = 0},
        {.name = "PUSH20", .imm_bytes = 20, .stack_args = 0},
        {.name = "PUSH21", .imm_bytes = 21, .stack_args = 0},
        {.name = "PUSH22", .imm_bytes = 22, .stack_args = 0},
        {.name = "PUSH23", .imm_bytes = 23, .stack_args = 0},
        {.name = "PUSH24", .imm_bytes = 24, .stack_args = 0},

        // 0x78
        {.name = "PUSH25", .imm_bytes = 25, .stack_args = 0},
        {.name = "PUSH26", .imm_bytes = 26, .stack_args = 0},
        {.name = "PUSH27", .imm_bytes = 27, .stack_args = 0},
        {.name = "PUSH28", .imm_bytes = 28, .stack_args = 0},
        {.name = "PUSH29", .imm_bytes = 29, .stack_args = 0},
        {.name = "PUSH30", .imm_bytes = 30, .stack_args = 0},
        {.name = "PUSH31", .imm_bytes = 31, .stack_args = 0},
        {.name = "PUSH32", .imm_bytes = 32, .stack_args = 0},

        // 0x80
        {.name = "DUP1", .imm_bytes = 0, .stack_args = 1},
        {.name = "DUP2", .imm_bytes = 0, .stack_args = 2},
        {.name = "DUP3", .imm_bytes = 0, .stack_args = 3},
        {.name = "DUP4", .imm_bytes = 0, .stack_args = 4},
        {.name = "DUP5", .imm_bytes = 0, .stack_args = 5},
        {.name = "DUP6", .imm_bytes = 0, .stack_args = 6},
        {.name = "DUP7", .imm_bytes = 0, .stack_args = 7},
        {.name = "DUP8", .imm_bytes = 0, .stack_args = 8},

        // 0x88
        {.name = "DUP9", .imm_bytes = 0, .stack_args = 9},
        {.name = "DUP10", .imm_bytes = 0, .stack_args = 10},
        {.name = "DUP11", .imm_bytes = 0, .stack_args = 11},
        {.name = "DUP12", .imm_bytes = 0, .stack_args = 12},
        {.name = "DUP13", .imm_bytes = 0, .stack_args = 13},
        {.name = "DUP14", .imm_bytes = 0, .stack_args = 14},
        {.name = "DUP15", .imm_bytes = 0, .stack_args = 15},
        {.name = "DUP16", .imm_bytes = 0, .stack_args = 16},

        // 0x90
        {.name = "SWAP1", .imm_bytes = 0, .stack_args = 1},
        {.name = "SWAP2", .imm_bytes = 0, .stack_args = 2},
        {.name = "SWAP3", .imm_bytes = 0, .stack_args = 3},
        {.name = "SWAP4", .imm_bytes = 0, .stack_args = 4},
        {.name = "SWAP5", .imm_bytes = 0, .stack_args = 5},
        {.name = "SWAP6", .imm_bytes = 0, .stack_args = 6},
        {.name = "SWAP7", .imm_bytes = 0, .stack_args = 7},
        {.name = "SWAP8", .imm_bytes = 0, .stack_args = 8},

        // 0x98
        {.name = "SWAP9", .imm_bytes = 0, .stack_args = 9},
        {.name = "SWAP10", .imm_bytes = 0, .stack_args = 10},
        {.name = "SWAP11", .imm_bytes = 0, .stack_args = 11},
        {.name = "SWAP12", .imm_bytes = 0, .stack_args = 12},
        {.name = "SWAP13", .imm_bytes = 0, .stack_args = 13},
        {.name = "SWAP14", .imm_bytes = 0, .stack_args = 14},
        {.name = "SWAP15", .imm_bytes = 0, .stack_args = 15},
        {.name = "SWAP16", .imm_bytes = 0, .stack_args = 16},

        // 0xA0
        {.name = "LOG0", .imm_bytes = 0, .stack_args = 2},
        {.name = "LOG1", .imm_bytes = 0, .stack_args = 3},
        {.name = "LOG2", .imm_bytes = 0, .stack_args = 4},
        {.name = "LOG3", .imm_bytes = 0, .stack_args = 5},
        {.name = "LOG4", .imm_bytes = 0, .stack_args = 6},
        {},
        {},
        {},
        // 0xA8
        {}, {}, {}, {}, {}, {}, {}, {},

        // 0xB0
        {}, {}, {}, {}, {}, {}, {}, {},
        // 0xB8
        {}, {}, {}, {}, {}, {}, {}, {},

        // 0xC0
        {}, {}, {}, {}, {}, {}, {}, {},
        // 0xC8
        {}, {}, {}, {}, {}, {}, {}, {},

        // 0xD0
        {}, {}, {}, {}, {}, {}, {}, {},
        // 0xD8
        {}, {}, {}, {}, {}, {}, {}, {},

        // 0xE0
        {}, {}, {}, {}, {}, {}, {}, {},
        // 0xE8
        {}, {}, {}, {}, {}, {}, {}, {},

        // 0xF0
        {.name = "CREATE", .imm_bytes = 0, .stack_args = 3},
        {.name = "CALL", .imm_bytes = 0, .stack_args = 7},
        {.name = "CALLCODE", .imm_bytes = 0, .stack_args = 7},
        {.name = "RETURN", .imm_bytes = 0, .stack_args = 2},
        {.name = "DELEGATECALL", .imm_bytes = 0, .stack_args = 7},
        {.name = "CREATE2", .imm_bytes = 0, .stack_args = 4},
        {},
        {},

        // 0xF8
        {},
        {},
        {.name = "STATICCALL", .imm_bytes = 0, .stack_args = 7},
        {},
        {},
        {.name = "REVERT", .imm_bytes = 0, .stack_args = 2},
        {.name = "INVALID", .imm_bytes = 0, .stack_args = 0},
        {.name = "SELFDESTRUCT", .imm_bytes = 0, .stack_args = 1},
};
