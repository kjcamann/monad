#pragma once

#include <cstdint>

enum class EvmOpcode : uint8_t
{
    STOP = 0,
};

struct EvmOpcodeInfoEntry
{
    char const *name;
    uint8_t imm_bytes;
    uint8_t stack_args;
};

constexpr EvmOpcodeInfoEntry EvmOpcodeInfoTable[] =
{
    {.name = "STOP", .imm_bytes = 0, .stack_args = 0},
};
