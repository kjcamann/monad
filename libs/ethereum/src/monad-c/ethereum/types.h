#pragma once

#include <stdint.h>

typedef struct mel_bytes32 {
    uint8_t bytes[32];
} mel_bytes32_t;

typedef struct mel_bytes256 {
    uint8_t bytes[256];
} mel_bytes256_t;

typedef struct mel_address {
    uint8_t bytes[20];
} mel_address_t;

typedef union mel_uint64be {
    uint64_t value;
    uint8_t bytes[8];
} mel_uint64be_t;

typedef union mel_uint128be {
    __uint128_t value;
    uint8_t bytes[16];
} mel_uint128be_t;

typedef struct mel_bytes32 mel_uint256be_t;
typedef struct mel_bytes32 mel_amount_t;
typedef struct mel_bytes32 mel_keccak256_t;