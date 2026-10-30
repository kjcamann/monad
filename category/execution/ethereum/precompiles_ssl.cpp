// Copyright (C) 2025-26 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <category/core/assert.h>
#include <category/core/byte_string.hpp>
#include <category/execution/ethereum/precompiles.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include <cstring>
#include <span>

MONAD_NAMESPACE_BEGIN

// Rollup precompiles

// EIP-7951
PrecompileImplResult
p256_verify_impl(byte_string_view const input, std::span<uint8_t, 32> const out)
{
    if (input.size() != 160) {
        return PrecompileImplResult::failure();
    }

    EC_GROUP const *const group = EC_group_p256();
    static BIGNUM const *const p = [group] {
        BIGNUM *const p = BN_new();
        MONAD_ASSERT(p != nullptr);
        bool const curve_ok =
            EC_GROUP_get_curve_GFp(group, p, nullptr, nullptr, nullptr) == 1;
        MONAD_ASSERT(curve_ok);
        return p;
    }();

    bssl::UniquePtr<BIGNUM> r{BN_bin2bn(input.data() + 32, 32, nullptr)};
    bssl::UniquePtr<BIGNUM> s{BN_bin2bn(input.data() + 64, 32, nullptr)};
    bssl::UniquePtr<BIGNUM> const qx{BN_bin2bn(input.data() + 96, 32, nullptr)};
    bssl::UniquePtr<BIGNUM> const qy{
        BN_bin2bn(input.data() + 128, 32, nullptr)};
    bssl::UniquePtr<EC_POINT> const q{EC_POINT_new(group)};
    bssl::UniquePtr<EC_KEY> const key{
        EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)};
    bssl::UniquePtr<ECDSA_SIG> const sig{ECDSA_SIG_new()};
    MONAD_ASSERT(r && s && qx && qy && q && key && sig);

    // if not (0 < r < n and 0 < s < n): return
    BIGNUM const *const n = EC_GROUP_get0_order(group);
    if (BN_is_zero(r.get()) || BN_cmp(r.get(), n) >= 0) {
        return PrecompileImplResult::failure();
    }
    if (BN_is_zero(s.get()) || BN_cmp(s.get(), n) >= 0) {
        return PrecompileImplResult::failure();
    }

    // if not (0 ≤ qx < p and 0 ≤ qy < p): return
    if (BN_cmp(qx.get(), p) >= 0 || BN_cmp(qy.get(), p) >= 0) {
        return PrecompileImplResult::failure();
    }

    // Fails for any point not on the curve, (0, 0) included
    if (EC_POINT_set_affine_coordinates_GFp(
            group, q.get(), qx.get(), qy.get(), nullptr) != 1) {
        ERR_clear_error();
        return PrecompileImplResult::failure();
    }

    bool const key_ok = EC_KEY_set_public_key(key.get(), q.get()) == 1;
    MONAD_ASSERT(key_ok);
    bool const sig_ok =
        ECDSA_SIG_set0(sig.get(), r.release(), s.release()) == 1;
    MONAD_ASSERT(sig_ok);

    // SEC 1 v2 4.1.4: R' is not at infinity and R'.x ≡ r (mod n)
    if (ECDSA_do_verify(input.data(), 32, sig.get(), key.get()) != 1) {
        ERR_clear_error();
        return PrecompileImplResult::failure();
    }

    // Return 0x000...1
    std::memset(out.data(), 0, 32);
    out.data()[31] = 1;
    return {out.data(), 32};
}

MONAD_NAMESPACE_END
