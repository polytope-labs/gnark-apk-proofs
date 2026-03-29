// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma solidity ^0.8.28;

import "./PlonkVerifier.sol";

/// @title APK Proof Verifier
/// @notice Human-readable wrapper around the auto-generated gnark PLONK verifier.
/// @dev BLS12-381 G1 points are passed as `bytes32[3]` (96 bytes total):
///      X (48 bytes big-endian) || Y (48 bytes big-endian), matching the
///      standard gnark-crypto / EIP-2537 uncompressed G1 format.
contract ApkProof {
    PlonkVerifier public immutable verifier;

    error G1AddFailed();
    error ProofVerificationFailed();

    /// EIP-2537 BLS12-381 G1ADD precompile address.
    uint256 constant PRECOMPILE_BLS12_G1ADD = 0x0b;

    /// Protocol-fixed seed point for APK aggregation.
    /// Computed as HashToG1(dst="gnark-apk-proofs", msg="apk-seed").
    /// The circuit hardcodes this same constant; the contract adds it to the
    /// caller-supplied APK before passing to the PLONK verifier.
    bytes32 constant SEED_0 = 0x054abdb6c5522fe2f71d55922d6f674a4908d39e2b33efcc62520c0621ca0d6a;
    bytes32 constant SEED_1 = 0x6d84ee717b7fb1cb5f46687265be01ce06e518322165fd114cdf6b4ab59eb45e;
    bytes32 constant SEED_2 = 0x9289cc4f6f7948d6b680cef9ecc0e0e0f96bd59a578d58c33c0e10db9c25b5ad;

    /// @notice Public inputs for the APK proof circuit.
    struct ApkPublicInputs {
        /// Poseidon2 hash commitment over all 1024 validator public keys.
        /// Computed as: Poseidon2(pk_0.X.limbs || pk_0.Y.limbs || pk_1.X.limbs || ... || pk_1023.Y.limbs)
        /// where each Fp coordinate is decomposed into 6 x 64-bit little-endian limbs
        /// (12 limbs per G1 point, 12288 field elements total).
        uint256 publicKeysCommitment;
        /// Bitlist encoding participating validators (5 field elements).
        /// bitlist[0..3] encode 250 bits each, bitlist[4] encodes 24 bits.
        uint256[5] bitlist;
        /// Aggregate public key of participating validators: apk = sum(b_i * pk_i).
        /// 96 bytes: X (48 bytes big-endian) || Y (48 bytes big-endian).
        /// Note: The circuit expects seed + apk; the contract adds the seed automatically.
        bytes32[3] apk;
    }

    constructor(address _verifier) {
        verifier = PlonkVerifier(_verifier);
    }

    /// @notice Verify a proof of APK aggregation.
    /// @param proof The serialized proof bytes.
    /// @param inputs The structured public inputs.
    function verify(
        ApkPublicInputs calldata inputs,
        bytes calldata proof
    ) external view {
        uint256[18] memory encoded = _encodePublicInputs(inputs);
        if (!verifier.Verify(proof, encoded)) {
            revert ProofVerificationFailed();
        }
    }

    /// @dev Encode structured public inputs into the flat uint256[18] format
    ///      expected by the gnark verifier.
    ///
    ///      Layout (matching circuit witness serialization):
    ///        [0..4]   bitlist (5 elements)
    ///        [5]      publicKeysCommitment
    ///        [6..11]  expectedApk.X limbs (6 x 64-bit, little-endian)
    ///        [12..17] expectedApk.Y limbs (6 x 64-bit, little-endian)
    ///
    ///      All work is done in a single assembly block using scratch memory
    ///      to avoid heap allocations and function call overhead.
    function _encodePublicInputs(
        ApkPublicInputs calldata inputs
    ) internal view returns (uint256[18] memory out) {
        bytes32 s0 = SEED_0;
        bytes32 s1 = SEED_1;
        bytes32 s2 = SEED_2;

        assembly {
            let mask := 0xFFFFFFFFFFFFFFFF

            // --- Copy bitlist and commitment into out[0..5] ---
            // Struct calldata layout: commitment(32) || bitlist(5*32) || apk(3*32)
            // Verifier expects: out[0..4]=bitlist, out[5]=commitment
            calldatacopy(out, add(inputs, 32), 160)        // bitlist (5*32) -> out[0..4]
            calldatacopy(add(out, 160), inputs, 32)        // commitment -> out[5]

            // --- Build G1ADD input in scratch memory at `out + 576` ---
            // out occupies 18*32 = 576 bytes; we use the space after it as scratch.
            let scratch := add(out, 576)

            // Zero the 256-byte G1ADD input region
            mstore(scratch, 0)
            mstore(add(scratch, 32), 0)
            mstore(add(scratch, 64), 0)
            mstore(add(scratch, 96), 0)
            mstore(add(scratch, 128), 0)
            mstore(add(scratch, 160), 0)
            mstore(add(scratch, 192), 0)
            mstore(add(scratch, 224), 0)

            // Seed point (padded EIP-2537 format):
            //   [16..48)  = s0          (seed X high 32 bytes)
            //   [48..64)  = s1[0:16]    (seed X low 16 bytes)
            //   [80..96)  = s1[16:32]   (seed Y high 16 bytes)
            //   [96..128) = s2          (seed Y low 32 bytes)
            mstore(add(scratch, 16), s0)
            mstore(add(scratch, 48), s1)
            mstore(add(scratch, 64), 0)            // zero-pad between X and Y
            mstore(add(scratch, 80), shl(128, s1)) // s1[16:32] left-aligned
            mstore(add(scratch, 96), s2)

            // APK point from calldata (padded):
            //   apk offset in inputs = 192 (after bitlist + commitment)
            let apkOff := add(inputs, 192)
            calldatacopy(add(scratch, 144), apkOff, 48)       // APK X
            calldatacopy(add(scratch, 208), add(apkOff, 48), 48) // APK Y

            // --- Call G1ADD precompile, output to scratch+256 (128 bytes) ---
            let res := add(scratch, 256)
            let ok := staticcall(gas(), PRECOMPILE_BLS12_G1ADD, scratch, 256, res, 128)
            if iszero(ok) {
                mstore(0, 0x55d4cbf9) // G1AddFailed()
                revert(28, 4)
            }

            // --- Decompose padded G1 result into 12 x 64-bit limbs ---
            // Result layout: [16 zero | X 48 bytes | 16 zero | Y 48 bytes]

            // X coordinate: hi at res+16, lo at res+32
            let xHi := mload(add(res, 16))
            let xLo := mload(add(res, 32))
            mstore(add(out, 192), and(xLo, mask))          // out[6]
            mstore(add(out, 224), and(shr(64, xLo), mask))  // out[7]
            mstore(add(out, 256), and(shr(128, xLo), mask)) // out[8]
            mstore(add(out, 288), and(shr(192, xLo), mask)) // out[9]
            mstore(add(out, 320), and(shr(128, xHi), mask)) // out[10]
            mstore(add(out, 352), shr(192, xHi))            // out[11]

            // Y coordinate: hi at res+80, lo at res+96
            let yHi := mload(add(res, 80))
            let yLo := mload(add(res, 96))
            mstore(add(out, 384), and(yLo, mask))          // out[12]
            mstore(add(out, 416), and(shr(64, yLo), mask))  // out[13]
            mstore(add(out, 448), and(shr(128, yLo), mask)) // out[14]
            mstore(add(out, 480), and(shr(192, yLo), mask)) // out[15]
            mstore(add(out, 512), and(shr(128, yHi), mask)) // out[16]
            mstore(add(out, 544), shr(192, yHi))            // out[17]
        }
    }
}
