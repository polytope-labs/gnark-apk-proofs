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

import {PlonkVerifier} from "./PlonkVerifier.sol";

/// @title APK Proof & BLS Aggregate Signature Verifier
/// @notice Verifies both APK aggregation proofs (via PLONK) and aggregate BLS
///         signatures using the scheme from "Efficient Aggregatable BLS
///         Signatures with Chaum-Pedersen Proofs" (https://eprint.iacr.org/2022/1611).
///
/// @dev BLS aggregate signature verification equation:
///        e(asig + t·apk₁, g₂) = e(H(m) + t·g₁, apk₂)
///      Checked as: e(asig + t·apk₁, -g₂) · e(H(m) + t·g₁, apk₂) = 1
///      where t = hash_to_field(H(m) ‖ sig ‖ apk₁ ‖ apk₂) via expand_message_xmd.
///
///      BLS12-381 G1 points are passed as `bytes32[3]` (96 bytes total):
///      X (48 bytes big-endian) || Y (48 bytes big-endian), matching the
///      standard gnark-crypto / EIP-2537 uncompressed G1 format.
///
///      G2 points are 192 bytes uncompressed (X.c0‖X.c1‖Y.c0‖Y.c1, 48 bytes each).
///
///      Requires Prague EVM (Pectra hardfork) for EIP-2537 BLS12-381 precompiles.
contract ApkProof {
    PlonkVerifier public immutable _plonk;

    error G1AddFailed();
    error PlonkVerificationFailed();
    error SignatureVerificationFailed();


    // Precompile addresses
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1ADD = 0x0b;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIRING = 0x0f;
    uint256 constant PRECOMPILE_BLS12_MAP_FP_TO_G1 = 0x10;

    /// APK proof constants
    ///
    /// Protocol-fixed seed point for APK aggregation.
    /// Computed as HashToG1(dst="gnark-apk-proofs", msg="apk-seed").
    /// The circuit hardcodes this same constant; the contract adds it to the
    /// caller-supplied APK before passing to the PLONK verifier.
    bytes32 constant SEED_0 = 0x054abdb6c5522fe2f71d55922d6f674a4908d39e2b33efcc62520c0621ca0d6a;
    bytes32 constant SEED_1 = 0x6d84ee717b7fb1cb5f46687265be01ce06e518322165fd114cdf6b4ab59eb45e;
    bytes32 constant SEED_2 = 0x9289cc4f6f7948d6b680cef9ecc0e0e0f96bd59a578d58c33c0e10db9c25b5ad;

    /// BLS signature verification constants
    /// 
    /// BLS12-381 scalar field order r.
    uint256 private constant R_MOD = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// BLS12-381 G1 generator in EIP-2537 padded format (hi/lo word pairs).
    uint256 private constant G1_GEN_X_HI = 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant G1_GEN_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint256 private constant G1_GEN_Y_HI = 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4;
    uint256 private constant G1_GEN_Y_LO = 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

    /// Negated BLS12-381 G2 generator (-g₂) in EIP-2537 padded format.
    /// X coordinates are unchanged; Y coordinates are negated (p − Y.c0, p − Y.c1).
    /// Using -g₂ lets us write the pairing check as:
    ///   e(asig + t·apk₁, -g₂) · e(H(m) + t·g₁, apk₂) = 1
    /// avoiding a runtime G1 negation.
    /// X values from the gnark PlonkVerifier's G2_SRS_0 constants.
    uint256 private constant NEG_G2_GEN_X_0_HI = 3045985886519456750490515843806728273;
    uint256 private constant NEG_G2_GEN_X_0_LO =
        89961632905173714226157479458612185649920463576279427516307505038263245192632;
    uint256 private constant NEG_G2_GEN_X_1_HI = 26419286191256893424348605754143887205;
    uint256 private constant NEG_G2_GEN_X_1_LO =
        40446337346877272185227670183527379362551741423616556919902061939448715946878;
    uint256 private constant NEG_G2_GEN_Y_0_HI = 17421388336814597573762763446246275004;
    uint256 private constant NEG_G2_GEN_Y_0_LO =
        82535940630695547964844822885348920226556672312706312698172214783216175252138;
    uint256 private constant NEG_G2_GEN_Y_1_HI = 26554973746327433462396120515077546301;
    uint256 private constant NEG_G2_GEN_Y_1_LO =
        69304817850384178235384652711014277219752988873539414788182467642510429663469;

    /// BLS12-381 base field modulus p, split for mstore (32 + 16 bytes).
    /// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 private constant BLS_P_FIRST_32 =
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624;
    uint256 private constant BLS_P_LAST_16 = 0x1eabfffeb153ffffb9feffffffffaaab;

    /// @notice Public inputs for the APK proof circuit.
    struct PublicInputs {
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
        _plonk = PlonkVerifier(_verifier);
    }

    /// @notice Verify both APK aggregation proof and aggregate BLS signature in one call.
    /// @param apkInputs   Structured public inputs for the APK proof.
    /// @param apkProof    The serialized PLONK proof bytes.
    /// @param message H(m) ∈ G1, bytes32[3] (96 bytes).
    /// @param signature   Aggregate signature ∈ G1, bytes32[3] (96 bytes).
    /// @param apk2        Aggregate public key ∈ G2, bytes32[6] (192 bytes).
    function verify(
        PublicInputs calldata apkInputs,
        bytes calldata apkProof,
        bytes32[3] calldata message,
        bytes32[3] calldata signature,
        bytes32[6] calldata apk2
    ) external view {
        // Verify APK aggregation proof
        uint256[18] memory encoded = _encodePublicInputs(apkInputs);
        if (!_plonk.Verify(apkProof, encoded)) revert PlonkVerificationFailed();

        // Verify BLS aggregate signature using apk from the proof inputs
        if (!_verifyBls(apkInputs, message, signature, apk2)) revert SignatureVerificationFailed();
    }

    /// @notice Hash an arbitrary message to a BLS12-381 G1 point.
    ///         Implements hash_to_curve (RFC 9380) with expand_message_xmd (SHA-256).
    ///         Uses DST = 0x01 (w3f/bls convention). Caller must prepend the cipher
    ///         suite string to the message (e.g. "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_").
    /// @param message The message to hash (with cipher suite prefix).
    /// @return result Uncompressed G1 point as bytes32[3] (X ‖ Y, 96 bytes).
    function hashToG1(bytes calldata message) public view returns (bytes32[3] memory result) {
        assembly {
            let ptr := mload(0x40)
            let sha2 := 0x02
            let msgLen := message.length

            // ═══════════════════════════════════════════════════════════
            // Phase 1: expand_message_xmd (SHA-256, DST=0x01, 128-byte output)
            //   DST_prime = 0x01 ‖ 0x01 (DST ‖ I2OSP(1,1))
            //   uniform_bytes = b1 ‖ b2 ‖ b3 ‖ b4
            // ═══════════════════════════════════════════════════════════

            // msg_prime = Z_pad(64) ‖ msg ‖ I2OSP(128,2) ‖ I2OSP(0,1) ‖ DST_prime
            mstore(ptr, 0)                                           // Z_pad[0..31]
            mstore(add(ptr, 0x20), 0)                                // Z_pad[32..63]
            calldatacopy(add(ptr, 0x40), message.offset, msgLen)     // message
            let pos := add(add(ptr, 0x40), msgLen)
            mstore8(pos, 0x00)                                       // I2OSP(128,2) high
            mstore8(add(pos, 1), 0x80)                               // I2OSP(128,2) low
            mstore8(add(pos, 2), 0x00)                               // I2OSP(0,1)
            mstore8(add(pos, 3), 0x01)                               // DST[0]
            mstore8(add(pos, 4), 0x01)                               // I2OSP(1,1)
            let msgPrimeLen := add(0x45, msgLen)                     // 64+msg+3+2

            // b0 = SHA256(msg_prime) — output just past msg_prime
            let b0Out := add(ptr, msgPrimeLen)
            if iszero(staticcall(gas(), sha2, ptr, msgPrimeLen, b0Out, 0x20)) { revert(0, 0) }
            let b0 := mload(b0Out)

            let hashOut := add(ptr, 0x200)

            // b1 = SHA256(b0 ‖ 0x01 ‖ DST_prime)
            // DST_prime = 0x01 0x01 → biHashLen = 32+1+2 = 35 = 0x23
            mstore(ptr, b0)
            mstore8(add(ptr, 0x20), 0x01)
            mstore8(add(ptr, 0x21), 0x01)                            // DST[0]
            mstore8(add(ptr, 0x22), 0x01)                            // I2OSP(1,1)
            if iszero(staticcall(gas(), sha2, ptr, 0x23, hashOut, 0x20)) { revert(0, 0) }
            let b1 := mload(hashOut)

            // b2 = SHA256((b0 ⊕ b1) ‖ 0x02 ‖ DST_prime)
            mstore(ptr, xor(b0, b1))
            mstore8(add(ptr, 0x20), 0x02)
            if iszero(staticcall(gas(), sha2, ptr, 0x23, hashOut, 0x20)) { revert(0, 0) }
            let b2 := mload(hashOut)

            // b3 = SHA256((b0 ⊕ b2) ‖ 0x03 ‖ DST_prime)
            mstore(ptr, xor(b0, b2))
            mstore8(add(ptr, 0x20), 0x03)
            if iszero(staticcall(gas(), sha2, ptr, 0x23, hashOut, 0x20)) { revert(0, 0) }
            let b3 := mload(hashOut)

            // b4 = SHA256((b0 ⊕ b3) ‖ 0x04 ‖ DST_prime)
            mstore(ptr, xor(b0, b3))
            mstore8(add(ptr, 0x20), 0x04)
            if iszero(staticcall(gas(), sha2, ptr, 0x23, hashOut, 0x20)) { revert(0, 0) }
            let b4 := mload(hashOut)

            // ═══════════════════════════════════════════════════════════
            // Phase 2: reduce to field elements via MODEXP (x^1 mod p)
            //   u0 = (b1‖b2) mod p,  u1 = (b3‖b4) mod p
            // ═══════════════════════════════════════════════════════════

            // MODEXP input: Bsize(32) ‖ Esize(32) ‖ Msize(32) ‖ base(64) ‖ exp(1) ‖ mod(48)
            mstore(ptr, 64)                                          // Bsize
            mstore(add(ptr, 0x20), 1)                                // Esize
            mstore(add(ptr, 0x40), 48)                               // Msize
            mstore(add(ptr, 0x60), b1)                               // base high
            mstore(add(ptr, 0x80), b2)                               // base low
            mstore8(add(ptr, 0xA0), 0x01)                            // exp = 1
            mstore(add(ptr, 0xA1), BLS_P_FIRST_32)                   // mod[0..31]
            mstore(add(ptr, 0xC1), shl(128, BLS_P_LAST_16))          // mod[32..47]

            // Zero MAP_FP_TO_G1 padding (16 bytes at ptr+0x200)
            mstore(add(ptr, 0x200), 0)

            // u0 = (b1‖b2) mod p → ptr+0x210 (48 bytes, forming MAP input at ptr+0x200)
            if iszero(staticcall(gas(), PRECOMPILE_MODEXP, ptr, 0xD1, add(ptr, 0x210), 48)) {
                revert(0, 0)
            }

            // MAP_FP_TO_G1(u0) → Q0 at ptr+0x300 (128 bytes)
            if iszero(staticcall(gas(), PRECOMPILE_BLS12_MAP_FP_TO_G1, add(ptr, 0x200), 64, add(ptr, 0x300), 128)) {
                revert(0, 0)
            }

            // u1 = (b3‖b4) mod p
            mstore(add(ptr, 0x60), b3)
            mstore(add(ptr, 0x80), b4)
            if iszero(staticcall(gas(), PRECOMPILE_MODEXP, ptr, 0xD1, add(ptr, 0x210), 48)) {
                revert(0, 0)
            }

            // MAP_FP_TO_G1(u1) → Q1 at ptr+0x380 (128 bytes)
            if iszero(staticcall(gas(), PRECOMPILE_BLS12_MAP_FP_TO_G1, add(ptr, 0x200), 64, add(ptr, 0x380), 128)) {
                revert(0, 0)
            }

            // ═══════════════════════════════════════════════════════════
            // Phase 3: G1ADD(Q0, Q1) → H(m)
            // ═══════════════════════════════════════════════════════════

            // Q0‖Q1 contiguous at ptr+0x300 (256 bytes)
            if iszero(staticcall(gas(), PRECOMPILE_BLS12_G1ADD, add(ptr, 0x300), 256, add(ptr, 0x300), 128)) {
                revert(0, 0)
            }

            // Extract raw G1 (96 bytes) from padded format (128 bytes)
            // X at ptr+0x310 (48 bytes), Y at ptr+0x350 (48 bytes)
            mcopy(result, add(ptr, 0x310), 48)
            mcopy(add(result, 48), add(ptr, 0x350), 48)
        }
    }

    /// @dev Derive challenge t and verify the BLS pairing check — all in assembly.
    ///      Reads apk1 directly from the struct's calldata slot, no memory copies.
    ///
    ///      Phase 1 — expand_message_xmd (SHA-256, empty DST, 48-byte output):
    ///        msg_prime = Z_pad(64) ‖ message(96) ‖ sig(96) ‖ apk1(96) ‖ apk2(192) ‖ 0x00300000
    ///        b0 = SHA256(msg_prime), b1 = SHA256(b0‖0x0100), b2 = SHA256((b0⊕b1)‖0x0200)
    ///        t  = (b1·2¹²⁸ + b2>>128) mod r
    ///
    ///      Phase 2 — pairing check:
    ///        e(sig + t·apk₁, -g₂) · e(msg + t·g₁, apk₂) = 1
    function _verifyBls(
        PublicInputs calldata apkInputs,
        bytes32[3] calldata message,
        bytes32[3] calldata signature,
        bytes32[6] calldata apk2
    ) internal view returns (bool result) {
        assembly {
            let ptr := mload(0x40)
            let sha2 := 0x02

            // apk1 sits at apkInputs + 192 in calldata (after commitment(32) + bitlist(160))
            let apk1Off := add(apkInputs, 192)

            // ═══════════════════════════════════════════════════════════
            // Phase 1: derive challenge t
            // ═══════════════════════════════════════════════════════════
            // Build msg_prime at ptr (548 = 0x224 bytes)
            mstore(ptr, 0)                                          // Z_pad[0..31]
            mstore(add(ptr, 0x20), 0)                               // Z_pad[32..63]
            calldatacopy(add(ptr, 0x40), message, 96)        // message
            calldatacopy(add(ptr, 0xA0), signature, 96)      // signature
            calldatacopy(add(ptr, 0x100), apk1Off, 96)              // apk1 direct from struct
            calldatacopy(add(ptr, 0x160), apk2, 192)         // apk2
            mstore8(add(ptr, 0x220), 0x00)                          // I2OSP(48,2) high
            mstore8(add(ptr, 0x221), 0x30)                          // I2OSP(48,2) low
            mstore8(add(ptr, 0x222), 0x00)                          // I2OSP(0,1)
            mstore8(add(ptr, 0x223), 0x00)                          // DST_prime

            // b0 = SHA256(msg_prime)
            let hashOut := add(ptr, 0x300)
            if iszero(staticcall(gas(), sha2, ptr, 0x224, hashOut, 0x20)) { revert(0, 0) }
            let b0 := mload(hashOut)

            // b1 = SHA256(b0 ‖ 0x01 ‖ 0x00)
            mstore(ptr, b0)
            mstore8(add(ptr, 0x20), 0x01)
            mstore8(add(ptr, 0x21), 0x00)
            if iszero(staticcall(gas(), sha2, ptr, 0x22, hashOut, 0x20)) { revert(0, 0) }
            let b1 := mload(hashOut)

            // b2 = SHA256((b0 ⊕ b1) ‖ 0x02 ‖ 0x00)
            mstore(ptr, xor(b0, b1))
            mstore8(add(ptr, 0x20), 0x02)
            mstore8(add(ptr, 0x21), 0x00)
            if iszero(staticcall(gas(), sha2, ptr, 0x22, hashOut, 0x20)) { revert(0, 0) }
            let b2 := mload(hashOut)

            // t = (b1 × 2¹²⁸ + b2>>128) mod r
            let t := addmod(
                mulmod(b1, 0x100000000000000000000000000000000, R_MOD),
                shr(128, b2),
                R_MOD
            )

            // ═══════════════════════════════════════════════════════════
            // Phase 2: pairing check
            // ═══════════════════════════════════════════════════════════

            // Write -g₂ into pairing buffer [0x080..0x17F]
            mstore(add(ptr, 0x080), NEG_G2_GEN_X_0_HI)
            mstore(add(ptr, 0x0A0), NEG_G2_GEN_X_0_LO)
            mstore(add(ptr, 0x0C0), NEG_G2_GEN_X_1_HI)
            mstore(add(ptr, 0x0E0), NEG_G2_GEN_X_1_LO)
            mstore(add(ptr, 0x100), NEG_G2_GEN_Y_0_HI)
            mstore(add(ptr, 0x120), NEG_G2_GEN_Y_0_LO)
            mstore(add(ptr, 0x140), NEG_G2_GEN_Y_1_HI)
            mstore(add(ptr, 0x160), NEG_G2_GEN_Y_1_LO)

            // Pad apk₂ into pairing buffer [0x200..0x2FF]
            let apk2Off := apk2
            mstore(add(ptr, 0x200), 0)
            calldatacopy(add(ptr, 0x210), apk2Off, 48)
            mstore(add(ptr, 0x240), 0)
            calldatacopy(add(ptr, 0x250), add(apk2Off, 48), 48)
            mstore(add(ptr, 0x280), 0)
            calldatacopy(add(ptr, 0x290), add(apk2Off, 96), 48)
            mstore(add(ptr, 0x2C0), 0)
            calldatacopy(add(ptr, 0x2D0), add(apk2Off, 144), 48)

            // G1MSM(apk₁, t) → t·apk₁ — direct from calldata
            let msmIn := add(ptr, 0x300)
            mstore(msmIn, 0)
            calldatacopy(add(msmIn, 0x10), apk1Off, 48)
            mstore(add(msmIn, 0x40), 0)
            calldatacopy(add(msmIn, 0x50), add(apk1Off, 48), 48)
            mstore(add(msmIn, 0x80), t)

            let msmOut := add(ptr, 0x3A0)
            if iszero(staticcall(gas(), PRECOMPILE_BLS12_G1MSM, msmIn, 0xA0, msmOut, 0x80)) {
                revert(0, 0)
            }

            // G1ADD(signature, t·apk₁) → lhs at pairing [0x000]
            let addIn := add(ptr, 0x420)
            mstore(addIn, 0)
            calldatacopy(add(addIn, 0x10), signature, 48)
            mstore(add(addIn, 0x40), 0)
            calldatacopy(add(addIn, 0x50), add(signature, 48), 48)
            mcopy(add(addIn, 0x80), msmOut, 0x80)

            if iszero(staticcall(gas(), PRECOMPILE_BLS12_G1ADD, addIn, 0x100, ptr, 0x80)) {
                revert(0, 0)
            }

            // G1MSM(g₁, t) → t·g₁
            mstore(msmIn, G1_GEN_X_HI)
            mstore(add(msmIn, 0x20), G1_GEN_X_LO)
            mstore(add(msmIn, 0x40), G1_GEN_Y_HI)
            mstore(add(msmIn, 0x60), G1_GEN_Y_LO)
            mstore(add(msmIn, 0x80), t)

            if iszero(staticcall(gas(), PRECOMPILE_BLS12_G1MSM, msmIn, 0xA0, msmOut, 0x80)) {
                revert(0, 0)
            }

            // G1ADD(message, t·g₁) → rhs at pairing [0x180]
            mstore(addIn, 0)
            calldatacopy(add(addIn, 0x10), message, 48)
            mstore(add(addIn, 0x40), 0)
            calldatacopy(add(addIn, 0x50), add(message, 48), 48)
            mcopy(add(addIn, 0x80), msmOut, 0x80)

            if iszero(staticcall(gas(), PRECOMPILE_BLS12_G1ADD, addIn, 0x100, add(ptr, 0x180), 0x80)) {
                revert(0, 0)
            }

            // Pairing check — e(lhs, -g₂) · e(rhs, apk₂) = 1
            if iszero(staticcall(gas(), PRECOMPILE_BLS12_PAIRING, ptr, 0x300, add(ptr, 0x300), 0x20)) {
                revert(0, 0)
            }

            result := mload(add(ptr, 0x300))
        }
    }

    /// @dev Encode structured public inputs into the flat uint256[18] format
    ///      expected by the gnark verifier.
    function _encodePublicInputs(PublicInputs calldata inputs) internal view returns (uint256[18] memory out) {
        bytes32 s0 = SEED_0;
        bytes32 s1 = SEED_1;
        bytes32 s2 = SEED_2;

        assembly {
            let mask := 0xFFFFFFFFFFFFFFFF

            // --- Copy bitlist and commitment into out[0..5] ---
            calldatacopy(out, add(inputs, 32), 160) // bitlist (5*32) -> out[0..4]
            calldatacopy(add(out, 160), inputs, 32) // commitment -> out[5]

            // --- Build G1ADD input in scratch memory at `out + 576` ---
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

            // Seed point (padded EIP-2537 format)
            mstore(add(scratch, 16), s0)
            mstore(add(scratch, 48), s1)
            mstore(add(scratch, 64), 0)
            mstore(add(scratch, 80), shl(128, s1))
            mstore(add(scratch, 96), s2)

            // APK point from calldata (padded)
            let apkOff := add(inputs, 192)
            calldatacopy(add(scratch, 144), apkOff, 48)
            calldatacopy(add(scratch, 208), add(apkOff, 48), 48)

            // --- Call G1ADD precompile ---
            let res := add(scratch, 256)
            let ok := staticcall(gas(), PRECOMPILE_BLS12_G1ADD, scratch, 256, res, 128)
            if iszero(ok) {
                mstore(0, 0x55d4cbf9) // G1AddFailed()
                revert(28, 4)
            }

            // --- Decompose padded G1 result into 12 x 64-bit limbs ---
            let xHi := mload(add(res, 16))
            let xLo := mload(add(res, 32))
            mstore(add(out, 192), and(xLo, mask))
            mstore(add(out, 224), and(shr(64, xLo), mask))
            mstore(add(out, 256), and(shr(128, xLo), mask))
            mstore(add(out, 288), and(shr(192, xLo), mask))
            mstore(add(out, 320), and(shr(128, xHi), mask))
            mstore(add(out, 352), shr(192, xHi))

            let yHi := mload(add(res, 80))
            let yLo := mload(add(res, 96))
            mstore(add(out, 384), and(yLo, mask))
            mstore(add(out, 416), and(shr(64, yLo), mask))
            mstore(add(out, 448), and(shr(128, yLo), mask))
            mstore(add(out, 480), and(shr(192, yLo), mask))
            mstore(add(out, 512), and(shr(128, yHi), mask))
            mstore(add(out, 544), shr(192, yHi))
        }
    }
}
