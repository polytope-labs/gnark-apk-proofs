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

/// @title Unified proof verifier interface.
/// @dev Adapters for Groth16 and PLONK implement this so APKVerifier
///      can work with either backend interchangeably.
interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[30] memory publicInputs
    ) external view returns (bool);
}

/// @title APK Proof Verifier
/// @notice Human-readable wrapper around the auto-generated gnark verifiers.
/// @dev BLS12-381 G1 points are passed as 96-byte uncompressed serializations
///      (X: 48 bytes big-endian || Y: 48 bytes big-endian), matching the
///      standard gnark-crypto / EIP-2537 uncompressed G1 format.
contract APKVerifier {
    IProofVerifier public immutable verifier;

    error InvalidG1PointLength();
    error G1AddFailed();
    error ProofVerificationFailed();

    /// EIP-2537 BLS12-381 G1ADD precompile address.
    uint256 constant PRECOMPILE_BLS12_G1ADD = 0x0b;

    /// @notice Public inputs for the APK proof circuit.
    struct APKPublicInputs {
        /// Bitlist encoding participating validators (5 field elements).
        /// bitlist[0..3] encode 250 bits each, bitlist[4] encodes 24 bits.
        uint256[5] bitlist;
        /// Poseidon2 hash commitment over all 1024 validator public keys.
        uint256 publicKeysCommitment;
        /// Seed point for aggregation (must be on curve but NOT in G1 subgroup).
        /// 96 bytes: X (48 bytes big-endian) || Y (48 bytes big-endian).
        bytes seed;
        /// Aggregate public key of participating validators: apk = sum(b_i * pk_i).
        /// 96 bytes: X (48 bytes big-endian) || Y (48 bytes big-endian).
        /// Note: The circuit expects seed + apk; the contract adds the seed automatically.
        bytes apk;
    }

    constructor(address _verifier) {
        verifier = IProofVerifier(_verifier);
    }

    /// @notice Verify a proof of APK aggregation.
    /// @param proof The serialized proof bytes.
    /// @param inputs The structured public inputs.
    function verify(
        bytes calldata proof,
        APKPublicInputs calldata inputs
    ) external view {
        uint256[30] memory encoded = _encodePublicInputs(inputs);
        if (!verifier.verifyProof(proof, encoded)) {
            revert ProofVerificationFailed();
        }
    }

    /// @dev Encode structured public inputs into the flat uint256[30] format
    ///      expected by the gnark verifiers.
    ///
    ///      Layout (matching circuit witness serialization):
    ///        [0..4]   bitlist (5 elements)
    ///        [5..10]  seed.X limbs (6 x 64-bit, little-endian)
    ///        [11..16] seed.Y limbs (6 x 64-bit, little-endian)
    ///        [17]     publicKeysCommitment
    ///        [18..23] expectedAPK.X limbs (6 x 64-bit, little-endian)
    ///        [24..29] expectedAPK.Y limbs (6 x 64-bit, little-endian)
    function _encodePublicInputs(
        APKPublicInputs calldata inputs
    ) internal view returns (uint256[30] memory out) {
        // Bitlist
        for (uint256 i = 0; i < 5; i++) {
            out[i] = inputs.bitlist[i];
        }

        // Seed G1 point (96 bytes -> 12 limbs)
        _g1BytesToLimbs(inputs.seed, out, 5);

        // Public keys commitment
        out[17] = inputs.publicKeysCommitment;

        // Compute expectedAPK = seed + apk via G1ADD precompile
        bytes memory expectedAPK = _g1Add(inputs.seed, inputs.apk);
        _g1PaddedToLimbs(expectedAPK, out, 18);
    }

    /// @dev Add two BLS12-381 G1 points using the EIP-2537 G1ADD precompile.
    /// @param a First G1 point (96 bytes uncompressed).
    /// @param b Second G1 point (96 bytes uncompressed).
    /// @return result The padded result (128 bytes: 64-byte X || 64-byte Y).
    function _g1Add(
        bytes calldata a,
        bytes calldata b
    ) internal view returns (bytes memory result) {
        if (a.length != 96 || b.length != 96) revert InvalidG1PointLength();

        // G1ADD input: two padded G1 points (128 bytes each) = 256 bytes
        // Padded format: 16 zero bytes || X (48 bytes) || 16 zero bytes || Y (48 bytes)
        bytes memory input = new bytes(256);
        assembly {
            let ptr := add(input, 32)
            // Point a: pad X
            calldatacopy(add(ptr, 16), a.offset, 48)
            // Point a: pad Y
            calldatacopy(add(ptr, 80), add(a.offset, 48), 48)
            // Point b: pad X
            calldatacopy(add(ptr, 144), b.offset, 48)
            // Point b: pad Y
            calldatacopy(add(ptr, 208), add(b.offset, 48), 48)
        }

        result = new bytes(128);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                PRECOMPILE_BLS12_G1ADD,
                add(input, 32),
                256,
                add(result, 32),
                128
            )
        }
        if (!success) revert G1AddFailed();
    }

    /// @dev Parse a 128-byte EIP-2537 padded G1 point into 12 x 64-bit limbs.
    ///      Padded format: [16 zero | X 48 bytes] [16 zero | Y 48 bytes]
    function _g1PaddedToLimbs(
        bytes memory point,
        uint256[30] memory out,
        uint256 offset
    ) internal pure {
        // X starts at byte 16, Y starts at byte 80
        _fpMemBytesToLimbs(point, 16, out, offset);
        _fpMemBytesToLimbs(point, 80, out, offset + 6);
    }

    /// @dev Parse a 96-byte uncompressed G1 point (calldata) into 12 x 64-bit limbs.
    function _g1BytesToLimbs(
        bytes calldata point,
        uint256[30] memory out,
        uint256 offset
    ) internal pure {
        if (point.length != 96) revert InvalidG1PointLength();
        _fpCalldataBytesToLimbs(point[0:48], out, offset);
        _fpCalldataBytesToLimbs(point[48:96], out, offset + 6);
    }

    /// @dev Convert a 48-byte big-endian Fp element (from calldata) into
    ///      6 x 64-bit limbs in little-endian order.
    function _fpCalldataBytesToLimbs(
        bytes calldata fp,
        uint256[30] memory out,
        uint256 offset
    ) internal pure {
        uint256 hi;
        uint256 lo;
        assembly {
            // hi = bytes[0..31]: bits[255..192]=bytes[0..8], bits[191..128]=bytes[8..16]
            hi := calldataload(fp.offset)
            // lo = bytes[16..47]: bits[255..192]=bytes[16..24], ..., bits[63..0]=bytes[40..48]
            lo := calldataload(add(fp.offset, 16))
        }
        out[offset]     = lo & 0xFFFFFFFFFFFFFFFF;
        out[offset + 1] = (lo >> 64) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 2] = (lo >> 128) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 3] = (lo >> 192) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 4] = (hi >> 128) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 5] = (hi >> 192) & 0xFFFFFFFFFFFFFFFF;
    }

    /// @dev Convert a 48-byte big-endian Fp element (from memory at given start offset)
    ///      into 6 x 64-bit limbs in little-endian order.
    function _fpMemBytesToLimbs(
        bytes memory data,
        uint256 start,
        uint256[30] memory out,
        uint256 offset
    ) internal pure {
        uint256 hi;
        uint256 lo;
        assembly {
            let ptr := add(add(data, 32), start)
            hi := mload(ptr)
            lo := mload(add(ptr, 16))
        }
        out[offset]     = lo & 0xFFFFFFFFFFFFFFFF;
        out[offset + 1] = (lo >> 64) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 2] = (lo >> 128) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 3] = (lo >> 192) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 4] = (hi >> 128) & 0xFFFFFFFFFFFFFFFF;
        out[offset + 5] = (hi >> 192) & 0xFFFFFFFFFFFFFFFF;
    }
}
