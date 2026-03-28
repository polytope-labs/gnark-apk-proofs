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

import "forge-std/Test.sol";
import "../PlonkVerifier.sol";
import "../APKVerifier.sol";

contract VerifierGasTest is Test {
    /// BLS12-381 base field modulus p.
    uint256 constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    /// EIP-2537 G1ADD precompile
    uint256 constant PRECOMPILE_BLS12_G1ADD = 0x0b;

    PlonkVerifier plonkVerifier;
    APKVerifier apkVerifier;

    function setUp() public {
        plonkVerifier = new PlonkVerifier();
        apkVerifier = new APKVerifier(address(plonkVerifier));
    }

    function _loadRawInputs(bytes memory pubData) internal pure returns (uint256[30] memory input) {
        require(pubData.length == 960, "unexpected public input size");
        for (uint256 i = 0; i < 30; i++) {
            uint256 val;
            assembly {
                val := mload(add(pubData, add(32, mul(i, 32))))
            }
            input[i] = val;
        }
    }

    /// @dev Reconstruct a 48-byte big-endian Fp element from 6 little-endian 64-bit limbs.
    function _limbsToFpBytes(
        uint256[30] memory input,
        uint256 offset
    ) internal pure returns (bytes memory) {
        uint256 lo = input[offset]
            | (input[offset + 1] << 64)
            | (input[offset + 2] << 128)
            | (input[offset + 3] << 192);
        uint256 hi = input[offset + 4]
            | (input[offset + 5] << 64);

        bytes memory result = new bytes(48);
        assembly {
            mstore(add(result, 32), shl(128, hi))
            mstore(add(result, 48), lo)
        }
        return result;
    }

    /// @dev Build a 96-byte G1 point from X and Y limbs in the raw array.
    function _limbsToG1Bytes(
        uint256[30] memory input,
        uint256 xOffset
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            _limbsToFpBytes(input, xOffset),
            _limbsToFpBytes(input, xOffset + 6)
        );
    }

    /// @dev Subtract seed from expectedAPK using G1ADD with negated seed Y.
    ///      apk = expectedAPK + (-seed), where -seed has Y negated: Y' = p - Y.
    function _subtractSeed(
        bytes memory expectedAPK,
        bytes memory seed
    ) internal view returns (bytes memory) {
        // Negate seed: keep X, replace Y with p - Y
        bytes memory negSeed = new bytes(96);
        assembly {
            let src := add(seed, 32)
            let dst := add(negSeed, 32)
            // Copy X (48 bytes)
            mcopy(dst, src, 48)
        }

        // Load Y coordinate (48 bytes big-endian at offset 48)
        // Split into hi (top 16 bytes) and lo (bottom 32 bytes)
        uint256 yHi;
        uint256 yLo;
        assembly {
            let yPtr := add(add(seed, 32), 48) // start of Y in data
            yHi := shr(128, mload(yPtr))       // bytes[48..64] -> top 128 bits
            yLo := mload(add(yPtr, 16))         // bytes[64..96] -> bottom 256 bits
        }

        // p - y: subtract with borrow
        uint256 negLo;
        uint256 negHi;
        unchecked {
            negLo = P_LO - yLo;
            negHi = P_HI - yHi;
            if (yLo > P_LO) {
                negHi -= 1;
            }
        }

        // Write negated Y back (48 bytes at offset 48)
        assembly {
            let dst := add(add(negSeed, 32), 48)
            mstore(dst, shl(128, negHi))    // bytes[48..80]: negHi in top 16, zeros in bottom 16
            mstore(add(dst, 16), negLo)      // bytes[64..96]: negLo overwrites bottom 16 + next 16
        }

        // G1ADD(expectedAPK, -seed) using EIP-2537 padded format
        bytes memory input = new bytes(256);
        assembly {
            let ptr := add(input, 32)
            let ePtr := add(expectedAPK, 32)
            let nPtr := add(negSeed, 32)
            // expectedAPK padded: 16 zeros + X(48) + 16 zeros + Y(48)
            mcopy(add(ptr, 16), ePtr, 48)
            mcopy(add(ptr, 80), add(ePtr, 48), 48)
            // negSeed padded
            mcopy(add(ptr, 144), nPtr, 48)
            mcopy(add(ptr, 208), add(nPtr, 48), 48)
        }

        bytes memory padded = new bytes(128);
        bool success;
        assembly {
            success := staticcall(gas(), PRECOMPILE_BLS12_G1ADD, add(input, 32), 256, add(padded, 32), 128)
        }
        require(success, "G1ADD failed");

        // Convert 128-byte padded result back to 96-byte uncompressed
        bytes memory result = new bytes(96);
        assembly {
            let src := add(padded, 32)
            let dst := add(result, 32)
            mcopy(dst, add(src, 16), 48)
            mcopy(add(dst, 48), add(src, 80), 48)
        }
        return result;
    }

    function _buildStructuredInputs(
        uint256[30] memory raw
    ) internal view returns (APKVerifier.APKPublicInputs memory inputs) {
        for (uint256 i = 0; i < 5; i++) {
            inputs.bitlist[i] = raw[i];
        }
        inputs.seed = _limbsToG1Bytes(raw, 5);
        inputs.publicKeysCommitment = raw[17];

        // Recover apk = expectedAPK - seed
        bytes memory expectedAPK = _limbsToG1Bytes(raw, 18);
        inputs.apk = _subtractSeed(expectedAPK, inputs.seed);
    }

    function test_plonk_verify_raw() public {
        bytes memory proofData = vm.readFileBinary("contracts/test/fixtures/plonk_proof.bin");
        bytes memory pubData = vm.readFileBinary("contracts/test/fixtures/plonk_public.bin");
        uint256[30] memory input = _loadRawInputs(pubData);

        uint256 gasBefore = gasleft();
        bool success = plonkVerifier.Verify(proofData, input);
        uint256 gasUsed = gasBefore - gasleft();

        require(success, "PLONK verification failed");
        emit log_named_uint("PLONK verification gas (raw)", gasUsed);
    }

    function test_plonk_verify_wrapper() public {
        bytes memory proofData = vm.readFileBinary("contracts/test/fixtures/plonk_proof.bin");
        bytes memory pubData = vm.readFileBinary("contracts/test/fixtures/plonk_public.bin");
        uint256[30] memory raw = _loadRawInputs(pubData);
        APKVerifier.APKPublicInputs memory inputs = _buildStructuredInputs(raw);

        uint256 gasBefore = gasleft();
        apkVerifier.verify(proofData, inputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("PLONK verification gas (wrapper)", gasUsed);
    }

    function test_contract_sizes() public {
        emit log_named_uint("PLONK bytecode size", address(plonkVerifier).code.length);
        emit log_named_uint("APKVerifier bytecode size", address(apkVerifier).code.length);
    }
}
