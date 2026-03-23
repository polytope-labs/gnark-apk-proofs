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

import "./Groth16Verifier.sol";
import "./APKVerifier.sol";

/// @title Groth16 adapter implementing IProofVerifier.
/// @dev Wraps the auto-generated Groth16 verifier (which reverts on failure)
///      into the unified bool-returning interface.
contract Groth16VerifierAdapter is IProofVerifier {
    Verifier public immutable inner;

    constructor(address _verifier) {
        inner = Verifier(_verifier);
    }

    function verifyProof(
        bytes calldata proof,
        uint256[30] memory publicInputs
    ) external view returns (bool) {
        inner.verifyProof(proof, publicInputs);
        return true;
    }
}
