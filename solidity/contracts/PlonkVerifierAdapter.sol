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
import "./APKVerifier.sol";

/// @title PLONK adapter implementing IProofVerifier.
/// @dev Wraps the auto-generated PLONK verifier into the unified interface.
contract PlonkVerifierAdapter is IProofVerifier {
    PlonkVerifier public immutable inner;

    constructor(address _verifier) {
        inner = PlonkVerifier(_verifier);
    }

    function verifyProof(
        bytes calldata proof,
        uint256[30] memory publicInputs
    ) external view returns (bool) {
        return inner.Verify(proof, publicInputs);
    }
}
