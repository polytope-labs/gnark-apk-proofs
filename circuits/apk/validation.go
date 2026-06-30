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

package apk

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// NumValidators is the fixed validator-set size of the APK circuit.
const NumValidators = 1024

// G1UncompressedSize is the byte length of a G1 point in the FFI/Solidity wire
// format: X (48 bytes big-endian) || Y (48 bytes big-endian).
const G1UncompressedSize = 96

// ParseG1 deserializes a single G1 point from the 96-byte FFI wire format
// (X || Y, big-endian) and validates it at the trust boundary.
//
// This is the first point at which untrusted public keys enter the system, so
// it is where cryptographic validity is enforced (audit findings 1, 3, 14):
//
//   - The all-zero encoding is the canonical point at infinity, used to pad the
//     validator set to NumValidators. It is accepted without curve checks,
//     matching the Rust prover's identity encoding (g1_to_gnark_bytes).
//   - Any other point must satisfy the curve equation y² = x³ + 4 and lie in the
//     prime-order subgroup. Proof of Possession at registration proves ownership
//     of the secret key but does NOT imply on-curve or subgroup membership —
//     those are independent algebraic checks enforced here.
func ParseG1(data []byte) (bls12381.G1Affine, error) {
	var pt bls12381.G1Affine
	if len(data) != G1UncompressedSize {
		return pt, fmt.Errorf("G1 point must be %d bytes, got %d", G1UncompressedSize, len(data))
	}

	// All-zero bytes denote the point at infinity (the zero value of G1Affine).
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return pt, nil
	}

	var x, y fp.Element
	x.SetBytes(data[0:48])
	y.SetBytes(data[48:96])
	pt.X = x
	pt.Y = y

	if !pt.IsOnCurve() {
		return pt, fmt.Errorf("G1 point not on curve")
	}
	if !pt.IsInSubGroup() {
		return pt, fmt.Errorf("G1 point not in prime-order subgroup")
	}
	return pt, nil
}

// ValidateParticipationIndices checks that every participation index is within
// [0, numKeys) and that there are no duplicates (audit findings 5, 12, 16).
//
// This is fail-loud input validation, not a soundness control. The circuit binds
// the key set via PublicKeysCommitment and exposes Bitlist/ExpectedApk as public
// inputs, so a malformed index list cannot make a verifier accept a wrong APK.
// And the bitlist and the aggregation set are derived from the same indices with
// the same range filter (and both are idempotent), so they cannot diverge or
// double-count. What this prevents is the prover *silently* building a proof for
// a different participation set than the caller intended: the previous helpers
// dropped out-of-range indices and collapsed duplicates without complaint.
func ValidateParticipationIndices(indices []int, numKeys int) error {
	seen := make(map[int]bool, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= numKeys {
			return fmt.Errorf("participant index %d out of range [0, %d)", idx, numKeys)
		}
		if seen[idx] {
			return fmt.Errorf("duplicate participant index %d", idx)
		}
		seen[idx] = true
	}
	return nil
}
