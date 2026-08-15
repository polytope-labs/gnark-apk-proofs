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
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// TestAddGuardRejectsXCollision checks that the AssertIsDifferent guard in
// Define rejects a witness in which the accumulator shares an x-coordinate with
// the key being added — the case where the incomplete chord formula degenerates
// and λ would otherwise become a free witness.
//
// The witness is valid in every other respect: the commitment is computed over
// the actual points, and the expected aggregate matches the participation set.
// Index 0 is deliberately *not* a participant, so the colliding addition is
// discarded by the Select. The guard is unconditional, so the circuit must
// still reject — which is the point, since the range checks and the guard both
// have to hold for every key, not only for participants.
//
// Note the guard is what makes this a constraint. An honest solver would also
// fail here, because the division hint cannot invert zero — but hints are
// prover-supplied, so hint behaviour binds nothing. Only the assertion does.
func TestAddGuardRejectsXCollision(t *testing.T) {
	const numPoints = 1024

	_, _, g, _ := bls12381.Generators()
	seed := ProtocolSeed()

	points := make([]bls12381.G1Affine, numPoints)
	// Index 0 collides with the initial accumulator value.
	points[0] = seed
	for i := 1; i < numPoints; i++ {
		var s fr.Element
		s.SetRandom()
		points[i].ScalarMultiplication(&g, s.BigInt(new(big.Int)))
	}

	indices := []int{5, 17, 300}
	bitlist := CreateBitlistFromIndices(indices)

	expectedApk := seed
	for _, idx := range indices {
		expectedApk.Add(&expectedApk, &points[idx])
	}

	var pubKeys [numPoints]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	witness := &ApkProofCircuit{
		PublicKeys:           pubKeys,
		Bitlist:              bitlist,
		PublicKeysCommitment: NativePublicKeysCommitment(points),
		ExpectedApk:          sw_bls12381.NewG1Affine(expectedApk),
	}

	if err := test.IsSolved(&ApkProofCircuit{}, witness, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("circuit solved despite an x-coordinate collision between the accumulator and a public key")
	}
}

// TestAddGuardAcceptsDistinctKeys is the positive control for the test above:
// the same construction with a non-colliding key at index 0 must solve.
func TestAddGuardAcceptsDistinctKeys(t *testing.T) {
	const numPoints = 1024

	_, _, g, _ := bls12381.Generators()
	seed := ProtocolSeed()

	points := make([]bls12381.G1Affine, numPoints)
	for i := range numPoints {
		var s fr.Element
		s.SetRandom()
		points[i].ScalarMultiplication(&g, s.BigInt(new(big.Int)))
	}

	indices := []int{5, 17, 300}
	bitlist := CreateBitlistFromIndices(indices)

	expectedApk := seed
	for _, idx := range indices {
		expectedApk.Add(&expectedApk, &points[idx])
	}

	var pubKeys [numPoints]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	witness := &ApkProofCircuit{
		PublicKeys:           pubKeys,
		Bitlist:              bitlist,
		PublicKeysCommitment: NativePublicKeysCommitment(points),
		ExpectedApk:          sw_bls12381.NewG1Affine(expectedApk),
	}

	if err := test.IsSolved(&ApkProofCircuit{}, witness, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("circuit did not solve: %v", err)
	}
}
