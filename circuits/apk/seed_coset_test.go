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

// TestProtocolSeedOutsideSubgroup locks the coset invariant the circuit's
// soundness rests on: the seed is on E(Fp) but NOT in the prime-order subgroup
// G1. The circuit aggregates with the incomplete chord addition and has no
// in-circuit x-collision guard; the degenerate case acc = ±pk_i is excluded
// because the accumulator lives in the coset seed + G1, disjoint from G1 —
// which is only true while this test passes. See ProtocolSeed and
// Ciobotaru et al. (eprint 2022/1205, §5.1 Claim 2).
func TestProtocolSeedOutsideSubgroup(t *testing.T) {
	seed := ProtocolSeed()
	if !seed.IsOnCurve() {
		t.Fatal("protocol seed is not on E(Fp)")
	}
	if seed.IsInSubGroup() {
		t.Fatal("protocol seed is in G1: the coset argument excluding the incomplete-addition degeneracy is void")
	}
	if seed.IsInfinity() {
		t.Fatal("protocol seed is the point at infinity")
	}
}

// TestProtocolSeedVectors locks the seed coordinates as 48-byte big-endian hex.
// The same point is hardcoded in solidity/contracts/ApkProof.sol as
// SEED_0..SEED_2; if the derivation ever changes, both copies and these vectors
// must be regenerated together — silently diverging copies would make on-chain
// verification reject every proof.
func TestProtocolSeedVectors(t *testing.T) {
	const (
		wantX = "19742ffba069554d8cacceb8ed5514b2ecf72cd7372d3414203338f4fd3b3cc742fb160f8eb5818422246de186e0814a"
		wantY = "0e0f5d1199876e646952fb74d39e0b34042a8d48786adae7e0fccf4b0236c72e82343de94c9d12bf17d22bec9edbbe2b"
	)
	seed := ProtocolSeed()
	x := seed.X.Bytes()
	y := seed.Y.Bytes()
	if got := fmt.Sprintf("%x", x); got != wantX {
		t.Errorf("seed X:\n got  %s\n want %s", got, wantX)
	}
	if got := fmt.Sprintf("%x", y); got != wantY {
		t.Errorf("seed Y:\n got  %s\n want %s", got, wantY)
	}
}

// TestDegenerateAdditionUnsolvable documents what happens if a committed key
// nonetheless collided with the accumulator: the witness cannot be solved,
// because the in-circuit division hint hits a zero denominator. Such a witness
// cannot occur for G1 keys (the coset argument), so the test plants the seed
// itself as "key" 0 — a curve point outside G1 that ParseG1 would reject at the
// FFI boundary. This is a liveness observation, not the soundness argument; the
// soundness argument is TestProtocolSeedOutsideSubgroup.
func TestDegenerateAdditionUnsolvable(t *testing.T) {
	const numPoints = 1024

	_, _, g, _ := bls12381.Generators()
	seed := ProtocolSeed()

	points := make([]bls12381.G1Affine, numPoints)
	// Key 0 equals the initial accumulator: x-collision at i=0.
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
		t.Fatal("witness with an accumulator/key x-collision solved; expected the division hint to fail")
	}
}

// TestAggregationSolvesWithDistinctKeys is the positive control: a well-formed
// witness over G1 keys solves.
func TestAggregationSolvesWithDistinctKeys(t *testing.T) {
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
