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
	"github.com/consensys/gnark/test"
)

// TestInCircuitCommitmentMatchesNative solves the full APK circuit against a
// witness whose PublicKeysCommitment comes from NativePublicKeysCommitment. The
// circuit asserts hasher.Sum() equals that input, so solving proves the
// in-circuit limb packing agrees with the native one. This is the regression
// guard for packLimbs / packLimbsNative drifting apart.
func TestInCircuitCommitmentMatchesNative(t *testing.T) {
	witness := GenerateWitness(WitnessConfig{
		NumParticipants: 600,
		UseRandom:       true,
		Seed:            42,
	})
	if err := test.IsSolved(&ApkProofCircuit{}, witness, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("circuit did not solve: %v", err)
	}
}

// TestPackLimbsNativeIsInjective checks the packing is a faithful positional
// encoding: three 64-bit limbs pack to exactly l0 + l1*2^64 + l2*2^128, which
// stays below the 255-bit native modulus and so never wraps. Injectivity on
// range-constrained limbs is what makes the packed commitment bind as tightly
// as hashing limbs individually.
func TestPackLimbsNativeIsInjective(t *testing.T) {
	maxLimb := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))

	// Saturated limbs: the largest value the packing can ever produce.
	all := [6]*big.Int{maxLimb, maxLimb, maxLimb, maxLimb, maxLimb, maxLimb}
	packed := packLimbsNative(all)
	if len(packed) != 2 {
		t.Fatalf("got %d packed elements, want 2", len(packed))
	}

	want := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(1))
	for i, p := range packed {
		if p.Cmp(want) != 0 {
			t.Errorf("packed[%d] = %x, want %x", i, p, want)
		}
	}

	// The saturated packing must stay below the native modulus, otherwise the
	// encoding would wrap and distinct limb vectors could collide.
	if want.Cmp(ecc.BLS12_381.ScalarField()) >= 0 {
		t.Fatal("packed element can exceed the native modulus: packing is not injective")
	}

	// Distinct limb vectors must give distinct packings, including the carry
	// boundary that a non-injective encoding would collapse.
	a := packLimbsNative([6]*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
	b := packLimbsNative([6]*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
	if a[0].Cmp(b[0]) == 0 {
		t.Error("distinct limb vectors packed to the same element")
	}
}
