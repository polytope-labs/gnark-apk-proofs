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
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// createBitlist creates a bitlist array with a specified number of randomly set bits
func createBitlist(numBitsToSet int) ([5]frontend.Variable, []int) {
	bitlist := [5]frontend.Variable{}

	for i := range 5 {
		bitlist[i] = new(big.Int)
	}

	if numBitsToSet <= 0 || numBitsToSet > 1024 {
		return bitlist, []int{}
	}

	allIndices := make([]int, 1024)
	for i := range allIndices {
		allIndices[i] = i
	}

	for i := len(allIndices) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		allIndices[i], allIndices[j] = allIndices[j], allIndices[i]
	}

	selectedIndices := allIndices[:numBitsToSet]

	for _, idx := range selectedIndices {
		var elemIdx int
		var bitPos int

		if idx < 1000 {
			elemIdx = idx / 250
			bitPos = idx % 250
		} else {
			elemIdx = 4
			bitPos = idx - 1000
		}

		val := bitlist[elemIdx].(*big.Int)
		val.SetBit(val, bitPos, 1)
	}

	return bitlist, selectedIndices
}

// testSimpleAPKG1 creates a test case with naive public key aggregation (PoP assumed)
func testSimpleAPKG1(t *testing.T, numParticipants int) (circ, wit frontend.Circuit) {
	numPoints := 1024

	_, _, G, _ := bls12381.Generators()

	var seed fr.Element
	seed.SetRandom()

	var init bls12381.G1Affine
	init.ScalarMultiplication(&G, seed.BigInt(new(big.Int)))

	points := make([]bls12381.G1Affine, numPoints)
	scalars := make([]fr.Element, numPoints)

	for i := range numPoints {
		scalars[i].SetRandom()
		points[i].ScalarMultiplication(&G, scalars[i].BigInt(new(big.Int)))
	}

	var pubKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	bitlist, participantIndices := createBitlist(numParticipants)
	t.Logf("Simple test: %d participants randomly selected", numParticipants)

	participantSet := make(map[int]bool, len(participantIndices))
	for _, idx := range participantIndices {
		participantSet[idx] = true
	}

	// Compute expected APK: Seed + Σ b_i * pk_i
	expectedAPK := init
	for i := range numPoints {
		if participantSet[i] {
			expectedAPK.Add(&expectedAPK, &points[i])
		}
	}

	// Compute Poseidon2 commitment
	commitment := NativePublicKeysCommitment(points)

	circuit := APKProofCircuit{}
	witness := APKProofCircuit{
		PublicKeys:          pubKeys,
		Bitlist:             bitlist,
		PublicKeysCommitment: commitment,
		ExpectedAPK:         sw_bls12381.NewG1Affine(expectedAPK),
		Seed:                sw_bls12381.NewG1Affine(init),
	}

	return &circuit, &witness
}

// TestCircuitCompiles verifies the APK circuit compiles correctly.
func TestCircuitCompiles(t *testing.T) {
	circuit := &APKProofCircuit{}
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Circuit compilation failed: %v", err)
	}
	t.Logf("Circuit compiled successfully. Constraints: %d", cs.GetNbConstraints())
}

func TestSimpleBLSG1APKCircuit(t *testing.T) {
	circuit, witness := testSimpleAPKG1(t, 600)
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness),
		test.WithCurves(ecc.BLS12_381),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.NoSolidityChecks(),
	)
}

func TestAllBitsSetBLSG1APKCircuit(t *testing.T) {
	circuit, witness := testSimpleAPKG1(t, 1024)
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness),
		test.WithCurves(ecc.BLS12_381),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.NoSolidityChecks(),
	)
}

func TestNoBitsSetBLSG1APKCircuit(t *testing.T) {
	circuit, witness := testSimpleAPKG1(t, 0)
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness),
		test.WithCurves(ecc.BLS12_381),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.NoSolidityChecks(),
	)
}
