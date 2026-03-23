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
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/stretchr/testify/assert"
)

// Groth16Harness encapsulates all components needed for Groth16 proving
type Groth16Harness struct {
	CS constraint.ConstraintSystem
	PK groth16.ProvingKey
	VK groth16.VerifyingKey
}

// SetupGroth16 compiles the circuit and performs trusted setup
func SetupGroth16(t *testing.T) (*Groth16Harness, error) {
	t.Log("Setting up Groth16 proving system...")

	circuit := APKProofCircuit{}

	t.Log("Compiling circuit...")
	startCompile := time.Now()
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	compileTime := time.Since(startCompile)
	if err != nil {
		return nil, err
	}
	t.Logf("Circuit compiled successfully in %v. Number of constraints: %d", compileTime, cs.GetNbConstraints())

	t.Log("Performing trusted setup (generating proving and verifying keys)...")
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(cs)
	setupTime := time.Since(startSetup)
	if err != nil {
		return nil, err
	}

	t.Logf("Trusted setup completed successfully in %v", setupTime)

	return &Groth16Harness{
		CS: cs,
		PK: pk,
		VK: vk,
	}, nil
}

// GenerateWitness creates a witness with random or specified participation
type WitnessConfig struct {
	NumParticipants int   // Number of participants (bits set)
	UseRandom       bool  // If true, randomly select participants
	SpecificIndices []int // If UseRandom is false, use these indices
	Seed            int64 // Random seed for reproducibility
}

func GenerateWitness(t *testing.T, config WitnessConfig) *APKProofCircuit {
	if config.Seed != 0 {
		rand.Seed(config.Seed)
	}

	numPoints := 1024

	_, _, G, _ := bls12381.Generators()

	var seed fr.Element
	seed.SetRandom()

	var init bls12381.G1Affine
	init.ScalarMultiplication(&G, seed.BigInt(new(big.Int)))

	points := make([]bls12381.G1Affine, numPoints)
	for i := range numPoints {
		var scalar fr.Element
		scalar.SetRandom()
		points[i].ScalarMultiplication(&G, scalar.BigInt(new(big.Int)))
	}

	var pubKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	var bitlist [5]frontend.Variable
	var participantIndices []int

	if config.UseRandom {
		bitlist, participantIndices = CreateBitlist(config.NumParticipants)
		t.Logf("Generated random bitlist with %d participants", config.NumParticipants)
	} else {
		bitlist = CreateBitlistFromIndices(config.SpecificIndices)
		participantIndices = config.SpecificIndices
		t.Logf("Generated bitlist with specific indices: %v", config.SpecificIndices)
	}

	participantSet := make(map[int]bool, len(participantIndices))
	for _, idx := range participantIndices {
		if idx >= 0 && idx < numPoints {
			participantSet[idx] = true
		}
	}

	// Compute expected APK: Seed + Σ b_i * pk_i
	expectedAPK := init
	for i := range numPoints {
		if participantSet[i] {
			expectedAPK.Add(&expectedAPK, &points[i])
		}
	}

	// Compute Poseidon2 commitment over all public keys
	commitment := NativePublicKeysCommitment(points)
	t.Logf("Public keys commitment: %s", commitment.String())

	return &APKProofCircuit{
		PublicKeys:          pubKeys,
		Bitlist:             bitlist,
		Seed:                sw_bls12381.NewG1Affine(init),
		PublicKeysCommitment: commitment,
		ExpectedAPK:         sw_bls12381.NewG1Affine(expectedAPK),
	}
}

// TestGroth16ProveAndVerify tests the full Groth16 pipeline
func TestGroth16ProveAndVerify(t *testing.T) {
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	testCases := []struct {
		name   string
		config WitnessConfig
	}{
		{
			name: "Small participation (10 keys)",
			config: WitnessConfig{
				NumParticipants: 10,
				UseRandom:       true,
				Seed:            42,
			},
		},
		{
			name: "Medium participation (100 keys)",
			config: WitnessConfig{
				NumParticipants: 100,
				UseRandom:       true,
				Seed:            43,
			},
		},
		{
			name: "Large participation (500 keys)",
			config: WitnessConfig{
				NumParticipants: 500,
				UseRandom:       true,
				Seed:            44,
			},
		},
		{
			name: "Deterministic participation",
			config: WitnessConfig{
				UseRandom:       false,
				SpecificIndices: []int{0, 10, 100, 500, 1000, 1023},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Generating witness data...")
			startWitnessGen := time.Now()
			witness := GenerateWitness(t, tc.config)
			witnessGenTime := time.Since(startWitnessGen)
			t.Logf("Witness data generated in %v", witnessGenTime)

			t.Log("Creating witness...")
			startWitnessCreate := time.Now()
			fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
			witnessCreateTime := time.Since(startWitnessCreate)
			assert.NoError(t, err, "Failed to create witness")
			t.Logf("Witness created in %v", witnessCreateTime)

			t.Log("Generating proof...")
			startProve := time.Now()
			proof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
			proveTime := time.Since(startProve)
			assert.NoError(t, err, "Failed to generate proof")
			t.Logf("Proof generated in %v", proveTime)

			publicWitness, err := fullWitness.Public()
			assert.NoError(t, err, "Failed to extract public witness")

			t.Log("Verifying proof...")
			startVerify := time.Now()
			err = groth16.Verify(proof, harness.VK, publicWitness)
			verifyTime := time.Since(startVerify)
			assert.NoError(t, err, "Proof verification failed")
			t.Logf("Proof verified successfully in %v", verifyTime)
		})
	}
}

// TestGroth16InvalidProof tests that invalid proofs are rejected
func TestGroth16InvalidProof(t *testing.T) {
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	t.Log("Generating witness data for valid proof...")
	witness := GenerateWitness(t, WitnessConfig{
		NumParticipants: 50,
		UseRandom:       true,
		Seed:            123,
	})

	fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err, "Failed to create witness")

	t.Log("Generating valid proof...")
	startProve := time.Now()
	validProof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
	proveTime := time.Since(startProve)
	assert.NoError(t, err, "Failed to generate proof")
	t.Logf("Valid proof generated in %v", proveTime)

	t.Log("Generating different witness data for invalid proof test...")
	differentWitness := GenerateWitness(t, WitnessConfig{
		NumParticipants: 100,
		UseRandom:       true,
		Seed:            456,
	})

	differentFullWitness, err := frontend.NewWitness(differentWitness, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err, "Failed to create different witness")

	wrongPublicWitness, err := differentFullWitness.Public()
	assert.NoError(t, err, "Failed to extract wrong public witness")

	t.Log("Attempting to verify proof with wrong public inputs...")
	err = groth16.Verify(validProof, harness.VK, wrongPublicWitness)
	assert.Error(t, err, "Proof should not verify with wrong public inputs")
	t.Log("Invalid proof correctly rejected")
}

// TestGroth16EdgeCases tests edge cases like all bits set and no bits set
func TestGroth16EdgeCases(t *testing.T) {
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	testCases := []struct {
		name   string
		config WitnessConfig
	}{
		{
			name: "No participants (only seed)",
			config: WitnessConfig{
				NumParticipants: 0,
				UseRandom:       true,
			},
		},
		{
			name: "All participants (1024 keys)",
			config: WitnessConfig{
				NumParticipants: 1024,
				UseRandom:       false,
				SpecificIndices: func() []int {
					indices := make([]int, 1024)
					for i := range indices {
						indices[i] = i
					}
					return indices
				}(),
			},
		},
		{
			name: "Single participant",
			config: WitnessConfig{
				UseRandom:       false,
				SpecificIndices: []int{512},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Generating witness data...")
			startWitnessGen := time.Now()
			witness := GenerateWitness(t, tc.config)
			witnessGenTime := time.Since(startWitnessGen)
			t.Logf("Witness data generated in %v", witnessGenTime)

			t.Log("Creating witness...")
			startWitnessCreate := time.Now()
			fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
			witnessCreateTime := time.Since(startWitnessCreate)
			assert.NoError(t, err, "Failed to create witness")
			t.Logf("Witness created in %v", witnessCreateTime)

			proof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
			assert.NoError(t, err, "Failed to generate proof")

			publicWitness, err := fullWitness.Public()
			assert.NoError(t, err, "Failed to extract public witness")

			err = groth16.Verify(proof, harness.VK, publicWitness)
			assert.NoError(t, err, "Proof verification failed")

			t.Log("Edge case proof verified successfully")
		})
	}
}
