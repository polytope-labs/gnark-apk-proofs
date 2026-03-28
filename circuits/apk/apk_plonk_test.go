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
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"

	"github.com/polytope-labs/gnark-apk-proofs/circuits/srs"
)

func TestPlonkProveAndVerify(t *testing.T) {
	circuit := APKProofCircuit{}

	t.Log("Compiling circuit (SCS)...")
	startCompile := time.Now()
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	compileTime := time.Since(startCompile)
	assert.NoError(t, err, "Failed to compile circuit")
	t.Logf("Circuit compiled in %v. Constraints: %d", compileTime, cs.GetNbConstraints())

	t.Log("Loading KZG SRS...")
	startSRS := time.Now()
	kzgSrs, kzgSrsLag, err := srs.LoadDefault(23)
	srsTime := time.Since(startSRS)
	assert.NoError(t, err, "Failed to load SRS")
	t.Logf("SRS loaded in %v", srsTime)

	t.Log("Performing PLONK setup...")
	startSetup := time.Now()
	pk, vk, err := plonk.Setup(cs, kzgSrs, kzgSrsLag)
	setupTime := time.Since(startSetup)
	assert.NoError(t, err, "Failed to setup PLONK")
	t.Logf("PLONK setup completed in %v", setupTime)

	// Generate witness
	t.Log("Generating witness data...")
	startWitnessGen := time.Now()
	witness := GenerateWitness(WitnessConfig{
		NumParticipants: 10,
		UseRandom:       true,
		Seed:            42,
	})
	witnessGenTime := time.Since(startWitnessGen)
	t.Logf("Witness data generated in %v", witnessGenTime)

	t.Log("Creating witness...")
	startWitnessCreate := time.Now()
	fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
	witnessCreateTime := time.Since(startWitnessCreate)
	assert.NoError(t, err, "Failed to create witness")
	t.Logf("Witness created in %v", witnessCreateTime)

	t.Log("Generating PLONK proof...")
	startProve := time.Now()
	proof, err := plonk.Prove(cs, pk, fullWitness)
	proveTime := time.Since(startProve)
	assert.NoError(t, err, "Failed to generate proof")
	t.Logf("Proof generated in %v", proveTime)

	publicWitness, err := fullWitness.Public()
	assert.NoError(t, err, "Failed to extract public witness")

	t.Log("Verifying PLONK proof...")
	startVerify := time.Now()
	err = plonk.Verify(proof, vk, publicWitness)
	verifyTime := time.Since(startVerify)
	assert.NoError(t, err, "Proof verification failed")
	t.Logf("Proof verified in %v", verifyTime)

	t.Log("=== PLONK Performance Summary ===")
	t.Logf("Compile:    %v", compileTime)
	t.Logf("SRS Gen:    %v", srsTime)
	t.Logf("Setup:      %v", setupTime)
	t.Logf("Witness:    %v", witnessGenTime+witnessCreateTime)
	t.Logf("Prove:      %v", proveTime)
	t.Logf("Verify:     %v", verifyTime)
}
