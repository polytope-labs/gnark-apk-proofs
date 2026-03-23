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
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

// TestExportGroth16ForFoundry generates a Groth16 verifier contract and a matching
// proof + public inputs for use in Foundry gas benchmarks.
func TestExportGroth16ForFoundry(t *testing.T) {
	circuit := APKProofCircuit{}
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(t, err)
	t.Logf("R1CS constraints: %d", cs.GetNbConstraints())

	pk, vk, err := groth16.Setup(cs)
	assert.NoError(t, err)

	// Export verifier contract
	os.MkdirAll("../../solidity/contracts", 0755)
	f, err := os.Create("../../solidity/contracts/Groth16Verifier.sol")
	assert.NoError(t, err)
	err = vk.ExportSolidity(f)
	f.Close()
	assert.NoError(t, err)
	t.Log("Exported Groth16Verifier.sol")

	// Generate proof
	wit := GenerateWitness(t, WitnessConfig{
		NumParticipants: 10,
		UseRandom:       true,
		Seed:            42,
	})
	fullWitness, err := frontend.NewWitness(wit, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err)

	// Use keccak256 for commitment hash to match the Solidity verifier
	proof, err := groth16.Prove(cs, pk, fullWitness,
		backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(t, err)

	// Verify proof in Go first (also with keccak256)
	pubWitness, err := fullWitness.Public()
	assert.NoError(t, err)
	err = groth16.Verify(proof, vk, pubWitness,
		backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(t, err, "Proof verification failed in Go")
	t.Log("Proof verified successfully in Go")

	// Export proof (Solidity format)
	solProof := proof.(interface{ MarshalSolidity() []byte })
	proofBytes := solProof.MarshalSolidity()

	// Export public inputs (strip 12-byte header)
	pubBytes, err := pubWitness.MarshalBinary()
	assert.NoError(t, err)
	t.Logf("Public witness binary header (first 12 bytes): %x", pubBytes[:12])
	pubBytes = pubBytes[12:]

	os.MkdirAll("../../solidity/contracts/test/fixtures", 0755)
	os.WriteFile("../../solidity/contracts/test/fixtures/groth16_proof.bin", proofBytes, 0644)
	os.WriteFile("../../solidity/contracts/test/fixtures/groth16_public.bin", pubBytes, 0644)

	t.Logf("Proof: %d bytes, Public inputs: %d bytes (%d uint256s)", len(proofBytes), len(pubBytes), len(pubBytes)/32)
}

// TestExportPlonkForFoundry generates a PLONK verifier contract and a matching
// proof + public inputs for use in Foundry gas benchmarks.
func TestExportPlonkForFoundry(t *testing.T) {
	circuit := APKProofCircuit{}
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(t, err)
	t.Logf("SCS constraints: %d", cs.GetNbConstraints())

	srs, srsLag, err := unsafekzg.NewSRS(cs)
	assert.NoError(t, err)

	pk, vk, err := plonk.Setup(cs, srs, srsLag)
	assert.NoError(t, err)

	// Export verifier contract
	os.MkdirAll("../../solidity/contracts", 0755)
	f, err := os.Create("../../solidity/contracts/PlonkVerifier.sol")
	assert.NoError(t, err)
	err = vk.ExportSolidity(f)
	f.Close()
	assert.NoError(t, err)
	t.Log("Exported PlonkVerifier.sol")

	// Generate proof
	wit := GenerateWitness(t, WitnessConfig{
		NumParticipants: 10,
		UseRandom:       true,
		Seed:            42,
	})
	fullWitness, err := frontend.NewWitness(wit, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err)

	proof, err := plonk.Prove(cs, pk, fullWitness)
	assert.NoError(t, err)

	// Export proof (Solidity format)
	solProof := proof.(interface{ MarshalSolidity() []byte })
	proofBytes := solProof.MarshalSolidity()

	// Export public inputs (strip 12-byte header)
	pubWitness, err := fullWitness.Public()
	assert.NoError(t, err)
	pubBytes, err := pubWitness.MarshalBinary()
	assert.NoError(t, err)
	pubBytes = pubBytes[12:]

	os.MkdirAll("../../solidity/contracts/test/fixtures", 0755)
	os.WriteFile("../../solidity/contracts/test/fixtures/plonk_proof.bin", proofBytes, 0644)
	os.WriteFile("../../solidity/contracts/test/fixtures/plonk_public.bin", pubBytes, 0644)

	t.Logf("Proof: %d bytes, Public inputs: %d bytes (%d uint256s)", len(proofBytes), len(pubBytes), len(pubBytes)/32)
}
