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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"

	"github.com/polytope-labs/gnark-apk-proofs/circuits/srs"
)

// patchPlonkVerifier rewrites the generated PlonkVerifier.sol to use a
// fixed-size public inputs array (uint256[N]) instead of a dynamic one.
// The verifier already asserts the length at runtime via check_number_of_public_inputs,
// so this makes the guarantee compile-time and avoids the ABI length prefix.
func patchPlonkVerifier(path string, nbPublicInputs int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	src := string(data)

	fixed := fmt.Sprintf("uint256[%d]", nbPublicInputs)

	// 1. Change signature: uint256[] calldata -> uint256[N] calldata
	src = strings.Replace(src,
		"uint256[] calldata public_inputs",
		fixed+" calldata public_inputs", 1)

	// 2. Replace public_inputs.length with the constant (fixed arrays have no .length in assembly)
	src = strings.ReplaceAll(src, "public_inputs.length", "VK_NB_PUBLIC_INPUTS")

	// 3. Replace public_inputs.offset with public_inputs (bare name gives calldata offset for fixed arrays)
	src = strings.ReplaceAll(src, "public_inputs.offset", "public_inputs")

	return os.WriteFile(path, []byte(src), 0644)
}

func TestExportSolidityVerifierPlonk(t *testing.T) {
	circuit := ApkProofCircuit{}

	t.Log("Compiling circuit (SCS)...")
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(t, err, "Failed to compile circuit")
	t.Logf("Constraints: %d", cs.GetNbConstraints())

	t.Log("Loading KZG SRS...")
	startSRS := time.Now()
	kzgSrs, kzgSrsLagrange, err := srs.LoadDefault(23)
	srsTime := time.Since(startSRS)
	assert.NoError(t, err, "Failed to load SRS")
	t.Logf("SRS loaded in %v", srsTime)

	t.Log("Performing PLONK setup...")
	startSetup := time.Now()
	_, vk, err := plonk.Setup(cs, kzgSrs, kzgSrsLagrange)
	setupTime := time.Since(startSetup)
	assert.NoError(t, err, "Failed to setup PLONK")
	t.Logf("Setup completed in %v", setupTime)

	os.MkdirAll("../../solidity/contracts", 0755)

	outputPath := "../../solidity/contracts/PlonkVerifier.sol"
	t.Logf("Exporting PLONK Solidity verifier to %s...", outputPath)

	file, err := os.Create(outputPath)
	assert.NoError(t, err, "Failed to create Solidity file")

	err = vk.ExportSolidity(file)
	file.Close()
	assert.NoError(t, err, "Failed to export Solidity verifier")

	err = patchPlonkVerifier(outputPath, 18)
	assert.NoError(t, err, "Failed to patch PlonkVerifier")

	info, err := os.Stat(outputPath)
	assert.NoError(t, err)
	t.Logf("PLONK Solidity verifier exported (%d bytes)", info.Size())
}

// TestExportPlonkForFoundry generates a PLONK verifier contract and a matching
// proof + public inputs for use in Foundry gas benchmarks.
func TestExportPlonkForFoundry(t *testing.T) {
	circuit := ApkProofCircuit{}
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(t, err)
	t.Logf("SCS constraints: %d", cs.GetNbConstraints())

	kzgSrs, kzgSrsLag, err := srs.LoadDefault(23)
	assert.NoError(t, err)

	pk, vk, err := plonk.Setup(cs, kzgSrs, kzgSrsLag)
	assert.NoError(t, err)

	// Export verifier contract
	os.MkdirAll("../../solidity/contracts", 0755)
	f, err := os.Create("../../solidity/contracts/PlonkVerifier.sol")
	assert.NoError(t, err)
	err = vk.ExportSolidity(f)
	f.Close()
	assert.NoError(t, err)

	err = patchPlonkVerifier("../../solidity/contracts/PlonkVerifier.sol", 18)
	assert.NoError(t, err)
	t.Log("Exported PlonkVerifier.sol")

	// Generate proof
	wit := GenerateWitness(WitnessConfig{
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
