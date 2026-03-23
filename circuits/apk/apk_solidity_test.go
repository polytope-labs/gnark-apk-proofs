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
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/assert"
)

func TestExportSolidityVerifierGroth16(t *testing.T) {
	circuit := APKProofCircuit{}

	t.Log("Compiling circuit (R1CS)...")
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(t, err, "Failed to compile circuit")
	t.Logf("Constraints: %d", cs.GetNbConstraints())

	t.Log("Performing trusted setup...")
	startSetup := time.Now()
	_, vk, err := groth16.Setup(cs)
	setupTime := time.Since(startSetup)
	assert.NoError(t, err, "Failed to setup Groth16")
	t.Logf("Setup completed in %v", setupTime)

	os.MkdirAll("../../solidity/contracts", 0755)

	outputPath := "../../solidity/contracts/Groth16Verifier.sol"
	t.Logf("Exporting Groth16 Solidity verifier to %s...", outputPath)

	file, err := os.Create(outputPath)
	assert.NoError(t, err, "Failed to create Solidity file")
	defer file.Close()

	err = vk.ExportSolidity(file)
	assert.NoError(t, err, "Failed to export Solidity verifier")

	info, err := os.Stat(outputPath)
	assert.NoError(t, err)
	t.Logf("Groth16 Solidity verifier exported (%d bytes)", info.Size())
}

func TestExportSolidityVerifierPlonk(t *testing.T) {
	circuit := APKProofCircuit{}

	t.Log("Compiling circuit (SCS)...")
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(t, err, "Failed to compile circuit")
	t.Logf("Constraints: %d", cs.GetNbConstraints())

	t.Log("Generating KZG SRS...")
	startSRS := time.Now()
	kzgSrs, kzgSrsLagrange, err := unsafekzg.NewSRS(cs)
	srsTime := time.Since(startSRS)
	assert.NoError(t, err, "Failed to generate SRS")
	t.Logf("SRS generated in %v", srsTime)

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
	defer file.Close()

	err = vk.ExportSolidity(file)
	assert.NoError(t, err, "Failed to export Solidity verifier")

	info, err := os.Stat(outputPath)
	assert.NoError(t, err)
	t.Logf("PLONK Solidity verifier exported (%d bytes)", info.Size())
}
