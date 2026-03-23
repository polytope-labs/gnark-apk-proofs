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

// Package apk provides utilities for working with Aggregated Public Key proofs
package apk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
)

// APKProofCircuit represents a circuit for aggregating BLS G1 public keys
// and proving that a subset's aggregate matches an expected value.
//
// Rogue key attacks are prevented by requiring Proof of Possession at registration.
// The circuit binds to a known validator set via a Poseidon2 hash commitment
// over all public keys.
//
// See: "Accountable Light Client Systems for PoS Blockchains" (Ciobotaru et al.)
// https://eprint.iacr.org/2022/1205
type APKProofCircuit struct {
	// ============== Private Witness Variables ==============
	// Public keys in G1 (input points to be aggregated)
	PublicKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// ======= Public Inputs ========
	// Bitlist that encodes the participating public keys
	Bitlist [5]frontend.Variable `gnark:",public"`

	// Start point for the aggregation. Must be a point on the curve
	// but NOT in the G1 subgroup, to ensure incomplete addition formulas
	// are safe. See Section 4.1 of the paper.
	Seed sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`

	// Poseidon2 hash commitment to the validator public key set
	PublicKeysCommitment frontend.Variable `gnark:",public"`

	// Expected aggregate public key of participating validators: apk = Seed + Σ b_i * pk_i
	ExpectedAPK sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`
}

// Define defines the circuit constraints
func (circuit *APKProofCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}

	// Verify the public key commitment: H(pk_0.X.Limbs || pk_0.Y.Limbs || pk_1.X.Limbs || ... )
	hasher, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	for i := 0; i < 1024; i++ {
		hasher.Write(circuit.PublicKeys[i].X.Limbs...)
		hasher.Write(circuit.PublicKeys[i].Y.Limbs...)
	}
	api.AssertIsEqual(hasher.Sum(), circuit.PublicKeysCommitment)

	// Decompose bitlist into individual bits
	var bits []frontend.Variable
	for i := range len(circuit.Bitlist) {
		if i == 4 {
			subset := api.ToBinary(circuit.Bitlist[i], 24)
			bits = append(bits, subset...)
		} else {
			subset := api.ToBinary(circuit.Bitlist[i], 250)
			bits = append(bits, subset...)
		}
	}

	// Aggregate participating public keys: apk = Seed + Σ b_i * pk_i
	// Note: on-curve and subgroup checks are performed by validators at
	// registration time (conditional NP relation / PoP assumption).
	apk := &circuit.Seed
	for i := 0; i < 1024; i++ {
		temp := curve.AddUnified(apk, &circuit.PublicKeys[i])
		apk = curve.Select(bits[i], temp, apk)
	}

	curve.AssertIsEqual(apk, &circuit.ExpectedAPK)

	return nil
}
