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
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
)

// ProtocolSeed returns the fixed seed point for APK aggregation.
// Computed deterministically via HashToG1 with domain separator "gnark-apk-proofs"
// and tag "apk-seed". The result is a point in the G1 subgroup.
//
// The seed ensures the running accumulator is never the point at infinity
// during aggregation. See Section 4.1 of "Accountable Light Client Systems
// for PoS Blockchains" (Ciobotaru et al., https://eprint.iacr.org/2022/1205).
func ProtocolSeed() bls12381.G1Affine {
	pt, err := bls12381.HashToG1([]byte("gnark-apk-proofs"), []byte("apk-seed"))
	if err != nil {
		panic("failed to compute protocol seed: " + err.Error())
	}
	return pt
}

// ApkProofCircuit represents a circuit for aggregating BLS G1 public keys
// and proving that a subset's aggregate matches an expected value.
//
// Rogue key attacks are prevented by requiring Proof of Possession at registration.
// The circuit binds to a known validator set via a Poseidon2 hash commitment
// over all public keys.
//
// See: "Accountable Light Client Systems for PoS Blockchains" (Ciobotaru et al.)
// https://eprint.iacr.org/2022/1205
type ApkProofCircuit struct {
	// ============== Private Witness Variables ==============
	// Public keys in G1 (input points to be aggregated)
	PublicKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// ======= Public Inputs ========
	// Bitlist that encodes the participating public keys
	Bitlist [5]frontend.Variable `gnark:",public"`

	// Poseidon2 hash commitment to the validator public key set
	PublicKeysCommitment frontend.Variable `gnark:",public"`

	// Expected aggregate public key of participating validators:
	//   expectedApk = ProtocolSeed() + Σ b_i * pk_i
	ExpectedApk sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`
}

// Define defines the circuit constraints
func (circuit *ApkProofCircuit) Define(api frontend.API) error {
	// Decompose the bitlist into 1024 individual participation bits.
	//
	// Bitlist encoding (audit finding 2): the 1024-bit participation set is packed
	// into 5 field-element limbs, little-endian within each limb:
	//   - Bitlist[0..3]: 250 bits each  -> indices 0..999
	//   - Bitlist[4]:    24 bits        -> indices 1000..1023
	// Bit i of limb k maps to validator index (k*250 + i) for k<4, and (1000 + i)
	// for k==4. api.ToBinary(x, n) constrains x < 2^n and enforces the canonical
	// bit decomposition, so out-of-range limb values are rejected in-circuit.
	// The Go/Rust witness builders MUST use this exact mapping
	// (see apk.CreateBitlistFromIndices); it is the single canonical source.
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

	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](
		api,
		sw_emulated.GetBLS12381Params(),
	)
	if err != nil {
		return err
	}
	hasher, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	seed := sw_bls12381.NewG1Affine(ProtocolSeed())
	apk := &seed

	// Hash public keys and aggregate in a single pass.
	//
	// On-curve and prime-order subgroup validity of every public key are enforced
	// outside the proving system, at the FFI trust boundary in apk.ParseG1 (audit
	// findings 1, 3, 14), and independently in the Rust prover before serialization
	// (finding 15). In-circuit subgroup checks over 1024 emulated BLS12-381 points
	// are prohibitively expensive and are intentionally not performed here; the
	// Poseidon2 commitment then binds the prover to exactly the validated key set.
	// Proof of Possession at registration covers secret-key ownership only — it is
	// a separate guarantee from the algebraic point validation done in ParseG1.
	for i := range 1024 {
		hasher.Write(circuit.PublicKeys[i].X.Limbs...)
		hasher.Write(circuit.PublicKeys[i].Y.Limbs...)

		temp := curve.AddUnified(apk, &circuit.PublicKeys[i])
		apk = curve.Select(bits[i], temp, apk)
	}
	api.AssertIsEqual(hasher.Sum(), circuit.PublicKeysCommitment)
	curve.AssertIsEqual(apk, &circuit.ExpectedApk)

	return nil
}
