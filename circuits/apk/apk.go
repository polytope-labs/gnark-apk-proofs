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
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
)

// LimbsPerElement is the number of emulated-field limbs packed into a single
// native (BLS12-381 Fr) field element before hashing.
//
// A BLS12381Fp coordinate is emulated as 6 limbs of 64 bits, so three limbs
// occupy at most 192 bits — well under the 255-bit native field. The packing
// l[0] + l[1]·2^64 + l[2]·2^128 therefore never wraps mod r and is injective on
// range-constrained limbs, so the commitment binds exactly as tightly as
// hashing each limb separately, at a third of the compressions.
//
// SOUNDNESS INVARIANT: injectivity depends on every limb being range-checked to
// 64 bits. That is supplied by the unconditional emulated point arithmetic in
// Define (curve.Add and the AssertIsDifferent guard preceding it) — gnark's
// emulated operations range-check their operands' limbs. Do not make those
// calls conditional on the participation bit. Without the range checks a prover
// could shift a limb by the native modulus r, leaving the packed value (and
// hence the digest) unchanged while altering the coordinate it represents,
// forging a public key under the committed validator set.
const LimbsPerElement = 3

// limbShifts are the positional weights 2^(64*i) used by the packing.
var limbShifts = [LimbsPerElement]*big.Int{
	big.NewInt(1),
	new(big.Int).Lsh(big.NewInt(1), 64),
	new(big.Int).Lsh(big.NewInt(1), 128),
}

// packLimbs folds limbs into ceil(len/LimbsPerElement) native field elements,
// least-significant limb first. Each output is a linear combination of witness
// variables, so it costs no constraints in PLONK.
//
// Its native counterpart is packLimbsNative; the two must stay in lockstep, and
// so must the Rust port in rust/verifier/src/commitment.rs.
func packLimbs(api frontend.API, limbs []frontend.Variable) []frontend.Variable {
	packed := make([]frontend.Variable, 0, (len(limbs)+LimbsPerElement-1)/LimbsPerElement)
	for i := 0; i < len(limbs); i += LimbsPerElement {
		acc := limbs[i]
		for j := 1; j < LimbsPerElement && i+j < len(limbs); j++ {
			acc = api.Add(acc, api.Mul(limbs[i+j], limbShifts[j]))
		}
		packed = append(packed, acc)
	}
	return packed
}

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
	// Shares the kvstore-cached Field instance that curve uses, so the limb
	// range checks below are not duplicated.
	baseApi, err := emulated.NewField[emulated.BLS12381Fp](api)
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
	//
	// Note that point validity is orthogonal to the x-collision guard below: a
	// perfectly valid, registered key can still share an x-coordinate with the
	// running accumulator, so ParseG1 does not subsume AssertIsDifferent.
	//
	// Each coordinate's 6 limbs are packed into 2 native field elements, so a
	// point costs 4 compressions instead of 12. The point arithmetic below must
	// stay unconditional — see the SOUNDNESS INVARIANT on LimbsPerElement.
	//
	// curve.Add is the incomplete chord formula: it computes
	//
	//	λ = (q.y - p.y) / (q.x - p.x)
	//
	// where the division is a prover-supplied hint bound by the constraint
	// λ·(q.x - p.x) = q.y - p.y. That constraint pins λ to a unique value only
	// while q.x ≠ p.x. If the accumulator ever shares an x-coordinate with the
	// key being added, it degenerates:
	//
	//   - apk = pk_i: both sides vanish, leaving λ·0 = 0, which every λ
	//     satisfies. λ becomes a free witness feeding x_r and y_r, letting a
	//     prover steer the accumulator to a point of their choosing and forge
	//     an aggregate. Intermediate points are never checked on-curve, so
	//     nothing downstream catches it.
	//   - apk = -pk_i: the constraint becomes λ·0 = -2y ≠ 0, unsatisfiable.
	//
	// The protocol seed does not cover this. It keeps the accumulator off the
	// point at infinity (Ciobotaru et al. §4.1), a different degeneracy, and
	// says nothing about a collision with the next key.
	//
	// AssertIsDifferent on the x-coordinates rules out both cases — they are
	// exactly the x-collision — and converts what would be a soundness risk
	// into a liveness one: a collision makes the circuit unprovable rather than
	// forgeable. Security therefore rests on the guard, not on an argument that
	// a prover cannot search bitlists for a subset whose accumulator collides
	// with a registered key.
	for i := range 1024 {
		hasher.Write(packLimbs(api, circuit.PublicKeys[i].X.Limbs)...)
		hasher.Write(packLimbs(api, circuit.PublicKeys[i].Y.Limbs)...)

		baseApi.AssertIsDifferent(&apk.X, &circuit.PublicKeys[i].X)
		temp := curve.Add(apk, &circuit.PublicKeys[i])
		apk = curve.Select(bits[i], temp, apk)
	}
	api.AssertIsEqual(hasher.Sum(), circuit.PublicKeysCommitment)
	curve.AssertIsEqual(apk, &circuit.ExpectedApk)

	return nil
}
