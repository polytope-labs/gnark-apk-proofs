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
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
)

// LimbsPerElement is how many 64-bit BLS12381Fp limbs are packed into one
// native Fr element before hashing. Three limbs span 192 bits < the 255-bit
// field, so the pack l[0] + l[1]·2^64 + l[2]·2^128 never wraps and is injective
// — one third the compressions, same binding strength.
//
// Injectivity requires each limb to be range-checked to 64 bits. That comes
// from the unconditional curve.Add in Define (its subtractions width-enforce
// both operands' limbs); do not make Add conditional on the participation bit,
// or an unchecked limb could be shifted by r to forge a key under the same
// commitment.
const LimbsPerElement = 3

// limbShifts are the positional weights 2^(64*i) used by the packing.
var limbShifts = [LimbsPerElement]*big.Int{
	big.NewInt(1),
	new(big.Int).Lsh(big.NewInt(1), 64),
	new(big.Int).Lsh(big.NewInt(1), 128),
}

// packLimbs folds limbs into native field elements, least-significant first.
// Each output is a linear combination, so it costs no constraints. Mirror of
// packLimbsNative and the Rust port in rust/verifier/src/commitment.rs — keep
// all three in lockstep.
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

// ProtocolSeed returns the fixed aggregation seed: a point on E(Fp) that is
// deliberately NOT in G1 (SSWU map + isogeny, without cofactor clearing).
//
// Placing the seed outside G1 is what makes the incomplete addition in Define
// sound: since every key is in G1, the accumulator seed + Σ pk stays in the
// coset seed + G1, disjoint from G1, so it can never collide with a key or
// reach infinity (Ciobotaru et al., eprint 2022/1205 §5.1). See Define.
//
// Protocol constant, mirrored in solidity/contracts/ApkProof.sol; the
// coordinates are locked by TestProtocolSeedVectors. Changing the derivation
// breaks compatibility — regenerate both copies and the vectors together.
func ProtocolSeed() bls12381.G1Affine {
	u, err := fp.Hash([]byte("gnark-apk-proofs"), []byte("apk-seed-coset"), 1)
	if err != nil {
		panic("failed to compute protocol seed: " + err.Error())
	}
	pt := bls12381.MapToCurve1(&u[0])
	hash_to_curve.G1Isogeny(&pt.X, &pt.Y) // onto E(Fp); no ClearCofactor
	if !pt.IsOnCurve() {
		panic("protocol seed is not on E(Fp)")
	}
	if pt.IsInSubGroup() {
		panic("protocol seed must not be in the G1 subgroup")
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
	// Decompose the bitlist into 1024 participation bits. The set is packed into
	// 5 limbs, little-endian: limbs 0..3 hold 250 bits each (indices 0..999),
	// limb 4 holds 24 (indices 1000..1023). ToBinary constrains each limb < 2^n,
	// rejecting out-of-range values. Witness builders must use this same mapping
	// (apk.CreateBitlistFromIndices).
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

	// Hash and aggregate the keys in one pass. Each coordinate's 6 limbs pack
	// into 2 Fr elements (4 compressions/point instead of 12); curve.Add is the
	// incomplete chord formula, valid only when the operands have distinct
	// x-coordinates. The seed's coset placement (see ProtocolSeed) guarantees
	// that for every key, so no in-circuit x-collision guard is needed. Add must
	// stay unconditional — it also supplies the limb range checks the packing
	// relies on (see LimbsPerElement).
	//
	// SOUNDNESS: the coset argument requires every committed key to be in G1.
	// The circuit does not (and cannot) check this — a malicious prover bypasses
	// the honest-path FFI ParseG1. It holds because PublicKeysCommitment is a
	// trusted input fixed by chain consensus, and the binding commitment pins the
	// prover to those keys. Registration must subgroup-check keys (BLS
	// KeyValidate); a PoP alone does not, since the pairing ignores the cofactor
	// component. No subgroup-checked commitment ⇒ no soundness.
	for i := range 1024 {
		hasher.Write(packLimbs(api, circuit.PublicKeys[i].X.Limbs)...)
		hasher.Write(packLimbs(api, circuit.PublicKeys[i].Y.Limbs)...)

		temp := curve.Add(apk, &circuit.PublicKeys[i])
		apk = curve.Select(bits[i], temp, apk)
	}
	api.AssertIsEqual(hasher.Sum(), circuit.PublicKeysCommitment)
	curve.AssertIsEqual(apk, &circuit.ExpectedApk)

	return nil
}
