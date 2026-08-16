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
// 64 bits. That is supplied by the unconditional curve.Add in Define — its
// internal subtractions width-enforce both coordinates' limbs of both operands,
// so every PublicKeys[i].X/.Y limb absorbed by the hash is range-checked.
// Do not make that call conditional on the participation bit. Without the
// range checks a prover could shift a limb by the native modulus r, leaving the
// packed value (and hence the digest) unchanged while altering the coordinate
// it represents, forging a public key under the committed validator set.
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

// ProtocolSeed returns the fixed seed point for APK aggregation: a point on
// E(Fp) that is deliberately NOT in the prime-order subgroup G1.
//
// Derivation is deterministic: hash-to-field with domain separator
// "gnark-apk-proofs" and tag "apk-seed-coset", then the RFC 9380 SSWU map and
// isogeny onto E(Fp) — i.e. HashToG1 WITHOUT the final cofactor clearing. A
// uniformly mapped curve point lands in G1 with probability 1/cofactor
// (≈ 2^-125 for BLS12-381 G1), and non-membership is asserted below, so the
// seed provably lies in E(Fp) \ G1.
//
// Why outside the subgroup: the circuit aggregates with the incomplete chord
// addition, whose constraint degenerates when the two operands share an
// x-coordinate (acc = ±pk_i). Every registered public key is in G1 (enforced
// by ParseG1 at the FFI boundary and by PoP registration), so the accumulator
// seed + Σ pk_j lives in the coset seed + G1, which is DISJOINT from G1 —
// acc = ±pk_i is algebraically impossible, for participants and non-participants
// alike, and the accumulator can never reach the point at infinity. This is the
// construction of Ciobotaru et al. (https://eprint.iacr.org/2022/1205, §5.1,
// Claim 2), where the seed h ∈ E \ G1 makes the degenerate case unreachable
// with no in-circuit guard.
//
// The seed is a protocol constant, mirrored in solidity/contracts/ApkProof.sol
// (SEED_0..SEED_2); TestProtocolSeedVectors locks the coordinates. Changing the
// derivation is a protocol break: both copies and the locked vectors must be
// regenerated together.
func ProtocolSeed() bls12381.G1Affine {
	u, err := fp.Hash([]byte("gnark-apk-proofs"), []byte("apk-seed-coset"), 1)
	if err != nil {
		panic("failed to compute protocol seed: " + err.Error())
	}
	pt := bls12381.MapToCurve1(&u[0])
	// MapToCurve1 lands on the SSWU isogenous curve; apply the isogeny to get
	// onto E(Fp). Deliberately no ClearCofactor.
	hash_to_curve.G1Isogeny(&pt.X, &pt.Y)

	// Both properties are load-bearing for circuit soundness; the derivation is
	// deterministic, so these can only fire if the derivation itself changes.
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
	//
	// Each coordinate's 6 limbs are packed into 2 native field elements, so a
	// point costs 4 compressions instead of 12. curve.Add must stay
	// unconditional — see the SOUNDNESS INVARIANT on LimbsPerElement.
	//
	// curve.Add is the incomplete chord formula: it computes
	//
	//	λ = (q.y - p.y) / (q.x - p.x)
	//
	// where the division is a prover-supplied hint bound by the constraint
	// λ·(q.x - p.x) = q.y - p.y. That constraint pins λ to a unique value only
	// while q.x ≠ p.x — if the accumulator ever shared an x-coordinate with the
	// key being added (acc = ±pk_i), λ would become a free witness and a prover
	// could steer the accumulator to a point of their choosing.
	//
	// That degenerate case is unreachable BY CONSTRUCTION OF THE SEED: the
	// accumulator starts at ProtocolSeed() ∈ E(Fp) \ G1 and every added key is
	// in G1, so each partial sum lives in the coset seed + G1, which is disjoint
	// from G1. Points sharing an x-coordinate are exactly ±each other, so
	// acc = ±pk_i would put a coset element inside G1 — impossible. The same
	// argument keeps the accumulator off the point at infinity (acc = -pk_i is
	// the only route there). This is Ciobotaru et al.'s construction
	// (https://eprint.iacr.org/2022/1205, §5.1 Observation 3 / Claim 2), and it
	// holds for every one of the 1024 keys — participants and non-participants
	// alike, since Add runs unconditionally before the Select.
	//
	// SOUNDNESS DEPENDENCY: this argument leans on every COMMITTED key being in
	// G1. That is enforced where the commitment's key set enters the system —
	// ParseG1's subgroup check at the FFI boundary, backed by PoP registration.
	// The subgroup check is therefore load-bearing for the incomplete addition,
	// not merely for BLS key hygiene: committing a valid-curve point OUTSIDE G1
	// would void the coset argument and reopen the free-λ forgery. Do not weaken
	// ParseG1, and do not introduce a commitment path that bypasses it.
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
