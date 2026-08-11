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

//! Poseidon2 commitment over a validator set's BLS12-381 G1 public keys —
//! byte-compatible with the gnark circuit's `PublicKeysCommitment` public input.
//!
//! The APK circuit (`circuits/apk`) binds the prover to a fixed validator set via
//! a Poseidon2 hash over all public keys. This module reproduces that hash on the
//! verifier side, so a caller can independently derive the `publicKeysCommitment`
//! argument of `ApkProof.verify` from a known set of keys, without invoking the
//! Go prover.
//!
//! It mirrors gnark-crypto's `ecc/bls12-381/fr/poseidon2` Merkle–Damgard hasher
//! (default parameters: width `t = 2`, `rF = 6` full rounds, `rP = 50` partial
//! rounds, S-box degree `d = 5`, zero IV) and the circuit's absorption order: each
//! G1 coordinate (a base-field `Fq` element) is decomposed into six little-endian
//! 64-bit limbs — matching gnark's emulated `BLS12381Fp` limbs — and each limb is
//! absorbed as one `Fr` element, in the order `X[0..6]` then `Y[0..6]` per point.

use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use sha3::{Digest, Keccak256};
use alloc::{boxed::Box, vec::Vec};
use once_cell::race::OnceBox;

// gnark-crypto default Poseidon2 parameters for BLS12-381 (compression / MD).
const WIDTH: usize = 2;
const FULL_ROUNDS: usize = 6;
const PARTIAL_ROUNDS: usize = 50;
// Seed string == gnark-crypto `Parameters.String()` for these parameters; the
// round keys are derived from it via a Keccak-256 chain (see `round_keys`).
const SEED: &str = "Poseidon2-BLS12_381[t=2,rF=6,rP=50,d=5]";

/// Round keys, derived deterministically from [`SEED`] via a Keccak-256 chain,
/// exactly reproducing gnark-crypto's `Parameters.initRC`: `rnd₀ = Keccak(seed)`,
/// `rndₖ₊₁ = Keccak(rndₖ)`, each key being `rnd mod r` (big-endian). Full rounds
/// carry `WIDTH` keys; partial rounds carry one (only lane 0 is keyed).
fn round_keys() -> &'static Vec<Vec<Fr>> {
	static KEYS: OnceBox<Vec<Vec<Fr>>> = OnceBox::new();
	KEYS.get_or_init(|| {
		let half_full = FULL_ROUNDS / 2;
		let total = FULL_ROUNDS + PARTIAL_ROUNDS;
		let mut rnd: [u8; 32] = Keccak256::digest(SEED.as_bytes()).into();
		let mut keys = Vec::with_capacity(total);
		for round in 0..total {
			let n =
				if round < half_full || round >= half_full + PARTIAL_ROUNDS { WIDTH } else { 1 };
			let mut row = Vec::with_capacity(n);
			for _ in 0..n {
				rnd = Keccak256::digest(rnd).into();
				row.push(Fr::from_be_bytes_mod_order(&rnd));
			}
			keys.push(row);
		}
		Box::new(keys)
	})
}

/// In-place x⁵ S-box.
#[inline]
fn sbox(x: &mut Fr) {
	let base = *x;
	x.square_in_place(); // x²
	x.square_in_place(); // x⁴
	*x *= base; // x⁵
}

/// External (full-round) MDS for t=2: `[[2,1],[1,2]]`.
#[inline]
fn mat_mul_external(s: &mut [Fr; WIDTH]) {
	let sum = s[0] + s[1];
	s[0] += sum;
	s[1] += sum;
}

/// Internal (partial-round) matrix for t=2: `[[2,1],[1,3]]`.
#[inline]
fn mat_mul_internal(s: &mut [Fr; WIDTH]) {
	let sum = s[0] + s[1];
	s[0] += sum;
	s[1].double_in_place();
	s[1] += sum;
}

/// The Poseidon2 permutation on a width-2 state.
fn permutation(state: &mut [Fr; WIDTH]) {
	let rk = round_keys();
	let half_full = FULL_ROUNDS / 2;
	let first_full = &rk[..half_full];
	let partial = &rk[half_full..half_full + PARTIAL_ROUNDS];
	let last_full = &rk[half_full + PARTIAL_ROUNDS..];

	mat_mul_external(state);
	for keys in first_full {
		for (s, k) in state.iter_mut().zip(keys) {
			*s += *k;
		}
		for s in state.iter_mut() {
			sbox(s);
		}
		mat_mul_external(state);
	}
	for keys in partial {
		state[0] += keys[0];
		sbox(&mut state[0]);
		mat_mul_internal(state);
	}
	for keys in last_full {
		for (s, k) in state.iter_mut().zip(keys) {
			*s += *k;
		}
		for s in state.iter_mut() {
			sbox(s);
		}
		mat_mul_external(state);
	}
}

/// 2-to-1 compression with feed-forward on the right input, matching
/// gnark-crypto's `Permutation.Compress`: `right + permutation([left, right])[1]`.
#[inline]
fn compress(left: Fr, right: Fr) -> Fr {
	let mut s = [left, right];
	permutation(&mut s);
	right + s[1]
}

/// Absorb a stream of field elements through the Merkle–Damgard construction with
/// a zero IV (gnark-crypto's `NewMerkleDamgardHasher` default), returning the
/// final state. No padding is performed: every absorbed limb is exactly one block,
/// so the input is always block-aligned (matching the gnark hasher's contract).
fn merkle_damgard<I: IntoIterator<Item = Fr>>(blocks: I) -> Fr {
	let mut state = Fr::ZERO;
	for block in blocks {
		state = compress(state, block);
	}
	state
}

/// Decompose a coordinate (`Fq`) into its six little-endian 64-bit limbs, each as
/// one `Fr` element — matching gnark's emulated `BLS12381Fp` limb layout.
#[inline]
fn coord_limbs(c: Fq) -> [Fr; 6] {
	let limbs = c.into_bigint().0; // [u64; 6], little-endian, canonical (non-Montgomery)
	core::array::from_fn(|i| Fr::from(limbs[i]))
}

/// Computes the Poseidon2 commitment over `points`, byte-identical to the gnark
/// circuit's `PublicKeysCommitment` public input (and to the Go reference
/// `apk.NativePublicKeysCommitment`).
///
/// Each point contributes twelve `Fr` blocks — the six little-endian 64-bit limbs
/// of `X` followed by the six of `Y`. The caller must supply the same point list
/// the circuit binds to (e.g. the full validator set in registration order, padded
/// to 1024 with the identity point).
pub fn public_keys_commitment(points: &[G1Affine]) -> Fr {
	merkle_damgard(points.iter().flat_map(|p| {
		let x = coord_limbs(p.x);
		let y = coord_limbs(p.y);
		x.into_iter().chain(y)
	}))
}

/// The commitment as a 32-byte big-endian value — i.e. the
/// `uint256 publicKeysCommitment` argument of `ApkProof.verify`.
pub fn public_keys_commitment_bytes(points: &[G1Affine]) -> [u8; 32] {
	let mut out = [0u8; 32];
	let be = public_keys_commitment(points).into_bigint().to_bytes_be();
	out[32 - be.len()..].copy_from_slice(&be);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_ec::{AffineRepr, CurveGroup};

	// Ground truth from `circuits/apk` — gnark-crypto Poseidon2 round keys and
	// `NativePublicKeysCommitment` digests over `k * G1::generator()` point sets,
	// as 32-byte big-endian hex. The same commitment vectors are locked Go-side by
	// `TestCommitmentVectors`; regenerate both together if the parameters change.

	fn hex_be(c: Fr) -> String {
		hex::encode(public_keys_commitment_bytes_of(c))
	}

	fn public_keys_commitment_bytes_of(c: Fr) -> [u8; 32] {
		let mut out = [0u8; 32];
		let be = c.into_bigint().to_bytes_be();
		out[32 - be.len()..].copy_from_slice(&be);
		out
	}

	fn k_times_generator(n: u64) -> Vec<G1Affine> {
		let g = G1Affine::generator();
		(1..=n).map(|k| (g * Fr::from(k)).into_affine()).collect()
	}

	#[test]
	fn round_keys_match_gnark_crypto() {
		let rk = round_keys();
		assert_eq!(
			hex_be(rk[0][0]),
			"30ad66715875b7f8f573a3fccb0239fe6f3835ecd52d8475ea97cf0515d8067b"
		);
		assert_eq!(
			hex_be(rk[0][1]),
			"5c3023f1195e979990cefb861e7c6dd5695b824302b4a36341231648572a331c"
		);
		// first partial round (single key)
		assert_eq!(
			hex_be(rk[3][0]),
			"53f2b48552da5bfb9f29407e07620c27ee8048729a867db40af6df6a44333b34"
		);
		// last full round, lane 1
		assert_eq!(
			hex_be(rk[55][1]),
			"6dc0d4ce6b24d2dc26e73435cf85aa6e9c093a5776d1a50dfe99aa162c6572b4"
		);
	}

	#[test]
	fn commitment_matches_gnark_native() {
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(1))),
			"3b14900f1cd55f300914ca5b4393f0fa6a777d5999963f9520b12a60204272e2"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(2))),
			"528fad7e07c1ec6db4ad009230329123e643e1629733d60d2b4eaa9e45dc5704"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(3))),
			"14bac0391b3646f28d9b0b6b64acca1c8c585ade555494ce189aa2e4b62e9977"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(10))),
			"4a401453041545fc28ebf4c3c2824f317d1c4a7b6bff644d6eb12d0edd1f64c5"
		);
	}

	#[test]
	fn commitment_bytes_helper_matches() {
		assert_eq!(
			hex::encode(public_keys_commitment_bytes(&k_times_generator(3))),
			"14bac0391b3646f28d9b0b6b64acca1c8c585ade555494ce189aa2e4b62e9977"
		);
	}
}
