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
//! 64-bit limbs — matching gnark's emulated `BLS12381Fp` limbs — and those limbs
//! are packed three at a time into `Fr` elements, giving two absorbed elements per
//! coordinate, in the order `X[0..2]` then `Y[0..2]` per point.
//!
//! Three 64-bit limbs occupy at most 192 bits, well under `Fr`'s 255, so the
//! packing never wraps and is injective — the commitment binds as tightly as
//! absorbing each limb separately, at a third of the compressions. See the
//! `LimbsPerElement` soundness note in `circuits/apk/apk.go`.

use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};

use crate::error::VerifierError;
use sha3::{Digest, Keccak256};
use std::sync::OnceLock;

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
	static KEYS: OnceLock<Vec<Vec<Fr>>> = OnceLock::new();
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
		keys
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

/// Number of 64-bit limbs packed into one `Fr` element. Must match
/// `apk.LimbsPerElement` in `circuits/apk/apk.go`.
const LIMBS_PER_ELEMENT: usize = 3;

/// Decompose a coordinate (`Fq`) into its six little-endian 64-bit limbs —
/// matching gnark's emulated `BLS12381Fp` limb layout — and pack them
/// `LIMBS_PER_ELEMENT` at a time into `Fr` elements as
/// `l[0] + l[1]·2^64 + l[2]·2^128`, least-significant limb first.
///
/// The packed value is built as a big-endian byte string of the limbs in
/// reverse order, which is that positional sum exactly; it is below 2^192 < r,
/// so `from_be_bytes_mod_order` performs no reduction.
#[inline]
fn coord_packed(c: Fq) -> [Fr; 2] {
	let limbs = c.into_bigint().0; // [u64; 6], little-endian, canonical (non-Montgomery)
	core::array::from_fn(|i| {
		let mut be = [0u8; 8 * LIMBS_PER_ELEMENT];
		for j in 0..LIMBS_PER_ELEMENT {
			// limb j sits at positional weight 2^(64*j), i.e. the j-th group of
			// 8 bytes from the end of the big-endian buffer.
			let start = 8 * (LIMBS_PER_ELEMENT - 1 - j);
			be[start..start + 8].copy_from_slice(&limbs[i * LIMBS_PER_ELEMENT + j].to_be_bytes());
		}
		Fr::from_be_bytes_mod_order(&be)
	})
}

/// Computes the Poseidon2 commitment over `points`, byte-identical to the gnark
/// circuit's `PublicKeysCommitment` public input (and to the Go reference
/// `apk.NativePublicKeysCommitment`).
///
/// Each point contributes four `Fr` blocks — the two packed halves of `X`
/// followed by the two of `Y`. The caller must supply the same point list the
/// circuit binds to (e.g. the full validator set in registration order, padded
/// to 1024 with the identity point).
///
/// # Soundness
///
/// Hashes coordinates verbatim with **no** curve or subgroup check. The circuit's
/// soundness needs every committed key in G1 (coset-seed argument in
/// `circuits/apk/apk.go`), so the caller must pass valid G1 points — e.g. from
/// ark's checked `deserialize_compressed`. Otherwise use
/// [`public_keys_commitment_checked`].
pub fn public_keys_commitment(points: &[G1Affine]) -> Fr {
	merkle_damgard(points.iter().flat_map(|p| {
		let x = coord_packed(p.x);
		let y = coord_packed(p.y);
		x.into_iter().chain(y)
	}))
}

/// [`public_keys_commitment`] with an explicit G1-membership guard on every
/// point.
///
/// Each point must be on the BLS12-381 curve and in the prime-order subgroup;
/// the identity point is accepted (it is the circuit's padding value for unused
/// validator slots). Returns [`VerifierError::PointNotOnCurve`] or
/// [`VerifierError::PointNotInSubgroup`] on the first point that fails.
///
/// Use this when deriving the trusted committee commitment `C` from points whose
/// provenance does not already guarantee G1 membership. The check is what ties
/// `C` to the circuit's soundness precondition; see the `# Soundness` note on
/// [`public_keys_commitment`].
pub fn public_keys_commitment_checked(points: &[G1Affine]) -> Result<Fr, VerifierError> {
	for p in points {
		if p.is_zero() {
			continue; // identity: valid padding, not on the affine curve
		}
		if !p.is_on_curve() {
			return Err(VerifierError::PointNotOnCurve);
		}
		if !p.is_in_correct_subgroup_assuming_on_curve() {
			return Err(VerifierError::PointNotInSubgroup);
		}
	}
	Ok(public_keys_commitment(points))
}

/// [`public_keys_commitment_bytes`] with the G1-membership guard of
/// [`public_keys_commitment_checked`].
pub fn public_keys_commitment_bytes_checked(
	points: &[G1Affine],
) -> Result<[u8; 32], VerifierError> {
	let fr = public_keys_commitment_checked(points)?;
	let mut out = [0u8; 32];
	let be = fr.into_bigint().to_bytes_be();
	out[32 - be.len()..].copy_from_slice(&be);
	Ok(out)
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
			"4df3ca8a29f6b37c04fefb167022ae638df17383caf668b718bf3b65aa320652"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(2))),
			"20b814b4a4cd0249ffee16a12c0e883eac49a18e91f104e0c777d7de9a797267"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(3))),
			"1d8d8ce5d1437ebe81c7a10c59d25ec6f53bffb9966d019f460157750a7a1cff"
		);
		assert_eq!(
			hex_be(public_keys_commitment(&k_times_generator(10))),
			"5f9529f2a793ad64450341a6ef732dc1e1b71ddcca7d83f3704ff5e637a4b3bd"
		);
	}

	#[test]
	fn commitment_bytes_helper_matches() {
		assert_eq!(
			hex::encode(public_keys_commitment_bytes(&k_times_generator(3))),
			"1d8d8ce5d1437ebe81c7a10c59d25ec6f53bffb9966d019f460157750a7a1cff"
		);
	}

	/// The packing must reproduce the positional sum `l0 + l1·2^64 + l2·2^128`
	/// over the coordinate's little-endian limbs, and stay below `Fr`'s modulus
	/// so it never wraps. This is what makes the encoding injective, and hence
	/// the commitment binding — see the `LimbsPerElement` note in
	/// `circuits/apk/apk.go`.
	#[test]
	fn coord_packing_is_positional_and_never_wraps() {
		let shift64 = Fr::from(2u64).pow([64]);

		for c in [G1Affine::generator().x, G1Affine::generator().y] {
			let limbs = c.into_bigint().0;
			let packed = coord_packed(c);
			assert_eq!(packed.len(), 6 / LIMBS_PER_ELEMENT);

			for (i, p) in packed.iter().enumerate() {
				// l0 + l1·2^64 + l2·2^128, evaluated in Fr. The true value is
				// below 2^192 < r, so Fr arithmetic agrees with the integers.
				let mut want = Fr::ZERO;
				for j in (0..LIMBS_PER_ELEMENT).rev() {
					want *= shift64;
					want += Fr::from(limbs[i * LIMBS_PER_ELEMENT + j]);
				}
				assert_eq!(*p, want, "packed[{i}]");

				// 192 bits < the 255-bit modulus: no reduction can have
				// occurred, so the encoding is injective.
				assert!(p.into_bigint().num_bits() <= 192, "packed[{i}] exceeds 192 bits");
			}
		}
	}

	/// An on-curve point outside the prime-order G1 subgroup, for the guard test.
	fn on_curve_not_in_subgroup() -> G1Affine {
		use ark_ff::{Field as _, One};
		let mut x = Fq::from(2u64);
		let four = Fq::from(4u64);
		for _ in 0..1000 {
			let rhs = x * x * x + four;
			if let Some(y) = rhs.sqrt() {
				let pt = G1Affine::new_unchecked(x, y);
				if pt.is_on_curve() && !pt.is_in_correct_subgroup_assuming_on_curve() {
					return pt;
				}
			}
			x += Fq::one();
		}
		panic!("could not construct on-curve non-subgroup point");
	}

	/// The checked wrapper accepts a valid G1 set (identity padding included) and
	/// agrees with the unchecked function on the digest.
	#[test]
	fn checked_accepts_valid_g1_and_matches_unchecked() {
		let mut pts = k_times_generator(3);
		pts.push(G1Affine::identity()); // padding is allowed
		let got = public_keys_commitment_checked(&pts).expect("valid G1 set rejected");
		assert_eq!(got, public_keys_commitment(&pts));
	}

	/// The checked wrapper rejects an on-curve point outside G1 — the case that
	/// would void the circuit's coset-seed soundness argument if committed.
	#[test]
	fn checked_rejects_non_subgroup_point() {
		let mut pts = k_times_generator(3);
		pts.insert(1, on_curve_not_in_subgroup());
		match public_keys_commitment_checked(&pts) {
			Err(VerifierError::PointNotInSubgroup) => {},
			other => panic!("expected PointNotInSubgroup, got {other:?}"),
		}
		// The bytes variant guards identically.
		assert!(matches!(
			public_keys_commitment_bytes_checked(&pts),
			Err(VerifierError::PointNotInSubgroup)
		));
	}

	/// The checked wrapper rejects an off-curve point.
	#[test]
	fn checked_rejects_off_curve_point() {
		let mut pts = k_times_generator(3);
		// (1, 1) is not on y^2 = x^3 + 4.
		pts.insert(1, G1Affine::new_unchecked(Fq::from(1u64), Fq::from(1u64)));
		match public_keys_commitment_checked(&pts) {
			Err(VerifierError::PointNotOnCurve) => {},
			other => panic!("expected PointNotOnCurve, got {other:?}"),
		}
	}
}
