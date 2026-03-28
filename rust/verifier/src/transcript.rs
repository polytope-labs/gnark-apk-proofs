// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Fiat-Shamir transcript matching gnark's PLONK Solidity verifier.
//!
//! gnark derives challenges via SHA256 over concatenated data with ASCII labels.
//! Each label is encoded as a uint256 (32 bytes, right-aligned big-endian ASCII).
//! The hash input starts at byte offset 0x1b (27) from the label — i.e. only the
//! last 5 bytes of the 32-byte label slot are included for 5-char labels.

use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha256};

use crate::{
	error::VerifierError,
	proof::{PlonkProof, VerifyingKey},
};

/// Challenges derived from the Fiat-Shamir transcript.
#[derive(Clone, Debug)]
pub struct Challenges {
	pub gamma: Fr,
	pub beta: Fr,
	pub alpha: Fr,
	pub zeta: Fr,
	pub gamma_kzg: Fr,
}

impl Challenges {
	/// Derive all challenges from the proof and verification key, matching gnark's
	/// Solidity verifier exactly.
	pub fn derive(
		proof: &PlonkProof,
		vk: &VerifyingKey,
		public_inputs: &[Fr],
	) -> Result<Self, VerifierError> {
		let gamma_unreduced = derive_gamma(proof, vk, public_inputs);
		let gamma = reduce_to_fr(&gamma_unreduced);

		let beta_unreduced = derive_beta(&gamma_unreduced);
		let beta = reduce_to_fr(&beta_unreduced);

		let alpha_unreduced = derive_alpha(proof, &beta_unreduced);
		let alpha = reduce_to_fr(&alpha_unreduced);

		derive_zeta_and_return(proof, vk, public_inputs, gamma, beta, alpha, &alpha_unreduced)
	}
}

fn derive_zeta_and_return(
	proof: &PlonkProof,
	_vk: &VerifyingKey,
	_public_inputs: &[Fr],
	gamma: Fr,
	beta: Fr,
	alpha: Fr,
	alpha_unreduced: &[u8; 32],
) -> Result<Challenges, VerifierError> {
	let zeta_unreduced = derive_zeta(proof, alpha_unreduced);
	let zeta = reduce_to_fr(&zeta_unreduced);

	// gamma_kzg depends on the linearised polynomial commitment, which requires
	// all prior challenges. We compute it during verification and set it later.
	// For now, return a placeholder that will be filled in by the verifier.
	Ok(Challenges {
		gamma,
		beta,
		alpha,
		zeta,
		gamma_kzg: Fr::from(0u64), // filled in during verification
	})
}

/// Derive gamma = SHA256("gamma" || VK_S1..S3 || VK_QL..QK || VK_QCP || PI || L,R,O) mod r
///
/// The hash preimage is tightly packed:
///   "gamma" (5 bytes) || 9 VK G1 points (9×96=864) || nb_qcp G1 points || PI (n×32) || LRO
/// (3×96=288)
fn derive_gamma(proof: &PlonkProof, vk: &VerifyingKey, public_inputs: &[Fr]) -> [u8; 32] {
	let mut preimage = Vec::new();

	// "gamma" as 5 ASCII bytes
	preimage.extend_from_slice(b"gamma");

	// VK commitments: S1, S2, S3, Ql, Qr, Qm, Qo, Qk
	for pt in &vk.s {
		push_g1_solidity(&mut preimage, pt);
	}
	push_g1_solidity(&mut preimage, &vk.ql);
	push_g1_solidity(&mut preimage, &vk.qr);
	push_g1_solidity(&mut preimage, &vk.qm);
	push_g1_solidity(&mut preimage, &vk.qo);
	push_g1_solidity(&mut preimage, &vk.qk);

	// QCP commitments
	for pt in &vk.qcp {
		push_g1_solidity(&mut preimage, pt);
	}

	// Public inputs (32 bytes each, big-endian)
	for pi in public_inputs {
		push_fr(&mut preimage, pi);
	}

	// Proof commitments L, R, O
	for pt in &proof.lro {
		push_g1_solidity(&mut preimage, pt);
	}

	sha256_hash(&preimage)
}

/// Derive beta = SHA256("beta" || gamma_unreduced) mod r
fn derive_beta(gamma_unreduced: &[u8; 32]) -> [u8; 32] {
	let mut preimage = Vec::new();
	preimage.extend_from_slice(b"beta");
	preimage.extend_from_slice(gamma_unreduced);
	sha256_hash(&preimage)
}

/// Derive alpha = SHA256("alpha" || beta_unreduced || BSB22_commitments || [Z]) mod r
fn derive_alpha(proof: &PlonkProof, beta_unreduced: &[u8; 32]) -> [u8; 32] {
	let mut preimage = Vec::new();
	preimage.extend_from_slice(b"alpha");
	preimage.extend_from_slice(beta_unreduced);

	// BSB22 commitments
	for pt in &proof.bsb22_commitments {
		push_g1_solidity(&mut preimage, pt);
	}

	// [Z] commitment
	push_g1_solidity(&mut preimage, &proof.z);

	sha256_hash(&preimage)
}

/// Derive zeta = SHA256("zeta" || alpha_unreduced || [H₀] || [H₁] || [H₂]) mod r
fn derive_zeta(proof: &PlonkProof, alpha_unreduced: &[u8; 32]) -> [u8; 32] {
	let mut preimage = Vec::new();
	preimage.extend_from_slice(b"zeta");
	preimage.extend_from_slice(alpha_unreduced);
	for pt in &proof.h {
		push_g1_solidity(&mut preimage, pt);
	}
	sha256_hash(&preimage)
}

/// Derive gamma_kzg = SHA256("gamma" || ζ || [lin_poly] || [L],[R],[O] || [S₁],[S₂]
///   || [QCP_i] || lin_poly(ζ) || L(ζ),R(ζ),O(ζ),S₁(ζ),S₂(ζ) || qcp_i(ζ) || Z(ωζ))
pub fn derive_gamma_kzg(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	zeta: &Fr,
	linearised_polynomial_commitment: &G1Affine,
	opening_linearised_polynomial_zeta: &Fr,
) -> Fr {
	let mut preimage = Vec::new();
	preimage.extend_from_slice(b"gamma");

	// ζ
	push_fr(&mut preimage, zeta);

	// [linearised polynomial] — serialized as 48-byte X || 48-byte Y (trimmed from
	// the 64-byte EIP-2537 format). In the Solidity verifier, the linearised poly
	// commitment is stored in STATE_LINEARISED_POLYNOMIAL as
	// [x_hi(16)||x_lo(32)||y_hi(16)||y_lo(32)], and only the 48-byte portions (offset+0x10 for
	// 0x30 bytes each) are hashed.
	push_g1_48byte(&mut preimage, linearised_polynomial_commitment);

	// [L], [R], [O] commitments from proof
	for pt in &proof.lro {
		push_g1_solidity(&mut preimage, pt);
	}

	// [S₁], [S₂] from VK
	push_g1_solidity(&mut preimage, &vk.s[0]);
	push_g1_solidity(&mut preimage, &vk.s[1]);

	// [QCP_i] from VK
	for pt in &vk.qcp {
		push_g1_solidity(&mut preimage, pt);
	}

	// Scalar evaluations
	push_fr(&mut preimage, opening_linearised_polynomial_zeta);
	push_fr(&mut preimage, &proof.l_at_zeta);
	push_fr(&mut preimage, &proof.r_at_zeta);
	push_fr(&mut preimage, &proof.o_at_zeta);
	push_fr(&mut preimage, &proof.s1_at_zeta);
	push_fr(&mut preimage, &proof.s2_at_zeta);

	// Custom gate evaluations
	for eval in &proof.qcp_evals {
		push_fr(&mut preimage, eval);
	}

	// Z(ωζ)
	push_fr(&mut preimage, &proof.z_shifted_eval);

	let hash = sha256_hash(&preimage);
	reduce_to_fr(&hash)
}

// ── Serialization helpers ────────────────────────────────────────────────────

/// Push a G1 point in gnark's 96-byte Solidity format: X(48 BE) || Y(48 BE).
fn push_g1_solidity(buf: &mut Vec<u8>, pt: &G1Affine) {
	if pt.is_zero() {
		buf.extend_from_slice(&[0u8; 96]);
		return;
	}
	let (x, y) = pt.xy().unwrap();
	push_fq(buf, &x);
	push_fq(buf, &y);
}

/// Push a G1 point as 48-byte X || 48-byte Y (no padding to 64 bytes).
/// This matches how the Solidity verifier hashes the linearised polynomial commitment:
/// it reads from STATE_LINEARISED_POLYNOMIAL + 0x10 for 0x30 bytes (X), then +0x50 for 0x30 (Y).
fn push_g1_48byte(buf: &mut Vec<u8>, pt: &G1Affine) {
	if pt.is_zero() {
		buf.extend_from_slice(&[0u8; 96]);
		return;
	}
	let (x, y) = pt.xy().unwrap();
	push_fq(buf, &x);
	push_fq(buf, &y);
}

/// Push an Fq element as 48 bytes big-endian.
fn push_fq(buf: &mut Vec<u8>, fq: &Fq) {
	let bigint = (*fq).into_bigint();
	let limbs: &[u64] = bigint.as_ref();
	// 6 limbs, most significant first
	for &limb in limbs.iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}

/// Push an Fr element as 32 bytes big-endian.
fn push_fr(buf: &mut Vec<u8>, fr: &Fr) {
	let bigint = (*fr).into_bigint();
	let limbs: &[u64] = bigint.as_ref();
	// 4 limbs, most significant first
	for &limb in limbs.iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(data);
	hasher.finalize().into()
}

/// Reduce a 32-byte SHA256 hash to an Fr element (mod r).
fn reduce_to_fr(hash: &[u8; 32]) -> Fr {
	Fr::from_be_bytes_mod_order(hash)
}

/// Hash-to-field for BSB22 commitments, matching gnark's expand_msg_xmd approach.
/// This is the `hash_fr` function from the Solidity verifier.
///
/// Input: a 96-byte G1 point (in Solidity encoding).
/// Output: an Fr element.
pub fn hash_fr_bsb22(point_bytes: &[u8; 96]) -> Fr {
	let dst = b"BSB22-Plonk";

	// Step 1: b0 = SHA256(0x00{64} || msg(96) || 0x00 || 0x30 || 0x00 || dst || dst_len)
	let mut preimage = Vec::with_capacity(64 + 96 + 3 + dst.len() + 1);
	preimage.extend_from_slice(&[0u8; 64]);
	preimage.extend_from_slice(point_bytes);
	preimage.push(0x00); // i2osp(0, 1)
	preimage.push(48); // L = 48 (HASH_FR_LEN_IN_BYTES)
	preimage.push(0x00); // i2osp(0, 1)
	preimage.extend_from_slice(dst);
	preimage.push(dst.len() as u8);

	let b0 = sha256_hash_vec(&preimage);

	// Step 2: b1 = SHA256(b0 || 0x01 || dst || dst_len)
	let mut preimage2 = Vec::with_capacity(32 + 1 + dst.len() + 1);
	preimage2.extend_from_slice(&b0);
	preimage2.push(0x01);
	preimage2.extend_from_slice(dst);
	preimage2.push(dst.len() as u8);

	let b1 = sha256_hash_vec(&preimage2);

	// Step 3: b2 = SHA256((b0 ^ b1) || 0x02 || dst || dst_len)
	let mut xored = [0u8; 32];
	for i in 0..32 {
		xored[i] = b0[i] ^ b1[i];
	}
	let mut preimage3 = Vec::with_capacity(32 + 1 + dst.len() + 1);
	preimage3.extend_from_slice(&xored);
	preimage3.push(0x02);
	preimage3.extend_from_slice(dst);
	preimage3.push(dst.len() as u8);

	let b2 = sha256_hash_vec(&preimage3);

	// Result = (b1 * 2^128 + b2[0..16]) mod r
	// b1 is 32 bytes, b2 first 16 bytes give the remaining 128 bits for a 48-byte field element.
	let b1_val = u256_from_be(&b1);
	let b2_hi = u128_from_be(&b2[..16]);

	// res = mulmod(b1_as_u256, 2^128, r) + b2_hi mod r
	let bb = Fr::from(2u64).pow([128]);
	let b1_fr = reduce_u256_to_fr(b1_val);
	let b2_fr = reduce_u128_to_fr(b2_hi);

	b1_fr * bb + b2_fr
}

fn sha256_hash_vec(data: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(data);
	hasher.finalize().into()
}

fn u256_from_be(bytes: &[u8; 32]) -> [u64; 4] {
	let mut limbs = [0u64; 4];
	for i in 0..4 {
		let start = i * 8;
		let mut buf = [0u8; 8];
		buf.copy_from_slice(&bytes[start..start + 8]);
		limbs[3 - i] = u64::from_be_bytes(buf);
	}
	limbs
}

fn u128_from_be(bytes: &[u8]) -> u128 {
	let mut buf = [0u8; 16];
	buf.copy_from_slice(&bytes[..16]);
	u128::from_be_bytes(buf)
}

fn reduce_u256_to_fr(limbs: [u64; 4]) -> Fr {
	// Convert limbs to big-endian bytes and use proper mod reduction
	let mut bytes = [0u8; 32];
	for i in 0..4 {
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[3 - i].to_be_bytes());
	}
	Fr::from_be_bytes_mod_order(&bytes)
}

fn reduce_u128_to_fr(val: u128) -> Fr {
	let lo = val as u64;
	let hi = (val >> 64) as u64;
	Fr::from_bigint(ark_ff::BigInteger256::new([lo, hi, 0, 0])).expect("128-bit value fits in Fr")
}
