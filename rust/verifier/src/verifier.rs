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

//! PLONK verification algorithm for gnark BLS12-381 proofs.
//!
//! This is a direct translation of gnark's Solidity PLONK verifier into safe Rust
//! using arkworks BLS12-381 types.

use alloc::{format, vec, vec::Vec};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};

use crate::{
	error::VerifierError,
	proof::{PlonkProof, VerifyingKey},
	transcript::{self, Challenges},
};

/// Verify a gnark BLS12-381 PLONK proof.
pub fn verify(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	public_inputs: &[Fr],
) -> Result<(), VerifierError> {
	// ── Input validation ─────────────────────────────────────────────────
	if public_inputs.len() != vk.nb_public_variables as usize {
		return Err(VerifierError::InvalidPublicInputCount {
			expected: vk.nb_public_variables as usize,
			actual: public_inputs.len(),
		});
	}

	// Domain size must be a power of two — PLONK relies on it for the FFT/Lagrange
	// basis. A non-power-of-two would silently corrupt Lagrange computations
	// (audit finding 34).
	if vk.size == 0 || !vk.size.is_power_of_two() {
		return Err(VerifierError::InvalidVkFormat("domain size must be a power of 2"));
	}

	// The proof's custom-gate vectors must match the VK's expected count, and the
	// VK's commitment-constraint indexes must line up with its custom gates
	// (audit finding 27). Otherwise later MSM/folding loops would index past the
	// end or fold the wrong number of terms.
	if proof.qcp_evals.len() != vk.qcp.len() || proof.bsb22_commitments.len() != vk.qcp.len() {
		return Err(VerifierError::InvalidProofStructure(format!(
			"custom-gate count mismatch: qcp_evals={}, bsb22_commitments={}, vk.qcp={}",
			proof.qcp_evals.len(),
			proof.bsb22_commitments.len(),
			vk.qcp.len(),
		)));
	}
	if vk.commitment_constraint_indexes.len() != vk.qcp.len() {
		return Err(VerifierError::InvalidVkFormat(
			"commitment_constraint_indexes length must equal qcp length",
		));
	}

	// ── Derive challenges (γ, β, α, ζ) ──────────────────────────────────
	let mut challenges = Challenges::derive(proof, vk, public_inputs)?;

	let zeta = challenges.zeta;
	let n = vk.size;

	// ζⁿ - 1
	let zeta_power_n_minus_one = zeta.pow([n]) - Fr::one();

	// ── Public inputs contribution ───────────────────────────────────────
	let pi_contribution =
		compute_public_inputs_contribution(vk, public_inputs, &zeta, &zeta_power_n_minus_one)?;

	// BSB22 commit API public inputs contribution
	let pi_commit = compute_pi_commit(proof, vk, &zeta, &zeta_power_n_minus_one)?;
	let pi = pi_contribution + pi_commit;

	// ── α² · L₁(ζ) ──────────────────────────────────────────────────────
	let alpha_square_lagrange_0 = {
		let l1_zeta = lagrange_0_at_zeta(&zeta, &zeta_power_n_minus_one, &vk.size_inv);
		challenges.alpha * challenges.alpha * l1_zeta
	};

	// ── ζⁿ⁺² and ζ²⁽ⁿ⁺²⁾ (for quotient folding) ───────────────────────
	let n_plus_two = n + 2;
	let zeta_power_n_plus_two = zeta.pow([n_plus_two]);
	let zeta_power_n_plus_two_sq = zeta_power_n_plus_two * zeta_power_n_plus_two;
	// Multiply by -Zₕ(ζ) = -(ζⁿ-1)
	let neg_zh = -zeta_power_n_minus_one;
	let h1_coeff = zeta_power_n_plus_two * neg_zh;
	let h2_coeff = zeta_power_n_plus_two_sq * neg_zh;

	// ── Linearised polynomial commitment ─────────────────────────────────
	let (linearised_poly_commitment, opening_linearised_poly_zeta) = compute_linearised_polynomial(
		proof,
		vk,
		&challenges,
		&pi,
		&alpha_square_lagrange_0,
		&zeta_power_n_minus_one,
		&h1_coeff,
		&h2_coeff,
	)?;

	// ── gamma_kzg challenge ──────────────────────────────────────────────
	challenges.gamma_kzg = transcript::derive_gamma_kzg(
		proof,
		vk,
		&zeta,
		&linearised_poly_commitment,
		&opening_linearised_poly_zeta,
	);

	// ── Fold state (multi-opening) ───────────────────────────────────────
	let (folded_digests, folded_evals) = fold_state(
		proof,
		vk,
		&challenges,
		&linearised_poly_commitment,
		&opening_linearised_poly_zeta,
	)?;

	// ── Batch verify multi-point opening ─────────────────────────────────
	batch_verify_multi_points(proof, vk, &challenges, &folded_digests, &folded_evals)
}

/// Compute Σᵢ public_inputs[i] · Lᵢ(ζ)
fn compute_public_inputs_contribution(
	vk: &VerifyingKey,
	public_inputs: &[Fr],
	zeta: &Fr,
	zeta_power_n_minus_one: &Fr,
) -> Result<Fr, VerifierError> {
	let n = public_inputs.len();
	let lagranges =
		batch_compute_lagranges_at_z(zeta, zeta_power_n_minus_one, &vk.size_inv, &vk.generator, n);

	let mut result = Fr::zero();
	for (li, pi) in lagranges.iter().zip(public_inputs.iter()) {
		result += *li * pi;
	}
	Ok(result)
}

/// BSB22 custom gate public inputs contribution.
fn compute_pi_commit(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	zeta: &Fr,
	zeta_power_n_minus_one: &Fr,
) -> Result<Fr, VerifierError> {
	let mut pi_commit = Fr::zero();

	for (i, bsb_com) in proof.bsb22_commitments.iter().enumerate() {
		// hash_fr(bsb_commitment)
		let mut point_bytes = [0u8; 96];
		write_g1_solidity(&mut point_bytes, bsb_com);
		let h_fr = transcript::hash_fr_bsb22(&point_bytes);

		// Lagrange at index (nb_public_variables + commitment_constraint_index).
		// Bound-check against the domain size (audit finding 30): an out-of-range
		// index would select ω^idx outside the basis, wrapping around the
		// multiplicative group and using the wrong Lagrange element.
		let idx = vk.nb_public_variables + vk.commitment_constraint_indexes[i];
		if idx >= vk.size {
			return Err(VerifierError::LagrangeIndexOutOfRange { idx, size: vk.size });
		}
		let li = compute_ith_lagrange_at_z(
			zeta,
			zeta_power_n_minus_one,
			&vk.size_inv,
			&vk.generator,
			idx,
		);
		pi_commit += h_fr * li;
	}
	Ok(pi_commit)
}

/// L₁(ζ) = (1/n) · (ζⁿ - 1) / (ζ - 1)
fn lagrange_0_at_zeta(zeta: &Fr, zeta_power_n_minus_one: &Fr, size_inv: &Fr) -> Fr {
	let den = *zeta - Fr::one();
	let den_inv = den.inverse().expect("zeta should not equal 1");
	*zeta_power_n_minus_one * *size_inv * den_inv
}

/// Compute [L₀(z), L₁(z), ..., L_{n-1}(z)].
fn batch_compute_lagranges_at_z(
	z: &Fr,
	zpnmo: &Fr,
	size_inv: &Fr,
	omega: &Fr,
	n: usize,
) -> Vec<Fr> {
	// L_i(z) = (ωⁱ/n) * (zⁿ-1) / (z - ωⁱ)
	// First compute (z - ωⁱ) for all i, then batch invert.
	let mut omega_powers = Vec::with_capacity(n);
	let mut denominators = Vec::with_capacity(n);
	let mut w = Fr::one();
	for _ in 0..n {
		denominators.push(*z - w);
		omega_powers.push(w);
		w *= omega;
	}

	// Batch invert
	batch_invert(&mut denominators);

	let zn = *zpnmo * *size_inv; // (zⁿ-1)/n
	let mut result = Vec::with_capacity(n);
	for (inv_den, wi) in denominators.iter().zip(omega_powers.iter()) {
		result.push(zn * *wi * *inv_den);
	}
	result
}

/// Compute Lᵢ(z) for a single index i.
fn compute_ith_lagrange_at_z(z: &Fr, zpnmo: &Fr, size_inv: &Fr, omega: &Fr, i: u64) -> Fr {
	let w_i = omega.pow([i]);
	let den = (*z - w_i).inverse().expect("z - omega^i should be nonzero");
	*zpnmo * *size_inv * w_i * den
}

/// Montgomery trick batch inversion in-place.
fn batch_invert(values: &mut [Fr]) {
	if values.is_empty() {
		return;
	}
	let n = values.len();

	// Compute prefix products
	let mut prefix = Vec::with_capacity(n);
	let mut acc = Fr::one();
	for v in values.iter() {
		acc *= v;
		prefix.push(acc);
	}

	// Invert the product
	let mut inv = acc.inverse().expect("batch invert: product is zero");

	// Sweep backwards
	for i in (0..n).rev() {
		let tmp = values[i];
		if i > 0 {
			values[i] = inv * prefix[i - 1];
		} else {
			values[i] = inv;
		}
		inv *= tmp;
	}
}

/// Compute the commitment to the linearised polynomial and its evaluation at ζ.
///
/// Returns ([lin_poly], lin_poly(ζ)).
#[allow(clippy::too_many_arguments)]
fn compute_linearised_polynomial(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	challenges: &Challenges,
	pi: &Fr,
	alpha_square_lagrange_0: &Fr,
	zeta_power_n_minus_one: &Fr,
	h1_coeff: &Fr,
	h2_coeff: &Fr,
) -> Result<(G1Affine, Fr), VerifierError> {
	let alpha = challenges.alpha;
	let beta = challenges.beta;
	let gamma = challenges.gamma;
	let zeta = challenges.zeta;

	let l_zeta = proof.l_at_zeta;
	let r_zeta = proof.r_at_zeta;
	let o_zeta = proof.o_at_zeta;
	let s1_zeta = proof.s1_at_zeta;
	let s2_zeta = proof.s2_at_zeta;
	let z_omega_zeta = proof.z_shifted_eval;

	// ── s1: α·Z(ωζ)·β·(l(ζ)+β·s₁(ζ)+γ)·(r(ζ)+β·s₂(ζ)+γ) ──────────
	let u = z_omega_zeta * beta;
	let v = beta * s1_zeta + l_zeta + gamma;
	let w = beta * s2_zeta + r_zeta + gamma;
	let s1_scalar = u * v * w * alpha;

	// ── coeff_z: -α·(l(ζ)+β·ζ+γ)·(r(ζ)+β·u·ζ+γ)·(o(ζ)+β·u²·ζ+γ) + α²·L₁(ζ) ──
	let coset_sq = vk.coset_shift * vk.coset_shift;
	let beta_zeta = beta * zeta;
	let u2 = beta_zeta + l_zeta + gamma;
	let v2 = beta_zeta * vk.coset_shift + r_zeta + gamma;
	let w2 = beta_zeta * coset_sq + o_zeta + gamma;
	let coeff_z = -(u2 * v2 * w2 * alpha) + *alpha_square_lagrange_0;

	// ── EC MSM for [linearised polynomial] ───────────────────────────────
	// Points: [Ql], [Qr], [Qm], [Qo], [Qk], [S3], [Z], [H0], [H1], [H2], [BSB22_i]
	// Scalars: l(ζ), r(ζ), l·r(ζ), o(ζ), 1, s1_scalar, coeff_z, -Zh, h1_coeff, h2_coeff, qcp_i(ζ)
	let neg_zh = -*zeta_power_n_minus_one;

	let mut bases: Vec<G1Affine> = Vec::with_capacity(10 + proof.bsb22_commitments.len());
	let mut scalars: Vec<Fr> = Vec::with_capacity(10 + proof.bsb22_commitments.len());

	bases.push(vk.ql);
	scalars.push(l_zeta);
	bases.push(vk.qr);
	scalars.push(r_zeta);
	bases.push(vk.qm);
	scalars.push(l_zeta * r_zeta);
	bases.push(vk.qo);
	scalars.push(o_zeta);
	bases.push(vk.qk);
	scalars.push(Fr::one());
	bases.push(vk.s[2]);
	scalars.push(s1_scalar);
	bases.push(proof.z);
	scalars.push(coeff_z);
	bases.push(proof.h[0]);
	scalars.push(neg_zh);
	bases.push(proof.h[1]);
	scalars.push(*h1_coeff);
	bases.push(proof.h[2]);
	scalars.push(*h2_coeff);

	for (i, bsb_com) in proof.bsb22_commitments.iter().enumerate() {
		bases.push(*bsb_com);
		scalars.push(proof.qcp_evals[i]);
	}

	let scalars_bigint: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();
	let lin_poly_commitment = G1Projective::msm_bigint(&bases, &scalars_bigint).into_affine();

	// ── Opening of linearised polynomial at ζ ────────────────────────────
	// = -[ PI(ζ) - α²·L₁(ζ) + α·(l+β·s1+γ)·(r+β·s2+γ)·(o+γ)·Z(ωζ) ]
	let s1_term = (l_zeta + beta * s1_zeta + gamma) *
		(r_zeta + beta * s2_zeta + gamma) *
		(o_zeta + gamma) *
		alpha * z_omega_zeta;

	let opening = -(s1_term + *pi - *alpha_square_lagrange_0);

	Ok((lin_poly_commitment, opening))
}

/// Fold the opening proofs at ζ into a single digest and evaluation.
fn fold_state(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	challenges: &Challenges,
	linearised_poly_commitment: &G1Affine,
	opening_linearised_poly_zeta: &Fr,
) -> Result<(G1Affine, Fr), VerifierError> {
	let gamma_kzg = challenges.gamma_kzg;
	let mut acc_gamma = gamma_kzg;

	// Folded evaluation: lin_poly(ζ) + γ·L(ζ) + γ²·R(ζ) + γ³·O(ζ) + γ⁴·S₁(ζ) + γ⁵·S₂(ζ) + Σ
	// γ^(5+i)·qcp_i(ζ)
	let mut folded_eval = *opening_linearised_poly_zeta;

	folded_eval += acc_gamma * proof.l_at_zeta;
	acc_gamma *= gamma_kzg;
	folded_eval += acc_gamma * proof.r_at_zeta;
	acc_gamma *= gamma_kzg;
	folded_eval += acc_gamma * proof.o_at_zeta;
	acc_gamma *= gamma_kzg;
	folded_eval += acc_gamma * proof.s1_at_zeta;
	acc_gamma *= gamma_kzg;
	folded_eval += acc_gamma * proof.s2_at_zeta;

	for qcp_eval in &proof.qcp_evals {
		acc_gamma *= gamma_kzg;
		folded_eval += acc_gamma * qcp_eval;
	}

	// Folded digest MSM: [lin_poly] + γ·[L] + γ²·[R] + γ³·[O] + γ⁴·[S₁] + γ⁵·[S₂] + Σ
	// γ^(5+i)·[QCP_i]
	let mut bases = Vec::with_capacity(6 + vk.qcp.len());
	let mut scalars = Vec::with_capacity(6 + vk.qcp.len());

	// lin_poly with scalar 1
	bases.push(*linearised_poly_commitment);
	scalars.push(Fr::one());

	let mut acc = gamma_kzg;
	bases.push(proof.lro[0]);
	scalars.push(acc);
	acc *= gamma_kzg;
	bases.push(proof.lro[1]);
	scalars.push(acc);
	acc *= gamma_kzg;
	bases.push(proof.lro[2]);
	scalars.push(acc);
	acc *= gamma_kzg;
	bases.push(vk.s[0]);
	scalars.push(acc);
	acc *= gamma_kzg;
	bases.push(vk.s[1]);
	scalars.push(acc);

	for qcp_com in &vk.qcp {
		acc *= gamma_kzg;
		bases.push(*qcp_com);
		scalars.push(acc);
	}

	let scalars_bigint: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();
	let folded_digest = G1Projective::msm_bigint(&bases, &scalars_bigint).into_affine();

	Ok((folded_digest, folded_eval))
}

/// Final pairing check for the batch multi-point opening.
fn batch_verify_multi_points(
	proof: &PlonkProof,
	vk: &VerifyingKey,
	challenges: &Challenges,
	folded_digests: &G1Affine,
	folded_evals: &Fr,
) -> Result<(), VerifierError> {
	let zeta = challenges.zeta;

	// Derive random scalar for batching the two opening proofs
	let random = derive_batch_random(proof, challenges, folded_digests)?;

	// Fold evaluations: folded_evals + random * Z(ωζ)
	let folded_eval_total = *folded_evals + random * proof.z_shifted_eval;

	// MSM for folded digests:
	//   [folded_digests] + random·[Z] + (-folded_eval_total)·G₁ + ζ·[W_ζ] + (random·ω·ζ)·[W_ζω]
	let zeta_omega = zeta * vk.generator;

	let bases = vec![*folded_digests, proof.z, vk.kzg_g1, proof.w_zeta, proof.w_zeta_omega];
	let scalars: Vec<Fr> = vec![Fr::one(), random, -folded_eval_total, zeta, random * zeta_omega];
	let scalars_bigint: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();
	let lhs_g1 = G1Projective::msm_bigint(&bases, &scalars_bigint).into_affine();

	// Folded quotients: -[W_ζ] + (-random)·[W_ζω]
	let folded_quotients = {
		let bases = vec![proof.w_zeta, proof.w_zeta_omega];
		let scalars = vec![(-Fr::one()).into_bigint(), (-random).into_bigint()];
		G1Projective::msm_bigint(&bases, &scalars).into_affine()
	};

	// Pairing check: e(lhs_g1, G2_SRS_0) · e(folded_quotients, G2_SRS_1) == 1
	let result = Bls12_381::multi_pairing([lhs_g1, folded_quotients], [vk.kzg_g2[0], vk.kzg_g2[1]]);

	if result.is_zero() {
		Ok(())
	} else {
		Err(VerifierError::ProofVerificationFailed)
	}
}

/// Derive the random scalar for batching the two KZG opening proofs.
///
/// The Solidity verifier hashes a 448-byte preimage where the folded_digests point
/// is in EIP-2537 128-byte format, but only the first 96 bytes survive an overlap
/// with W_zeta. The effective layout is:
///   [0*16 || X(48) || 0*16 || Y[0:16]] (96 bytes of folded_digests in EIP format)
///   || W_zeta (96 bytes) || Z (96 bytes) || W_zeta_omega (96 bytes)
///   || zeta (32 bytes) || gamma_kzg (32 bytes)
fn derive_batch_random(
	proof: &PlonkProof,
	challenges: &Challenges,
	folded_digests: &G1Affine,
) -> Result<Fr, VerifierError> {
	let mut preimage = Vec::with_capacity(448);

	// folded_digests in first-96-bytes-of-EIP-2537-format:
	//   [0x00 * 16 || X(48 bytes) || 0x00 * 16 || Y_first_16_bytes(16 bytes)]
	if folded_digests.is_zero() {
		preimage.extend_from_slice(&[0u8; 96]);
	} else {
		let (x, y) = folded_digests.xy().unwrap();
		preimage.extend_from_slice(&[0u8; 16]); // X padding
		push_fq_buf(&mut preimage, &x); // X (48 bytes)
		preimage.extend_from_slice(&[0u8; 16]); // Y padding
										  // Only first 16 bytes of Y (most significant bytes of big-endian encoding)
		let y_bigint = y.into_bigint();
		let y_limbs: &[u64] = y_bigint.as_ref();
		// Big-endian: most significant limb first, we need first 16 bytes = 2 limbs
		preimage.extend_from_slice(&y_limbs[5].to_be_bytes());
		preimage.extend_from_slice(&y_limbs[4].to_be_bytes());
	}

	// [W_ζ]
	push_g1_solidity_buf(&mut preimage, &proof.w_zeta);

	// [Z] (grand product commitment)
	push_g1_solidity_buf(&mut preimage, &proof.z);

	// [W_ζω]
	push_g1_solidity_buf(&mut preimage, &proof.w_zeta_omega);

	// ζ
	push_fr_buf(&mut preimage, &challenges.zeta);

	// gamma_kzg
	push_fr_buf(&mut preimage, &challenges.gamma_kzg);

	debug_assert_eq!(preimage.len(), 448);

	use sha2::Digest;
	let hash = sha2::Sha256::digest(&preimage);

	// Reduce the 256-bit big-endian hash into Fr. `from_be_bytes_mod_order`
	// performs the modular reduction correctly and infallibly, replacing the
	// earlier repeated-subtraction fallback that could panic (audit finding 31).
	Ok(Fr::from_be_bytes_mod_order(&hash))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn push_g1_solidity_buf(buf: &mut Vec<u8>, pt: &G1Affine) {
	if pt.is_zero() {
		buf.extend_from_slice(&[0u8; 96]);
		return;
	}
	let (x, y) = pt.xy().unwrap();
	push_fq_buf(buf, &x);
	push_fq_buf(buf, &y);
}

fn push_fq_buf(buf: &mut Vec<u8>, fq: &ark_bls12_381::Fq) {
	let bigint = (*fq).into_bigint();
	let limbs: &[u64] = bigint.as_ref();
	for &limb in limbs.iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}

fn push_fr_buf(buf: &mut Vec<u8>, fr: &Fr) {
	let bigint = (*fr).into_bigint();
	let limbs: &[u64] = bigint.as_ref();
	for &limb in limbs.iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}

fn write_g1_solidity(out: &mut [u8; 96], pt: &G1Affine) {
	if pt.is_zero() {
		out.fill(0);
		return;
	}
	let (x, y) = pt.xy().unwrap();
	write_fq(&mut out[..48], &x);
	write_fq(&mut out[48..], &y);
}

fn write_fq(out: &mut [u8], fq: &ark_bls12_381::Fq) {
	let bigint = (*fq).into_bigint();
	let limbs: &[u64] = bigint.as_ref();
	for (i, &limb) in limbs.iter().rev().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
	}
}

#[cfg(test)]
mod tests {
	use super::verify;
	use crate::{
		error::VerifierError,
		proof::{PlonkProof, VerifyingKey},
	};
	use ark_bls12_381::{Fr, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_ff::One;

	/// Minimal VK shell for exercising the early structural checks in `verify`.
	fn vk(size: u64, nb_public: u64, qcp_len: usize, cci: Vec<u64>) -> VerifyingKey {
		let g1 = G1Affine::generator();
		let g2 = G2Affine::generator();
		VerifyingKey {
			size,
			size_inv: Fr::one(),
			generator: Fr::one(),
			nb_public_variables: nb_public,
			coset_shift: Fr::one(),
			s: [g1; 3],
			ql: g1,
			qr: g1,
			qm: g1,
			qo: g1,
			qk: g1,
			qcp: vec![g1; qcp_len],
			commitment_constraint_indexes: cci,
			kzg_g1: g1,
			kzg_g2: [g2; 2],
		}
	}

	fn proof(qcp_evals: usize, bsb22: usize) -> PlonkProof {
		let g1 = G1Affine::generator();
		PlonkProof {
			lro: [g1; 3],
			h: [g1; 3],
			l_at_zeta: Fr::one(),
			r_at_zeta: Fr::one(),
			o_at_zeta: Fr::one(),
			s1_at_zeta: Fr::one(),
			s2_at_zeta: Fr::one(),
			z: g1,
			z_shifted_eval: Fr::one(),
			w_zeta: g1,
			w_zeta_omega: g1,
			qcp_evals: vec![Fr::one(); qcp_evals],
			bsb22_commitments: vec![g1; bsb22],
		}
	}

	// Finding 34: domain size must be a power of two.
	#[test]
	fn rejects_non_power_of_two_domain() {
		let err = verify(&proof(1, 1), &vk(3, 0, 1, vec![0]), &[]).unwrap_err();
		assert!(matches!(err, VerifierError::InvalidVkFormat(_)));
	}

	// Finding 27: proof custom-gate vectors must match the VK.
	#[test]
	fn rejects_custom_gate_count_mismatch() {
		let err = verify(&proof(0, 1), &vk(4, 0, 1, vec![0]), &[]).unwrap_err();
		assert!(matches!(err, VerifierError::InvalidProofStructure(_)));
	}

	// Existing invariant: public input count must match the VK.
	#[test]
	fn rejects_public_input_count_mismatch() {
		let err = verify(&proof(1, 1), &vk(4, 2, 1, vec![0]), &[Fr::one()]).unwrap_err();
		assert!(matches!(err, VerifierError::InvalidPublicInputCount { .. }));
	}

	// Finding 30: Lagrange index (nb_public + cci) must be within the domain.
	#[test]
	fn rejects_out_of_range_lagrange_index() {
		// size = 4, commitment_constraint_index = 4  ⇒  idx 4 ≥ size 4.
		let err = verify(&proof(1, 1), &vk(4, 0, 1, vec![4]), &[]).unwrap_err();
		assert!(matches!(err, VerifierError::LagrangeIndexOutOfRange { idx: 4, size: 4 }));
	}
}
