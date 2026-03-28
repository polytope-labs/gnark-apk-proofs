// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! PLONK verification algorithm for gnark BLS12-381 proofs.
//!
//! This is a direct translation of gnark's Solidity PLONK verifier into safe Rust
//! using arkworks BLS12-381 types.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};

use crate::error::VerifierError;
use crate::proof::{PlonkProof, VerifyingKey};
use crate::transcript::{self, Challenges};

/// Verify a gnark BLS12-381 PLONK proof.
pub fn verify(
    proof: &PlonkProof,
    vk: &VerifyingKey,
    public_inputs: &[Fr],
) -> Result<bool, VerifierError> {
    // ── Input validation ─────────────────────────────────────────────────
    if public_inputs.len() != vk.nb_public_variables as usize {
        return Err(VerifierError::InvalidPublicInputCount {
            expected: vk.nb_public_variables as usize,
            actual: public_inputs.len(),
        });
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
    let (linearised_poly_commitment, opening_linearised_poly_zeta) =
        compute_linearised_polynomial(proof, vk, &challenges, &pi, &alpha_square_lagrange_0, &zeta_power_n_minus_one, &h1_coeff, &h2_coeff)?;

    // ── gamma_kzg challenge ──────────────────────────────────────────────
    challenges.gamma_kzg = transcript::derive_gamma_kzg(
        proof,
        vk,
        &zeta,
        &linearised_poly_commitment,
        &opening_linearised_poly_zeta,
    );

    // ── Fold state (multi-opening) ───────────────────────────────────────
    let (folded_digests, folded_evals) =
        fold_state(proof, vk, &challenges, &linearised_poly_commitment, &opening_linearised_poly_zeta)?;

    // ── Batch verify multi-point opening ─────────────────────────────────
    batch_verify_multi_points(
        proof,
        vk,
        &challenges,
        &folded_digests,
        &folded_evals,
    )
}

/// Compute Σᵢ public_inputs[i] · Lᵢ(ζ)
fn compute_public_inputs_contribution(
    vk: &VerifyingKey,
    public_inputs: &[Fr],
    zeta: &Fr,
    zeta_power_n_minus_one: &Fr,
) -> Result<Fr, VerifierError> {
    let n = public_inputs.len();
    let lagranges = batch_compute_lagranges_at_z(zeta, zeta_power_n_minus_one, &vk.size_inv, &vk.generator, n);

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

        // Lagrange at index (nb_public_variables + commitment_constraint_index)
        let idx = vk.nb_public_variables + vk.commitment_constraint_indexes[i];
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
fn compute_ith_lagrange_at_z(
    z: &Fr,
    zpnmo: &Fr,
    size_inv: &Fr,
    omega: &Fr,
    i: u64,
) -> Fr {
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

    bases.push(vk.ql); scalars.push(l_zeta);
    bases.push(vk.qr); scalars.push(r_zeta);
    bases.push(vk.qm); scalars.push(l_zeta * r_zeta);
    bases.push(vk.qo); scalars.push(o_zeta);
    bases.push(vk.qk); scalars.push(Fr::one());
    bases.push(vk.s[2]); scalars.push(s1_scalar);
    bases.push(proof.z); scalars.push(coeff_z);
    bases.push(proof.h[0]); scalars.push(neg_zh);
    bases.push(proof.h[1]); scalars.push(*h1_coeff);
    bases.push(proof.h[2]); scalars.push(*h2_coeff);

    for (i, bsb_com) in proof.bsb22_commitments.iter().enumerate() {
        bases.push(*bsb_com);
        scalars.push(proof.qcp_evals[i]);
    }

    let scalars_bigint: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();
    let lin_poly_commitment = G1Projective::msm_bigint(&bases, &scalars_bigint).into_affine();

    // ── Opening of linearised polynomial at ζ ────────────────────────────
    // = -[ PI(ζ) - α²·L₁(ζ) + α·(l+β·s1+γ)·(r+β·s2+γ)·(o+γ)·Z(ωζ) ]
    let s1_term = (l_zeta + beta * s1_zeta + gamma)
        * (r_zeta + beta * s2_zeta + gamma)
        * (o_zeta + gamma)
        * alpha
        * z_omega_zeta;

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

    // Folded evaluation: lin_poly(ζ) + γ·L(ζ) + γ²·R(ζ) + γ³·O(ζ) + γ⁴·S₁(ζ) + γ⁵·S₂(ζ) + Σ γ^(5+i)·qcp_i(ζ)
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

    // Folded digest MSM: [lin_poly] + γ·[L] + γ²·[R] + γ³·[O] + γ⁴·[S₁] + γ⁵·[S₂] + Σ γ^(5+i)·[QCP_i]
    let mut bases = Vec::with_capacity(6 + vk.qcp.len());
    let mut scalars = Vec::with_capacity(6 + vk.qcp.len());

    // lin_poly with scalar 1
    bases.push(*linearised_poly_commitment);
    scalars.push(Fr::one());

    let mut acc = gamma_kzg;
    bases.push(proof.lro[0]); scalars.push(acc);
    acc *= gamma_kzg;
    bases.push(proof.lro[1]); scalars.push(acc);
    acc *= gamma_kzg;
    bases.push(proof.lro[2]); scalars.push(acc);
    acc *= gamma_kzg;
    bases.push(vk.s[0]); scalars.push(acc);
    acc *= gamma_kzg;
    bases.push(vk.s[1]); scalars.push(acc);

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
) -> Result<bool, VerifierError> {
    let zeta = challenges.zeta;

    // Derive random scalar for batching the two opening proofs
    let random = derive_batch_random(proof, challenges, folded_digests)?;

    // Fold evaluations: folded_evals + random * Z(ωζ)
    let folded_eval_total = *folded_evals + random * proof.z_shifted_eval;

    // MSM for folded digests:
    //   [folded_digests] + random·[Z] + (-folded_eval_total)·G₁ + ζ·[W_ζ] + (random·ω·ζ)·[W_ζω]
    let zeta_omega = zeta * vk.generator;

    let bases = vec![
        *folded_digests,
        proof.z,
        vk.kzg_g1,
        proof.w_zeta,
        proof.w_zeta_omega,
    ];
    let scalars: Vec<Fr> = vec![
        Fr::one(),
        random,
        -folded_eval_total,
        zeta,
        random * zeta_omega,
    ];
    let scalars_bigint: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();
    let lhs_g1 = G1Projective::msm_bigint(&bases, &scalars_bigint).into_affine();

    // Folded quotients: -[W_ζ] + (-random)·[W_ζω]
    let folded_quotients = {
        let bases = vec![proof.w_zeta, proof.w_zeta_omega];
        let scalars = vec![(-Fr::one()).into_bigint(), (-random).into_bigint()];
        G1Projective::msm_bigint(&bases, &scalars).into_affine()
    };

    // Pairing check: e(lhs_g1, G2_SRS_0) · e(folded_quotients, G2_SRS_1) == 1
    let result = Bls12_381::multi_pairing(
        [lhs_g1, folded_quotients],
        [vk.kzg_g2[0], vk.kzg_g2[1]],
    );

    Ok(result.is_zero())
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
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash);

    // mod r
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash_arr[start..start + 8]);
        limbs[3 - i] = u64::from_be_bytes(bytes);
    }
    let bigint = ark_ff::BigInteger256::new(limbs);
    Ok(Fr::from_bigint(bigint).unwrap_or_else(|| {
        let r_mod = [
            0xffffffff00000001u64,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ];
        let mut val = limbs;
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b1) = val[i].overflowing_sub(r_mod[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            val[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Fr::from_bigint(ark_ff::BigInteger256::new(val)).expect("reduced")
    }))
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
