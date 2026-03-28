// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Deserialization of gnark BLS12-381 PLONK proofs and verification keys.
//!
//! Proof bytes use gnark's `MarshalSolidity` layout (1184 bytes for 1 custom gate).
//! VK bytes use gnark's `WriteTo` binary format.

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger256, BigInteger384, Field, PrimeField};

use crate::error::VerifierError;

/// A gnark BLS12-381 PLONK proof (deserialized from MarshalSolidity format).
#[derive(Clone, Debug)]
pub struct PlonkProof {
	/// Wire polynomial commitments [L], [R], [O].
	pub lro: [G1Affine; 3],
	/// Quotient polynomial commitments [H₀], [H₁], [H₂].
	pub h: [G1Affine; 3],
	/// Evaluations: L(ζ), R(ζ), O(ζ), S₁(ζ), S₂(ζ).
	pub l_at_zeta: Fr,
	pub r_at_zeta: Fr,
	pub o_at_zeta: Fr,
	pub s1_at_zeta: Fr,
	pub s2_at_zeta: Fr,
	/// Grand product commitment [Z].
	pub z: G1Affine,
	/// Grand product evaluation Z(ωζ).
	pub z_shifted_eval: Fr,
	/// Batch opening proof at ζ.
	pub w_zeta: G1Affine,
	/// Opening proof at ωζ.
	pub w_zeta_omega: G1Affine,
	/// Custom gate evaluations qcp_i(ζ).
	pub qcp_evals: Vec<Fr>,
	/// BSB22 custom gate commitments.
	pub bsb22_commitments: Vec<G1Affine>,
}

/// A gnark BLS12-381 PLONK verification key.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
	/// Domain size (power of 2).
	pub size: u64,
	/// 1 / size  (in Fr).
	pub size_inv: Fr,
	/// Generator ω of the multiplicative subgroup of order `size`.
	pub generator: Fr,
	/// Number of public inputs.
	pub nb_public_variables: u64,
	/// Coset shift.
	pub coset_shift: Fr,
	/// Permutation commitments [S₁], [S₂], [S₃].
	pub s: [G1Affine; 3],
	/// Selector commitments.
	pub ql: G1Affine,
	pub qr: G1Affine,
	pub qm: G1Affine,
	pub qo: G1Affine,
	pub qk: G1Affine,
	/// Custom gate commitments.
	pub qcp: Vec<G1Affine>,
	/// Indices for commit API constraints.
	pub commitment_constraint_indexes: Vec<u64>,
	/// KZG verification key: G₁ generator.
	pub kzg_g1: G1Affine,
	/// KZG verification key: [G₂, τ·G₂].
	pub kzg_g2: [G2Affine; 2],
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Size of G1 uncompressed point in gnark encoding (X: 48 bytes + Y: 48 bytes).
const G1_SIZE: usize = 96;
/// Size of G2 uncompressed point in gnark encoding.
/// Size of G2 uncompressed point in gnark encoding.
#[allow(dead_code)]
const G2_SIZE: usize = 192;
/// Size of Fr element (32 bytes, big-endian).
const FR_SIZE: usize = 32;
/// Fixed proof size without custom gates.
const FIXED_PROOF_SIZE: usize = 0x420;

// ── Proof deserialization ────────────────────────────────────────────────────

impl PlonkProof {
	/// Deserialize from gnark's `MarshalSolidity` byte layout.
	///
	/// Expected size: `0x420 + nb_custom_gates * 0x80` bytes.
	pub fn from_solidity_bytes(data: &[u8], nb_custom_gates: usize) -> Result<Self, VerifierError> {
		let expected = FIXED_PROOF_SIZE + nb_custom_gates * 0x80;
		if data.len() != expected {
			return Err(VerifierError::InvalidProofSize { expected, actual: data.len() });
		}

		let mut offset = 0;

		// LRO commitments (3 × G1)
		let l_com = read_g1_solidity(data, &mut offset)?;
		let r_com = read_g1_solidity(data, &mut offset)?;
		let o_com = read_g1_solidity(data, &mut offset)?;

		// Quotient polynomial commitments (3 × G1)
		let h0 = read_g1_solidity(data, &mut offset)?;
		let h1 = read_g1_solidity(data, &mut offset)?;
		let h2 = read_g1_solidity(data, &mut offset)?;

		// Wire evaluations at ζ (5 × Fr)
		let l_at_zeta = read_fr(data, &mut offset)?;
		let r_at_zeta = read_fr(data, &mut offset)?;
		let o_at_zeta = read_fr(data, &mut offset)?;
		let s1_at_zeta = read_fr(data, &mut offset)?;
		let s2_at_zeta = read_fr(data, &mut offset)?;

		// Grand product commitment [Z]
		let z = read_g1_solidity(data, &mut offset)?;

		// Z(ωζ)
		let z_shifted_eval = read_fr(data, &mut offset)?;

		// Opening proofs
		let w_zeta = read_g1_solidity(data, &mut offset)?;
		let w_zeta_omega = read_g1_solidity(data, &mut offset)?;

		// Custom gate evaluations
		let mut qcp_evals = Vec::with_capacity(nb_custom_gates);
		for _ in 0..nb_custom_gates {
			qcp_evals.push(read_fr(data, &mut offset)?);
		}

		// BSB22 commitments
		let mut bsb22_commitments = Vec::with_capacity(nb_custom_gates);
		for _ in 0..nb_custom_gates {
			bsb22_commitments.push(read_g1_solidity(data, &mut offset)?);
		}

		debug_assert_eq!(offset, expected);

		Ok(Self {
			lro: [l_com, r_com, o_com],
			h: [h0, h1, h2],
			l_at_zeta,
			r_at_zeta,
			o_at_zeta,
			s1_at_zeta,
			s2_at_zeta,
			z,
			z_shifted_eval,
			w_zeta,
			w_zeta_omega,
			qcp_evals,
			bsb22_commitments,
		})
	}
}

// ── VK deserialization ───────────────────────────────────────────────────────

impl VerifyingKey {
	/// Deserialize from gnark's `WriteTo` binary format.
	pub fn from_gnark_bytes(data: &[u8]) -> Result<Self, VerifierError> {
		let mut offset = 0;

		// Version marker and version
		let marker = read_u64(data, &mut offset)?;
		if marker != 0 {
			return Err(VerifierError::InvalidVkFormat("expected version marker 0"));
		}
		let version = read_u64(data, &mut offset)?;
		if version != 1 {
			return Err(VerifierError::InvalidVkFormat("unsupported VK version"));
		}

		let size = read_u64(data, &mut offset)?;
		let size_inv = read_fr(data, &mut offset)?;
		let generator = read_fr(data, &mut offset)?;
		let nb_public_variables = read_u64(data, &mut offset)?;
		let coset_shift = read_fr(data, &mut offset)?;

		// S[0..2]
		let s0 = read_g1_gnark(data, &mut offset)?;
		let s1 = read_g1_gnark(data, &mut offset)?;
		let s2 = read_g1_gnark(data, &mut offset)?;

		// Selectors
		let ql = read_g1_gnark(data, &mut offset)?;
		let qr = read_g1_gnark(data, &mut offset)?;
		let qm = read_g1_gnark(data, &mut offset)?;
		let qo = read_g1_gnark(data, &mut offset)?;
		let qk = read_g1_gnark(data, &mut offset)?;

		// Qcp (variable-length slice)
		let qcp_len = read_u32(data, &mut offset)? as usize;
		let mut qcp = Vec::with_capacity(qcp_len);
		for _ in 0..qcp_len {
			qcp.push(read_g1_gnark(data, &mut offset)?);
		}

		// KZG verification key (G1 then G2[0], G2[1])
		let kzg_g1 = read_g1_gnark(data, &mut offset)?;
		let kzg_g2_0 = read_g2_gnark(data, &mut offset)?;
		let kzg_g2_1 = read_g2_gnark(data, &mut offset)?;

		// Skip precomputed pairing lines: [2][2][63]LineEvaluationAff
		// Each LineEvaluationAff = 2 × E2 = 2 × (2 × Fp) = 4 × 48 = 192 bytes
		// Total: 2 × 2 × 63 × 192 = 48384 bytes
		const LINES_SIZE: usize = 2 * 2 * 63 * 192;
		ensure_bytes(data, offset, LINES_SIZE)?;
		offset += LINES_SIZE;

		// CommitmentConstraintIndexes (comes after KZG lines in gnark's WriteTo order)
		let cci_len = read_u32(data, &mut offset)? as usize;
		let mut commitment_constraint_indexes = Vec::with_capacity(cci_len);
		for _ in 0..cci_len {
			commitment_constraint_indexes.push(read_u64(data, &mut offset)?);
		}

		Ok(Self {
			size,
			size_inv,
			generator,
			nb_public_variables,
			coset_shift,
			s: [s0, s1, s2],
			ql,
			qr,
			qm,
			qo,
			qk,
			qcp,
			commitment_constraint_indexes,
			kzg_g1,
			kzg_g2: [kzg_g2_0, kzg_g2_1],
		})
	}
}

// ── Low-level readers ────────────────────────────────────────────────────────

/// Read a G1 point from MarshalSolidity format: X(48 bytes BE) || Y(48 bytes BE).
fn read_g1_solidity(data: &[u8], offset: &mut usize) -> Result<G1Affine, VerifierError> {
	ensure_bytes(data, *offset, G1_SIZE)?;
	let chunk = &data[*offset..*offset + G1_SIZE];
	*offset += G1_SIZE;

	// Point at infinity: all 96 bytes zero (MarshalSolidity uses raw coordinates, no flags)
	if chunk.iter().all(|&b| b == 0) {
		return Ok(G1Affine::zero());
	}

	let x = fq_from_be_bytes(&chunk[..48])?;
	let y = fq_from_be_bytes(&chunk[48..96])?;

	let point = G1Affine::new_unchecked(x, y);
	if !point.is_on_curve() {
		return Err(VerifierError::PointNotOnCurve);
	}
	Ok(point)
}

/// Read a G1 point from gnark's binary (WriteTo) format — compressed.
/// gnark-crypto uses a flags byte in the MSB of the first coordinate byte.
fn read_g1_gnark(data: &[u8], offset: &mut usize) -> Result<G1Affine, VerifierError> {
	// gnark's binary encoder writes G1 points as compressed (48 bytes) by default.
	ensure_bytes(data, *offset, 48)?;
	let chunk = &data[*offset..*offset + 48];
	*offset += 48;

	let flags = chunk[0] >> 5;
	// 0b100 = compressed, normal point
	// 0b110 = compressed, infinity
	if flags & 0b010 != 0 {
		// infinity
		return Ok(G1Affine::zero());
	}

	// Extract X coordinate (mask out top 3 flag bits)
	let mut x_bytes = [0u8; 48];
	x_bytes.copy_from_slice(chunk);
	x_bytes[0] &= 0x1F; // clear flag bits

	let x = fq_from_be_bytes(&x_bytes)?;
	let greatest = flags & 0b001 != 0; // lexicographically largest Y

	// Reconstruct Y from X using curve equation: Y² = X³ + 4
	let x2 = x.square();
	let x3 = x2 * x;
	let b = ark_bls12_381::Fq::from(4u64);
	let rhs = x3 + b;

	let y = rhs.sqrt().ok_or(VerifierError::PointNotOnCurve)?;

	// gnark uses "largest" convention: if the flag says largest and y is not the
	// largest, negate.
	let neg_y = -y;
	let y = if greatest == (y > neg_y) { y } else { neg_y };

	Ok(G1Affine::new_unchecked(x, y))
}

/// Read a G2 point from gnark's binary format — compressed (96 bytes).
fn read_g2_gnark(data: &[u8], offset: &mut usize) -> Result<G2Affine, VerifierError> {
	ensure_bytes(data, *offset, 96)?;
	let chunk = &data[*offset..*offset + 96];
	*offset += 96;

	let flags = chunk[0] >> 5;
	if flags & 0b010 != 0 {
		return Ok(G2Affine::zero());
	}

	// G2 X coordinate is Fq2 = c0 + c1*u, stored as c1(48 bytes) || c0(48 bytes) in gnark
	let mut c1_bytes = [0u8; 48];
	c1_bytes.copy_from_slice(&chunk[..48]);
	c1_bytes[0] &= 0x1F; // clear flag bits
	let c1 = fq_from_be_bytes(&c1_bytes)?;

	let c0 = fq_from_be_bytes(&chunk[48..96])?;

	let x = ark_bls12_381::Fq2::new(c0, c1);
	let greatest = flags & 0b001 != 0;

	// Y² = X³ + B where B = 4(1 + i) for BLS12-381 G2
	let b = ark_bls12_381::Fq2::new(ark_bls12_381::Fq::from(4u64), ark_bls12_381::Fq::from(4u64));
	let rhs = x.square() * x + b;
	let y = rhs.sqrt().ok_or(VerifierError::PointNotOnCurve)?;

	let neg_y = -y;
	let y = if greatest == (y > neg_y) { y } else { neg_y };

	Ok(G2Affine::new_unchecked(x, y))
}

/// Read a 32-byte big-endian Fr scalar.
fn read_fr(data: &[u8], offset: &mut usize) -> Result<Fr, VerifierError> {
	ensure_bytes(data, *offset, FR_SIZE)?;
	let chunk = &data[*offset..*offset + FR_SIZE];
	*offset += FR_SIZE;

	// Fr is 32 bytes = 4 x u64 limbs, big-endian
	let mut limbs = [0u64; 4];
	for i in 0..4 {
		let start = i * 8;
		let mut bytes = [0u8; 8];
		bytes.copy_from_slice(&chunk[start..start + 8]);
		// Big-endian: first 8 bytes are most significant limb
		limbs[3 - i] = u64::from_be_bytes(bytes);
	}

	Fr::from_bigint(BigInteger256::new(limbs)).ok_or(VerifierError::ScalarOutOfRange)
}

/// Read a 48-byte big-endian Fq element.
fn fq_from_be_bytes(bytes: &[u8]) -> Result<ark_bls12_381::Fq, VerifierError> {
	debug_assert_eq!(bytes.len(), 48);

	// Fq is 48 bytes = 6 x u64 limbs, big-endian
	let mut limbs = [0u64; 6];
	for i in 0..6 {
		let start = i * 8;
		let mut buf = [0u8; 8];
		buf.copy_from_slice(&bytes[start..start + 8]);
		limbs[5 - i] = u64::from_be_bytes(buf);
	}

	ark_bls12_381::Fq::from_bigint(BigInteger384::new(limbs)).ok_or(VerifierError::ScalarOutOfRange)
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, VerifierError> {
	ensure_bytes(data, *offset, 8)?;
	let mut buf = [0u8; 8];
	buf.copy_from_slice(&data[*offset..*offset + 8]);
	*offset += 8;
	Ok(u64::from_big_endian_or_le(&buf))
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, VerifierError> {
	ensure_bytes(data, *offset, 4)?;
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&data[*offset..*offset + 4]);
	*offset += 4;
	Ok(u32::from_be_bytes(buf))
}

fn ensure_bytes(data: &[u8], offset: usize, need: usize) -> Result<(), VerifierError> {
	if offset + need > data.len() {
		Err(VerifierError::UnexpectedEof)
	} else {
		Ok(())
	}
}

/// gnark's binary encoder uses big-endian for uint64.
trait FromBigEndianOrLe {
	fn from_big_endian_or_le(bytes: &[u8; 8]) -> Self;
}

impl FromBigEndianOrLe for u64 {
	fn from_big_endian_or_le(bytes: &[u8; 8]) -> Self {
		u64::from_be_bytes(*bytes)
	}
}
