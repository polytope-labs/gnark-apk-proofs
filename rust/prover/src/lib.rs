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

pub use ark_bls12_381::G1Affine;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use gnark_apk_ffi::{ApkFreeHandle, ApkFreeResult, ApkProve, ApkSetup, CProveResult};
use std::{
	ffi::CString,
	path::{Path, PathBuf},
};
use thiserror::Error;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

/// Number of validators in the circuit.
pub const NUM_VALIDATORS: usize = 1024;

/// Returns the default SRS directory: `$HOME/.config/gnark-apk-proofs/srs`.
pub fn default_srs_dir() -> PathBuf {
	PathBuf::from(std::env::var("HOME").expect("HOME environment variable not set"))
		.join(".config/gnark-apk-proofs/srs")
}

#[derive(Error, Debug)]
pub enum ApkProverError {
	#[error("setup failed (circuit compilation or key generation)")]
	SetupFailed,

	#[error("missing required field: {0}")]
	MissingField(&'static str),

	#[error("expected at most 1024 public keys, got {0}")]
	InvalidPublicKeyCount(usize),

	#[error("participant index {0} out of range (0..1023)")]
	InvalidParticipantIndex(u16),

	#[error("proving failed: {0}")]
	ProvingFailed(String),

	#[error("failed to read VK from disk: {0}")]
	VkReadFailed(#[from] std::io::Error),

	#[error("failed to parse VK: {0}")]
	VkParseFailed(#[from] gnark_plonk_verifier::VerifierError),
}

/// A generated proof ready for on-chain or off-chain verification.
#[derive(Clone, Debug)]
pub struct ApkProof {
	/// Parsed PLONK proof.
	pub proof: gnark_plonk_verifier::PlonkProof,
	/// Parsed public inputs as field elements.
	pub public_inputs: Vec<gnark_plonk_verifier::Fr>,
	/// Raw proof bytes from gnark's MarshalSolidity.
	solidity_proof: Vec<u8>,
	/// Raw public inputs bytes (32 bytes big-endian per element).
	solidity_public_inputs: Vec<u8>,
}

impl ApkProof {
	/// Serialized proof bytes for the Solidity verifier (1184 bytes).
	pub fn proof_calldata(&self) -> &[u8] {
		&self.solidity_proof
	}

	/// Serialized public inputs for the Solidity verifier (32 bytes big-endian per element).
	pub fn public_inputs_calldata(&self) -> &[u8] {
		&self.solidity_public_inputs
	}
}

/// Holds the proving/verifying keys from a one-time setup.
/// Drop frees the Go-side resources.
pub struct ProverContext {
	handle: u64,
	srs_dir: PathBuf,
}

impl ProverContext {
	/// Perform circuit compilation and PLONK key generation.
	///
	/// `srs_dir` should point to the directory containing
	/// `plonk_srs.canonical` and `plonk_srs.lagrange` files. If `None`,
	/// defaults to `$HOME/.config/gnark-apk-proofs/srs`
	///
	/// (the Go side will download from the Filecoin ceremony if the files are missing).
	pub fn setup(srs_dir: Option<&Path>) -> Result<Self, ApkProverError> {
		let default_dir = srs_dir.is_none().then(default_srs_dir);
		let effective_dir = srs_dir.or(default_dir.as_deref());

		let c_srs_dir = effective_dir
			.map(|p| CString::new(p.to_str().expect("srs_dir must be valid UTF-8")))
			.transpose()
			.map_err(|_| ApkProverError::SetupFailed)?;

		let srs_ptr = c_srs_dir.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());

		let resolved_dir = effective_dir.map(|p| p.to_path_buf()).unwrap_or_else(default_srs_dir);

		let handle = unsafe { ApkSetup(srs_ptr) };
		if handle == 0 {
			return Err(ApkProverError::SetupFailed);
		}
		Ok(Self { handle, srs_dir: resolved_dir })
	}

	/// Load the PLONK verifying key from the cached file on disk.
	/// The VK is written to `<srs_dir>/plonk_vk.bin` during setup.
	pub fn verifying_key(&self) -> Result<gnark_plonk_verifier::VerifyingKey, ApkProverError> {
		let vk_path = self.srs_dir.join("plonk_vk.bin");
		let bytes = std::fs::read(&vk_path)?;
		Ok(gnark_plonk_verifier::VerifyingKey::try_from(bytes.as_slice())?)
	}
}

impl Drop for ProverContext {
	fn drop(&mut self) {
		unsafe { ApkFreeHandle(self.handle) };
	}
}

// ProverContext owns a unique handle — safe to send across threads.
// Not Sync because gnark proving is not thread-safe for a single PK.
unsafe impl Send for ProverContext {}

/// Builder for constructing and proving Apk proofs.
pub struct ProofBuilder<'a> {
	ctx: &'a ProverContext,
	public_keys: Option<Vec<G1Affine>>,
	participation: Option<Vec<u16>>,
}

impl<'a> ProofBuilder<'a> {
	pub fn new(ctx: &'a ProverContext) -> Self {
		Self { ctx, public_keys: None, participation: None }
	}

	/// Set the validator public key set (at most 1024; padded to 1024 with identity).
	pub fn public_keys(mut self, keys: Vec<G1Affine>) -> Self {
		self.public_keys = Some(keys);
		self
	}

	/// Set which validators participated, by index (0..1023).
	pub fn participation(mut self, indices: Vec<u16>) -> Self {
		self.participation = Some(indices);
		self
	}

	/// Generate the proof.
	///
	/// If fewer than 1024 public keys are provided, the remaining slots are
	/// padded with the identity point. Participation indices are validated
	/// against the actual number of keys provided.
	pub fn prove(self) -> Result<ApkProof, ApkProverError> {
		let mut public_keys =
			self.public_keys.ok_or(ApkProverError::MissingField("public_keys"))?;
		let participation =
			self.participation.ok_or(ApkProverError::MissingField("participation"))?;

		let num_keys = public_keys.len();
		if num_keys > NUM_VALIDATORS {
			return Err(ApkProverError::InvalidPublicKeyCount(num_keys));
		}

		for &idx in &participation {
			if idx as usize >= num_keys {
				return Err(ApkProverError::InvalidParticipantIndex(idx));
			}
		}

		// Pad to 1024 with identity points for unused slots.
		public_keys.resize(NUM_VALIDATORS, G1Affine::identity());

		let witness = serialize_witness(&public_keys, &participation);

		let mut result = CProveResult::default();
		let ret = unsafe {
			ApkProve(self.ctx.handle, witness.as_ptr(), witness.len() as u32, &mut result)
		};

		if ret != 0 || !result.error.is_null() {
			let msg = if result.error.is_null() {
				"unknown error".to_string()
			} else {
				let c_str = unsafe { std::ffi::CStr::from_ptr(result.error) };
				let msg = c_str.to_string_lossy().into_owned();
				unsafe { ApkFreeResult(&mut result) };
				msg
			};
			return Err(ApkProverError::ProvingFailed(msg));
		}

		let proof_bytes = unsafe {
			std::slice::from_raw_parts(result.proof_data, result.proof_len as usize).to_vec()
		};
		let public_inputs_bytes = unsafe {
			std::slice::from_raw_parts(result.public_inputs_data, result.public_inputs_len as usize)
				.to_vec()
		};

		unsafe { ApkFreeResult(&mut result) };

		// Parse into typed proof and public inputs.
		let vk = self.ctx.verifying_key()?;
		let proof =
			gnark_plonk_verifier::PlonkProof::try_from((proof_bytes.as_slice(), vk.qcp.len()))?;
		let public_inputs = parse_public_inputs(&public_inputs_bytes);

		Ok(ApkProof {
			proof,
			public_inputs,
			solidity_proof: proof_bytes,
			solidity_public_inputs: public_inputs_bytes,
		})
	}
}

/// Parse public inputs from gnark's binary witness format (header stripped).
/// Each public input is a 32-byte big-endian Fr element.
fn parse_public_inputs(data: &[u8]) -> Vec<gnark_plonk_verifier::Fr> {
	use ark_ff::BigInteger256;

	assert_eq!(data.len() % 32, 0);
	data.chunks(32)
		.map(|chunk| {
			let mut limbs = [0u64; 4];
			for i in 0..4 {
				let start = i * 8;
				let mut bytes = [0u8; 8];
				bytes.copy_from_slice(&chunk[start..start + 8]);
				limbs[3 - i] = u64::from_be_bytes(bytes);
			}
			gnark_plonk_verifier::Fr::from_bigint(BigInteger256::new(limbs))
				.expect("public input out of range")
		})
		.collect()
}

/// Serialize witness into the FFI wire format:
///   [1024 x 96-byte G1 points] [4-byte BE count] [n x 2-byte BE indices]
///
/// Each G1 point is serialized as 96 bytes: X (48 bytes big-endian) || Y (48 bytes big-endian),
/// matching gnark-crypto's uncompressed G1 format.
///
/// The seed point is a protocol constant hardcoded in the circuit and is not
/// included in the witness.
fn serialize_witness(keys: &[G1Affine], participation: &[u16]) -> Vec<u8> {
	let num_indices = participation.len();
	let total = NUM_VALIDATORS * 96 + 4 + num_indices * 2;
	let mut buf = Vec::with_capacity(total);

	for key in keys {
		g1_to_gnark_bytes(key, &mut buf);
	}

	buf.extend_from_slice(&(num_indices as u32).to_be_bytes());
	for &idx in participation {
		buf.extend_from_slice(&idx.to_be_bytes());
	}

	buf
}

/// Convert an arkworks G1Affine point to gnark-crypto's 96-byte uncompressed format:
/// X (48 bytes big-endian) || Y (48 bytes big-endian).
fn g1_to_gnark_bytes(point: &G1Affine, buf: &mut Vec<u8>) {
	if point.is_zero() {
		buf.extend_from_slice(&[0u8; 96]);
		return;
	}
	let (x, y) = point.xy().unwrap();
	fq_to_be_bytes(&x, buf);
	fq_to_be_bytes(&y, buf);
}

/// Serialize an Fq element as 48 bytes big-endian.
fn fq_to_be_bytes(fq: &ark_bls12_381::Fq, buf: &mut Vec<u8>) {
	let bigint = (*fq).into_bigint();
	let limbs: &[u64] = bigint.as_ref();

	// 6 limbs x 8 bytes = 48 bytes, most significant limb first.
	for &limb in limbs.iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}
