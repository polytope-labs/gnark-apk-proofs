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
use std::{
	ffi::CString,
	path::{Path, PathBuf},
};
use thiserror::Error;

use gnark_apk_ffi::{
	APKExportVK, APKFreeBuffer, APKFreeHandle, APKFreeResult, APKProve, APKSetup, CBuffer,
	CProveResult,
};

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
pub enum APKProverError {
	#[error("setup failed (circuit compilation or key generation)")]
	SetupFailed,

	#[error("missing required field: {0}")]
	MissingField(&'static str),

	#[error("expected 1024 public keys, got {0}")]
	InvalidPublicKeyCount(usize),

	#[error("participant index {0} out of range (0..1023)")]
	InvalidParticipantIndex(u16),

	#[error("proving failed: {0}")]
	ProvingFailed(String),
}

/// A generated proof ready for on-chain verification.
#[derive(Clone, Debug)]
pub struct APKProof {
	/// Serialized proof bytes (1184 bytes PLONK).
	pub proof_bytes: Vec<u8>,
	/// Serialized public inputs (960 bytes = 30 x uint256).
	pub public_inputs: Vec<u8>,
}

/// Holds the proving/verifying keys from a one-time setup.
/// Drop frees the Go-side resources.
pub struct ProverContext {
	handle: u64,
}

impl ProverContext {
	/// Perform circuit compilation and PLONK key generation.
	///
	/// `srs_dir` should point to the directory containing
	/// `plonk_srs.canonical` and `plonk_srs.lagrange` files. If `None`,
	/// defaults to `$HOME/.config/gnark-apk-proofs/srs` (the Go side will
	/// download from the Filecoin ceremony if the files are missing).
	pub fn setup(srs_dir: Option<&Path>) -> Result<Self, APKProverError> {
		let default_dir = srs_dir.is_none().then(default_srs_dir);
		let effective_dir = srs_dir.or(default_dir.as_deref());

		let c_srs_dir = effective_dir
			.map(|p| CString::new(p.to_str().expect("srs_dir must be valid UTF-8")))
			.transpose()
			.map_err(|_| APKProverError::SetupFailed)?;

		let srs_ptr = c_srs_dir.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());

		let handle = unsafe { APKSetup(srs_ptr) };
		if handle == 0 {
			return Err(APKProverError::SetupFailed);
		}
		Ok(Self { handle })
	}

	/// Export the PLONK verifying key in gnark's binary format.
	pub fn export_vk(&self) -> Result<Vec<u8>, APKProverError> {
		let mut buf = CBuffer::default();
		let ret = unsafe { APKExportVK(self.handle, &mut buf) };
		if ret != 0 {
			return Err(APKProverError::SetupFailed);
		}
		let data = unsafe { std::slice::from_raw_parts(buf.data, buf.len as usize).to_vec() };
		unsafe { APKFreeBuffer(&mut buf) };
		Ok(data)
	}

	/// Prove from pre-serialized witness bytes (FFI wire format).
	pub fn prove_raw(&self, witness: &[u8]) -> Result<APKProof, APKProverError> {
		prove_ffi(self.handle, witness)
	}
}

impl Drop for ProverContext {
	fn drop(&mut self) {
		unsafe { APKFreeHandle(self.handle) };
	}
}

// ProverContext owns a unique handle — safe to send across threads.
// Not Sync because gnark proving is not thread-safe for a single PK.
unsafe impl Send for ProverContext {}

/// Builder for constructing and proving APK proofs.
pub struct ProofBuilder {
	public_keys: Option<Vec<G1Affine>>,
	participation: Option<Vec<u16>>,
	seed: Option<G1Affine>,
}

impl ProofBuilder {
	pub fn new() -> Self {
		Self { public_keys: None, participation: None, seed: None }
	}

	/// Set the full validator public key set (must be exactly 1024).
	pub fn public_keys(mut self, keys: Vec<G1Affine>) -> Self {
		self.public_keys = Some(keys);
		self
	}

	/// Set which validators participated, by index (0..1023).
	pub fn participation(mut self, indices: Vec<u16>) -> Self {
		self.participation = Some(indices);
		self
	}

	/// Set the seed point for aggregation.
	pub fn seed(mut self, seed: G1Affine) -> Self {
		self.seed = Some(seed);
		self
	}

	/// Generate the proof using the given prover context.
	pub fn prove(self, ctx: &ProverContext) -> Result<APKProof, APKProverError> {
		let public_keys = self.public_keys.ok_or(APKProverError::MissingField("public_keys"))?;
		let participation =
			self.participation.ok_or(APKProverError::MissingField("participation"))?;
		let seed = self.seed.ok_or(APKProverError::MissingField("seed"))?;

		if public_keys.len() != NUM_VALIDATORS {
			return Err(APKProverError::InvalidPublicKeyCount(public_keys.len()));
		}

		for &idx in &participation {
			if idx as usize >= NUM_VALIDATORS {
				return Err(APKProverError::InvalidParticipantIndex(idx));
			}
		}

		let witness = serialize_witness(&public_keys, &participation, &seed);
		prove_ffi(ctx.handle, &witness)
	}
}

impl Default for ProofBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Call the Go FFI prover and collect the result.
fn prove_ffi(handle: u64, witness: &[u8]) -> Result<APKProof, APKProverError> {
	let mut result = CProveResult::default();
	let ret = unsafe { APKProve(handle, witness.as_ptr(), witness.len() as u32, &mut result) };

	if ret != 0 || !result.error.is_null() {
		let msg = if result.error.is_null() {
			"unknown error".to_string()
		} else {
			let c_str = unsafe { std::ffi::CStr::from_ptr(result.error) };
			let msg = c_str.to_string_lossy().into_owned();
			unsafe { APKFreeResult(&mut result) };
			msg
		};
		return Err(APKProverError::ProvingFailed(msg));
	}

	let proof_bytes = unsafe {
		std::slice::from_raw_parts(result.proof_data, result.proof_len as usize).to_vec()
	};
	let public_inputs = unsafe {
		std::slice::from_raw_parts(result.public_inputs_data, result.public_inputs_len as usize)
			.to_vec()
	};

	unsafe { APKFreeResult(&mut result) };

	Ok(APKProof { proof_bytes, public_inputs })
}

/// Serialize witness into the FFI wire format:
///   [1024 x 96-byte G1 points] [4-byte BE count] [n x 2-byte BE indices] [96-byte seed]
///
/// Each G1 point is serialized as 96 bytes: X (48 bytes big-endian) || Y (48 bytes big-endian),
/// matching gnark-crypto's uncompressed G1 format.
fn serialize_witness(keys: &[G1Affine], participation: &[u16], seed: &G1Affine) -> Vec<u8> {
	let num_indices = participation.len();
	let total = NUM_VALIDATORS * 96 + 4 + num_indices * 2 + 96;
	let mut buf = Vec::with_capacity(total);

	for key in keys {
		g1_to_gnark_bytes(key, &mut buf);
	}

	buf.extend_from_slice(&(num_indices as u32).to_be_bytes());
	for &idx in participation {
		buf.extend_from_slice(&idx.to_be_bytes());
	}

	g1_to_gnark_bytes(seed, &mut buf);

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
