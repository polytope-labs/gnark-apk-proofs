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
use thiserror::Error;

use gnark_apk_ffi::{APKFreeHandle, APKFreeResult, APKProve, APKSetup, CProveResult};

/// Number of validators in the circuit.
pub const NUM_VALIDATORS: usize = 1024;


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


/// Proving backend selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Backend {
    Groth16 = 0,
    Plonk = 1,
}

/// A generated proof ready for on-chain verification.
#[derive(Clone, Debug)]
pub struct APKProof {
    /// Serialized proof bytes (576 for Groth16, 1184 for PLONK).
    pub proof_bytes: Vec<u8>,
    /// Serialized public inputs (960 bytes = 30 x uint256).
    pub public_inputs: Vec<u8>,
    /// Which backend was used.
    pub backend: Backend,
}


/// Holds the proving/verifying keys from a one-time setup.
/// Drop frees the Go-side resources.
pub struct ProverContext {
    handle: u64,
    backend: Backend,
}

impl ProverContext {
    /// Perform circuit compilation and trusted setup.
    /// This is expensive (~2 min for Groth16, ~45s for PLONK).
    pub fn setup(backend: Backend) -> Result<Self, APKProverError> {
        let handle = unsafe { APKSetup(backend as u8) };
        if handle == 0 {
            return Err(APKProverError::SetupFailed);
        }
        Ok(Self { handle, backend })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Prove from pre-serialized witness bytes (FFI wire format).
    pub fn prove_raw(&self, witness: &[u8]) -> Result<APKProof, APKProverError> {
        prove_ffi(self.handle, self.backend, witness)
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
        Self {
            public_keys: None,
            participation: None,
            seed: None,
        }
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
        let public_keys = self
            .public_keys
            .ok_or(APKProverError::MissingField("public_keys"))?;
        let participation = self
            .participation
            .ok_or(APKProverError::MissingField("participation"))?;
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
        prove_ffi(ctx.handle, ctx.backend, &witness)
    }
}

impl Default for ProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}


/// Call the Go FFI prover and collect the result.
fn prove_ffi(handle: u64, backend: Backend, witness: &[u8]) -> Result<APKProof, APKProverError> {
    let mut result = CProveResult::default();
    let ret = unsafe {
        APKProve(handle, witness.as_ptr(), witness.len() as u32, &mut result)
    };

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

    Ok(APKProof {
        proof_bytes,
        public_inputs,
        backend,
    })
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
