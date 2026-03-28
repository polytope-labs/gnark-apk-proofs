// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust verifier for gnark BLS12-381 PLONK proofs using arkworks.
//!
//! # Usage
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use gnark_plonk_verifier::{PlonkProof, VerifyingKey, verify};
//! # let vk_bytes = vec![0u8; 0];
//! # let proof_bytes = vec![0u8; 0];
//! # let public_inputs = vec![];
//!
//! let vk = VerifyingKey::from_gnark_bytes(&vk_bytes)?;
//! let proof = PlonkProof::from_solidity_bytes(&proof_bytes, vk.qcp.len())?;
//! let valid = verify(&proof, &vk, &public_inputs)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod proof;
pub mod transcript;
pub mod verifier;

pub use ark_bls12_381::Fr;
pub use error::VerifierError;
pub use proof::{PlonkProof, VerifyingKey};
pub use verifier::verify;
