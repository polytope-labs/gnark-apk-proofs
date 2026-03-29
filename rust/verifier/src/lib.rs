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
//! let vk = VerifyingKey::try_from(vk_bytes.as_slice())?;
//! let proof = PlonkProof::try_from((proof_bytes.as_slice(), vk.qcp.len()))?;
//! verify(&proof, &vk, &public_inputs)?;
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
