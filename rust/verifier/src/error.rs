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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifierError {
	#[error("invalid proof size: expected {expected}, got {actual}")]
	InvalidProofSize { expected: usize, actual: usize },

	#[error("invalid public input count: expected {expected}, got {actual}")]
	InvalidPublicInputCount { expected: usize, actual: usize },

	#[error("point not on curve")]
	PointNotOnCurve,

	#[error("scalar out of range")]
	ScalarOutOfRange,

	#[error("unexpected end of input")]
	UnexpectedEof,

	#[error("invalid VK format: {0}")]
	InvalidVkFormat(&'static str),

	#[error("proof verification failed")]
	ProofVerificationFailed,
}
