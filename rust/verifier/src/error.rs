// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

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
}
