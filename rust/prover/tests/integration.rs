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

use gnark_apk_ffi::{APKFreeBuffer, APKGenerateTestWitness, CBuffer};
use gnark_apk_prover::{Backend, ProverContext};

/// Generate a valid test witness with random BLS12-381 points via Go FFI.
/// Only for testing — not for production use.
pub fn generate_test_witness(num_participants: u32, seed: i64) -> Vec<u8> {
    let mut buf = CBuffer::default();
    let ret = unsafe { APKGenerateTestWitness(num_participants, seed, &mut buf) };
    assert_eq!(ret, 0, "APKGenerateTestWitness failed");

    let data = unsafe { std::slice::from_raw_parts(buf.data, buf.len as usize).to_vec() };
    unsafe { APKFreeBuffer(&mut buf) };
    data
}

#[test]
#[ignore] // Run with `cargo test -- --ignored` (~2 min for Groth16 setup + prove)
fn test_groth16_prove() {
    let ctx = ProverContext::setup(Backend::Groth16).expect("setup failed");

    let witness = generate_test_witness(10, 42);

    let proof = ctx.prove_raw(&witness).expect("proving failed");

    assert_eq!(
        proof.proof_bytes.len(),
        576,
        "Groth16 proof should be 576 bytes"
    );
    assert_eq!(
        proof.public_inputs.len(),
        960,
        "public inputs should be 960 bytes"
    );
    assert_eq!(proof.backend, Backend::Groth16);

    println!(
        "Groth16 proof generated: {} bytes proof, {} bytes public inputs",
        proof.proof_bytes.len(),
        proof.public_inputs.len()
    );
}

#[test]
#[ignore] // Run with `cargo test -- --ignored` (~90s for PLONK setup + prove)
fn test_plonk_prove() {
    let ctx = ProverContext::setup(Backend::Plonk).expect("setup failed");

    let witness = generate_test_witness(10, 42);

    let proof = ctx.prove_raw(&witness).expect("proving failed");

    assert_eq!(
        proof.proof_bytes.len(),
        1184,
        "PLONK proof should be 1184 bytes"
    );
    assert_eq!(
        proof.public_inputs.len(),
        960,
        "public inputs should be 960 bytes"
    );
    assert_eq!(proof.backend, Backend::Plonk);

    println!(
        "PLONK proof generated: {} bytes proof, {} bytes public inputs",
        proof.proof_bytes.len(),
        proof.public_inputs.len()
    );
}
