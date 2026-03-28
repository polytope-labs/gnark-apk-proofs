// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: generate a PLONK proof via the Go FFI prover, then verify
//! it with the pure-Rust arkworks verifier.
//!
//! Run with:
//!   cargo test -p gnark-plonk-verifier --test verify_gnark_proof -- --ignored

use ark_ff::{BigInteger256, PrimeField};
use gnark_apk_prover::{testing, ProofBuilder, ProverContext};
use gnark_plonk_verifier::{verify, Fr, PlonkProof, VerifyingKey};

/// Parse public inputs from gnark's binary witness format (header stripped).
/// Each public input is a 32-byte big-endian Fr element.
fn parse_public_inputs(data: &[u8]) -> Vec<Fr> {
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
            Fr::from_bigint(BigInteger256::new(limbs)).expect("public input out of range")
        })
        .collect()
}

#[test]
#[ignore = "requires SRS files and is slow (~2 min for setup + proving)"]
fn test_verify_plonk_proof() {
    // Set up the PLONK prover with Filecoin ceremony SRS (default path).
    println!("Setting up PLONK prover...");
    let ctx = ProverContext::setup(None)
        .expect("prover setup failed");

    // Export the VK from the prover context.
    let vk_bytes = ctx.export_vk().expect("VK export failed");
    println!("VK exported: {} bytes", vk_bytes.len());

    // Generate a test witness in Rust and prove via Go FFI.
    let wit = testing::generate_test_witness(10, 42);
    println!("Generating proof...");
    let proof_result = ProofBuilder::new()
        .public_keys(wit.public_keys)
        .participation(wit.participation)
        .seed(wit.seed)
        .prove(&ctx)
        .expect("proving failed");

    println!(
        "Proof: {} bytes, Public inputs: {} bytes",
        proof_result.proof_bytes.len(),
        proof_result.public_inputs.len()
    );

    // Parse VK, proof, and public inputs with the Rust verifier.
    let vk = VerifyingKey::from_gnark_bytes(&vk_bytes).expect("failed to parse VK");
    println!(
        "VK parsed: domain_size={}, nb_public={}, nb_qcp={}",
        vk.size,
        vk.nb_public_variables,
        vk.qcp.len()
    );

    let proof = PlonkProof::from_solidity_bytes(&proof_result.proof_bytes, vk.qcp.len())
        .expect("failed to parse proof");

    let public_inputs = parse_public_inputs(&proof_result.public_inputs);
    assert_eq!(public_inputs.len(), vk.nb_public_variables as usize);

    // Verify with pure-Rust verifier.
    let result = verify(&proof, &vk, &public_inputs).expect("verification error");
    assert!(result, "Proof verification failed!");
    println!("Proof verified successfully!");
}

#[test]
fn test_parse_proof_size_validation() {
    let bad_proof = vec![0u8; 100];
    let result = PlonkProof::from_solidity_bytes(&bad_proof, 1);
    assert!(result.is_err());
}
