// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: generate a PLONK proof via the Go FFI prover, then verify
//! it with the pure-Rust arkworks verifier.
//!
//! Run with:
//!   cargo test -p gnark-plonk-verifier --test verify_proof -- --ignored

use gnark_apk_prover::{testing, ProofBuilder, ProverContext};
use gnark_plonk_verifier::{verify, PlonkProof};

#[test]
#[ignore = "requires SRS files and is slow (~2 min for setup + proving)"]
fn test_verify_plonk_proof() {
	// Set up the PLONK prover with Filecoin ceremony SRS (default path).
	println!("Setting up PLONK prover...");
	let ctx = ProverContext::setup(None).expect("prover setup failed");

	let vk = ctx.verifying_key().expect("VK not found — run setup first");
	println!(
		"VK parsed: domain_size={}, nb_public={}, nb_qcp={}",
		vk.size,
		vk.nb_public_variables,
		vk.qcp.len()
	);

	// Generate a test witness and prove via Go FFI.
	let wit = testing::generate_test_witness(10, 42);
	println!("Generating proof...");
	let apk_proof = ProofBuilder::new(&ctx)
		.public_keys(wit.public_keys)
		.participation(wit.participation)
		.prove()
		.expect("proving failed");

	println!(
		"Proof calldata: {} bytes, Public inputs: {} elements",
		apk_proof.proof_calldata().len(),
		apk_proof.public_inputs.len()
	);

	// Verify with pure-Rust verifier.
	verify(&apk_proof.proof, &vk, &apk_proof.public_inputs).expect("proof verification failed");
	println!("Proof verified successfully!");
}

#[test]
fn test_parse_proof_size_validation() {
	let bad_proof = vec![0u8; 100];
	let result = PlonkProof::try_from((bad_proof.as_slice(), 1));
	assert!(result.is_err());
}
