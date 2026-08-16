//! Generates an APK proof for a validator set collected from a live chain.
//!
//! Exists so a consumer does not have to depend on this crate to get a proof: the cgo toolchain and
//! the 800MB SRS stay here, and the data crosses as json.
//!
//! Input is `apk-inputs.json`, needing only two of its fields:
//!
//! ```json
//! { "keys": ["<96 byte hex G1, X||Y>", ...], "participation": [0, 1] }
//! ```
//!
//! Output is `apk-snark.json`, carrying the proof and the public inputs the Solidity verifier
//! wants, plus the bitlist and commitment read back out of those inputs so the caller does not
//! have to know their layout.
//!
//!   cargo run --release --example prove_from_json -- /tmp/apk

use ark_bls12_381::{Fq, G1Affine};
use ark_ff::PrimeField;
use gnark_apk_prover::{ProofBuilder, ProverContext};
use std::{env, fs, time::Instant};

fn fq_from_be(bytes: &[u8]) -> Fq {
	Fq::from_be_bytes_mod_order(bytes)
}

/// Inverse of the packing the consumer writes: 48 byte big-endian X then Y, no padding.
fn g1_from_packed(hex_str: &str) -> G1Affine {
	let raw = hex::decode(hex_str).expect("key is hex");
	assert_eq!(raw.len(), 96, "expected an uncompressed 96 byte G1 point");
	let point = G1Affine::new_unchecked(fq_from_be(&raw[0..48]), fq_from_be(&raw[48..96]));
	assert!(point.is_on_curve(), "key is not on the curve");
	assert!(point.is_in_correct_subgroup_assuming_on_curve(), "key is not in the subgroup");
	point
}

fn main() {
	let dir = env::args().nth(1).expect("usage: prove_from_json <fixture dir>");
	let inputs: serde_json::Value =
		serde_json::from_str(&fs::read_to_string(format!("{dir}/apk-inputs.json")).expect("read"))
			.expect("parse");

	let keys: Vec<G1Affine> = inputs["keys"]
		.as_array()
		.expect("keys is an array")
		.iter()
		.map(|k| g1_from_packed(k.as_str().expect("key is a string")))
		.collect();
	let participation: Vec<u16> = inputs["participation"]
		.as_array()
		.expect("participation is an array")
		.iter()
		.map(|i| i.as_u64().expect("index is a number") as u16)
		.collect();

	println!("{} validator keys, {} signed", keys.len(), participation.len());

	let started = Instant::now();
	let ctx = ProverContext::setup(None).expect("setup");
	println!("setup took {:?}", started.elapsed());

	let started = Instant::now();
	let proof = ProofBuilder::new(&ctx)
		.public_keys(keys)
		.participation(participation)
		.prove()
		.expect("prove");
	println!("proving took {:?}", started.elapsed());

	// The Solidity verifier takes 18 public inputs: the bitlist in the first five words, the
	// commitment in the sixth, then the aggregate key as twelve limbs. The first six are what a
	// caller has to pass alongside the proof, so hand them back decoded.
	let raw = proof.public_inputs_calldata();
	assert_eq!(raw.len(), 18 * 32, "expected 18 public inputs");
	let word = |i: usize| hex::encode(&raw[i * 32..(i + 1) * 32]);

	let out = serde_json::json!({
		"apkProof": hex::encode(proof.proof_calldata()),
		"publicInputs": hex::encode(raw),
		"bitlist": (0..5).map(word).collect::<Vec<_>>(),
		"apkCommitment": word(5),
	});

	let path = format!("{dir}/apk-snark.json");
	fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).expect("write");
	println!("proof is {} bytes; wrote {path}", proof.proof_calldata().len());
}
