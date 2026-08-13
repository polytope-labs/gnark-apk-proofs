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

//! Proves repeatedly, so the setup is paid once instead of per proof.
//!
//! `prove_from_json` compiles the circuit and generates the keys on every run, which is four
//! minutes a caller pays again and again. This does that once at startup and then answers
//! requests, one json object per line on stdin, one per line on stdout.
//!
//! Request:  {"keys": ["<96 byte hex G1, X||Y>", ...], "participation": [0, 1]}
//! Response: {"apkProof": "..", "publicInputs": "..", "bitlist": [".."], "apkCommitment": ".."}
//!           or {"error": "what went wrong"}
//!
//! The first line of stdout is `{"ready":true}`, so a caller knows the setup has finished.

use std::io::{BufRead, Write};

use ark_bls12_381::{Fq, G1Affine};
use ark_ff::PrimeField;
use gnark_apk_prover::{ProofBuilder, ProverContext};

fn g1_from_packed(hex_str: &str) -> Result<G1Affine, String> {
	let raw = hex::decode(hex_str).map_err(|e| format!("key is not hex: {e}"))?;
	if raw.len() != 96 {
		return Err(format!("expected an uncompressed 96 byte G1 point, got {}", raw.len()));
	}
	let point = G1Affine::new_unchecked(
		Fq::from_be_bytes_mod_order(&raw[0..48]),
		Fq::from_be_bytes_mod_order(&raw[48..96]),
	);
	if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
		return Err("key is not a valid curve point".into());
	}
	Ok(point)
}

fn prove(
	context: &ProverContext,
	request: &serde_json::Value,
) -> Result<serde_json::Value, String> {
	let keys = request["keys"]
		.as_array()
		.ok_or("request has no keys")?
		.iter()
		.map(|key| g1_from_packed(key.as_str().ok_or("key is not a string")?))
		.collect::<Result<Vec<_>, _>>()?;
	let participation = request["participation"]
		.as_array()
		.ok_or("request has no participation")?
		.iter()
		.map(|index| {
			index
				.as_u64()
				.map(|i| i as u16)
				.ok_or_else(|| "index is not a number".to_string())
		})
		.collect::<Result<Vec<_>, _>>()?;

	let proof = ProofBuilder::new(context)
		.public_keys(keys)
		.participation(participation)
		.prove()
		.map_err(|e| format!("proving failed: {e}"))?;

	let raw = proof.public_inputs_calldata();
	if raw.len() != 18 * 32 {
		return Err(format!("expected 18 public inputs, got {}", raw.len() / 32));
	}
	let word = |i: usize| hex::encode(&raw[i * 32..(i + 1) * 32]);

	Ok(serde_json::json!({
		"apkProof": hex::encode(proof.proof_calldata()),
		"publicInputs": hex::encode(raw),
		"bitlist": (0..5).map(word).collect::<Vec<_>>(),
		"apkCommitment": word(5),
	}))
}

fn main() {
	let srs_dir = std::env::args().nth(1);
	let context =
		ProverContext::setup(srs_dir.as_deref().map(std::path::Path::new)).expect("setup");

	let stdout = std::io::stdout();
	let mut out = stdout.lock();
	writeln!(out, "{}", serde_json::json!({ "ready": true })).expect("write");
	out.flush().expect("flush");

	for line in std::io::stdin().lock().lines() {
		let line = line.expect("read");
		if line.trim().is_empty() {
			continue;
		}

		let response = match serde_json::from_str::<serde_json::Value>(&line) {
			Ok(request) => match prove(&context, &request) {
				Ok(proof) => proof,
				Err(error) => serde_json::json!({ "error": error }),
			},
			Err(e) => serde_json::json!({ "error": format!("request is not json: {e}") }),
		};

		writeln!(out, "{response}").expect("write");
		out.flush().expect("flush");
	}
}
