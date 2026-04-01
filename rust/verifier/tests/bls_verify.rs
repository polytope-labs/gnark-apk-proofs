// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0
//!
//! End-to-end test: generate an APK proof via Go FFI, sign with BLS, then verify
//! the combined `verify()` on-chain using revm with Prague EIP-2537 precompiles.
//!
//! Run with:
//!   cargo test -p gnark-plonk-verifier --test bls_verify -- --ignored --nocapture

use alloy_primitives::{Bytes, FixedBytes, TxKind, U256};
use alloy_sol_types::{sol, SolCall};
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::SeedableRng;
use gnark_apk_prover::{ProofBuilder, ProverContext, NUM_VALIDATORS};
use revm::{
	context::{
		result::{ExecutionResult, Output},
		TxEnv,
	},
	database::{CacheDB, EmptyDB},
	handler::{ExecuteCommitEvm, MainBuilder, MainContext},
	primitives::hardfork::SpecId,
};

sol! {
	struct ApkPublicInputs {
		uint256 publicKeysCommitment;
		uint256[5] bitlist;
		bytes32[3] apk;
	}

	function verify(
		ApkPublicInputs apkInputs,
		bytes apkProof,
		bytes32[3] message,
		bytes32[3] signature,
		bytes32[6] apk2
	) external view;

	function hashToG1(bytes message) external view returns (bytes32[3]);
}

// ─── Serialization helpers ───────────────────────────────────────────────────

fn g1_to_bytes(point: &G1Affine) -> Vec<u8> {
	if point.is_zero() {
		return vec![0u8; 96];
	}
	let (x, y) = point.xy().unwrap();
	let mut bytes = Vec::with_capacity(96);
	fq_to_be(&x, &mut bytes);
	fq_to_be(&y, &mut bytes);
	bytes
}

fn g2_to_bytes(point: &G2Affine) -> Vec<u8> {
	if point.is_zero() {
		return vec![0u8; 192];
	}
	let (x, y) = point.xy().unwrap();
	let mut bytes = Vec::with_capacity(192);
	fq_to_be(&x.c0, &mut bytes);
	fq_to_be(&x.c1, &mut bytes);
	fq_to_be(&y.c0, &mut bytes);
	fq_to_be(&y.c1, &mut bytes);
	bytes
}

fn fq_to_be(fq: &ark_bls12_381::Fq, buf: &mut Vec<u8>) {
	for &limb in (*fq).into_bigint().as_ref().iter().rev() {
		buf.extend_from_slice(&limb.to_be_bytes());
	}
}

fn g1_to_bytes32x3(point: &G1Affine) -> [FixedBytes<32>; 3] {
	let raw = g1_to_bytes(point);
	[
		FixedBytes::from_slice(&raw[0..32]),
		FixedBytes::from_slice(&raw[32..64]),
		FixedBytes::from_slice(&raw[64..96]),
	]
}

fn g2_to_bytes32x6(point: &G2Affine) -> [FixedBytes<32>; 6] {
	let raw = g2_to_bytes(point);
	[
		FixedBytes::from_slice(&raw[0..32]),
		FixedBytes::from_slice(&raw[32..64]),
		FixedBytes::from_slice(&raw[64..96]),
		FixedBytes::from_slice(&raw[96..128]),
		FixedBytes::from_slice(&raw[128..160]),
		FixedBytes::from_slice(&raw[160..192]),
	]
}

// ─── EVM helpers ─────────────────────────────────────────────────────────────

fn load_contract_bytecode(contract_name: &str) -> Vec<u8> {
	let manifest_dir = env!("CARGO_MANIFEST_DIR");
	let path =
		format!("{}/../../solidity/out/{contract_name}.sol/{contract_name}.json", manifest_dir);
	let json: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| {
			panic!(
				"Failed to read forge artifact at {}. Run `forge build` in solidity/ first.",
				path
			)
		}))
		.expect("Failed to parse forge artifact JSON");

	let bytecode_hex = json["bytecode"]["object"]
		.as_str()
		.expect("Missing bytecode.object in forge artifact");
	let hex_str = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);
	hex::decode(hex_str).expect("Invalid bytecode hex")
}

type Evm = revm::handler::MainnetEvm<
	revm::Context<
		revm::context::BlockEnv,
		TxEnv,
		revm::context::CfgEnv,
		CacheDB<EmptyDB>,
		revm::context::journal::Journal<CacheDB<EmptyDB>>,
		(),
	>,
>;

fn create_evm() -> Evm {
	revm::Context::mainnet()
		.modify_cfg_chained(|c: &mut revm::context::CfgEnv| {
			c.set_spec_and_mainnet_gas_params(SpecId::PRAGUE);
		})
		.with_db(CacheDB::<EmptyDB>::default())
		.build_mainnet()
}

fn deploy(evm: &mut Evm, nonce: &mut u64, bytecode: Bytes) -> alloy_primitives::Address {
	let result = evm
		.transact_commit(
			TxEnv::builder()
				.kind(TxKind::Create)
				.data(bytecode)
				.gas_limit(30_000_000)
				.nonce(*nonce)
				.build()
				.unwrap(),
		)
		.expect("deployment failed");
	*nonce += 1;
	match result {
		ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
		other => panic!("deployment failed: {:?}", other),
	}
}

fn call(
	evm: &mut Evm,
	nonce: &mut u64,
	to: alloy_primitives::Address,
	calldata: Bytes,
) -> ExecutionResult {
	let result = evm
		.transact_commit(
			TxEnv::builder()
				.kind(TxKind::Call(to))
				.data(calldata)
				.gas_limit(30_000_000)
				.nonce(*nonce)
				.build()
				.unwrap(),
		)
		.expect("call failed");
	*nonce += 1;
	result
}

fn deploy_contracts(evm: &mut Evm, nonce: &mut u64) -> alloy_primitives::Address {
	let plonk_verifier = deploy(evm, nonce, Bytes::from(load_contract_bytecode("PlonkVerifier")));

	let mut deploy_data = load_contract_bytecode("ApkProof");
	let mut constructor_arg = [0u8; 32];
	constructor_arg[12..32].copy_from_slice(plonk_verifier.as_slice());
	deploy_data.extend_from_slice(&constructor_arg);

	deploy(evm, nonce, Bytes::from(deploy_data))
}

// ─── Test ────────────────────────────────────────────────────────────────────

/// Full end-to-end: generate keypairs → APK proof via Go FFI → BLS sign →
/// combined `verify()` on revm (PLONK proof + BLS signature in one call).
///
///   cargo test -p gnark-plonk-verifier --test bls_verify -- --ignored --nocapture
#[test]
#[ignore = "requires SRS files and Go FFI prover (~2 min)"]
fn test_full_verify() {
	let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(99);
	let num_signers = (NUM_VALIDATORS * 2 / 3 + 1) as u16; // 683 of 1024

	// ── 1. Generate keypairs (secret keys + G1/G2 public keys) ──
	println!("Generating {} keypairs...", NUM_VALIDATORS);
	let secret_keys: Vec<Fr> = (0..NUM_VALIDATORS).map(|_| Fr::rand(&mut rng)).collect();

	let g1_pks: Vec<G1Affine> = secret_keys
		.iter()
		.map(|sk| (G1Affine::generator().into_group() * sk).into_affine())
		.collect();

	let g2_pks: Vec<G2Affine> = secret_keys
		.iter()
		.map(|sk| (G2Affine::generator().into_group() * sk).into_affine())
		.collect();

	let participation: Vec<u16> = (0..num_signers).collect();

	// ── 2. Generate APK proof via Go FFI ──
	println!("Setting up PLONK prover...");
	let ctx = ProverContext::setup(None).expect("prover setup failed");

	println!("Generating APK proof...");
	let apk_proof = ProofBuilder::new(&ctx)
		.public_keys(g1_pks.clone())
		.participation(participation.clone())
		.prove()
		.expect("proving failed");

	println!(
		"Proof: {} bytes, Public inputs: {} elements",
		apk_proof.proof_calldata().len(),
		apk_proof.public_inputs.len()
	);

	// ── 3. BLS sign and aggregate ──
	// Hash message to G1 using w3f/bls convention
	let raw_msg = b"test message for full verify";
	let w3f_message = w3f_bls::Message::new_assuming_pop(b"", raw_msg);
	let h_m_proj = w3f_message.hash_to_signature_curve::<w3f_bls::TinyBLS381>();
	// Transmute ark 0.4 → ark 0.5 (identical memory layout)
	let h_m: G1Affine = unsafe {
		core::mem::transmute::<_, G1Affine>(
			<w3f_bls::TinyBLS381 as w3f_bls::EngineBLS>::SignatureGroupAffine::from(h_m_proj),
		)
	};

	let sigs: Vec<G1Projective> = participation
		.iter()
		.map(|&i| h_m.into_group() * secret_keys[i as usize])
		.collect();

	let asig: G1Affine = sigs.iter().sum::<G1Projective>().into_affine();

	let apk1: G1Affine = participation
		.iter()
		.map(|&i| g1_pks[i as usize].into_group())
		.sum::<G1Projective>()
		.into_affine();

	let apk2: G2Affine = participation
		.iter()
		.map(|&i| g2_pks[i as usize].into_group())
		.sum::<G2Projective>()
		.into_affine();

	// Sanity: off-chain pairing check
	assert_eq!(
		ark_bls12_381::Bls12_381::pairing(asig, G2Affine::generator()),
		ark_bls12_381::Bls12_381::pairing(h_m, apk2),
		"off-chain BLS verification failed"
	);

	// ── 4. Build ApkPublicInputs struct ──
	let raw_pi = apk_proof.public_inputs_calldata();
	assert_eq!(raw_pi.len(), 18 * 32);

	let mut bitlist = [U256::ZERO; 5];
	for i in 0..5 {
		bitlist[i] = U256::from_be_slice(&raw_pi[i * 32..(i + 1) * 32]);
	}
	let commitment = U256::from_be_slice(&raw_pi[5 * 32..6 * 32]);

	let apk_inputs =
		ApkPublicInputs { publicKeysCommitment: commitment, bitlist, apk: g1_to_bytes32x3(&apk1) };

	// ── 5. Deploy and call combined verify() ──
	println!("Deploying contracts in revm...");
	let mut evm = create_evm();
	let mut nonce = 0u64;
	let contract = deploy_contracts(&mut evm, &mut nonce);

	let calldata = verifyCall {
		apkInputs: apk_inputs,
		apkProof: apk_proof.proof_calldata().to_vec().into(),
		message: g1_to_bytes32x3(&h_m),
		signature: g1_to_bytes32x3(&asig),
		apk2: g2_to_bytes32x6(&apk2),
	}
	.abi_encode();

	println!("Calling verify() (APK proof + BLS signature)...");
	let result = call(&mut evm, &mut nonce, contract, Bytes::from(calldata));

	match result {
		ExecutionResult::Success { gas, .. } => {
			println!("Full verify PASSED — gas: {}", gas.spent());
		},
		ExecutionResult::Revert { output, .. } => {
			panic!("verify() reverted: 0x{}", alloy_primitives::hex::encode(&output));
		},
		ExecutionResult::Halt { reason, .. } => {
			panic!("verify() halted: {:?}", reason);
		},
	}
}

/// Test hashToG1 against w3f/bls reference implementation.
///
///   cargo test -p gnark-plonk-verifier --test bls_verify -- test_hash_to_g1 --nocapture
#[test]
fn test_hash_to_g1() {
	use w3f_bls::{EngineBLS, Message, TinyBLS381};

	let context = b"";
	let raw_msg = b"hello world";

	// Compute expected point via w3f/bls
	let message = Message::new_assuming_pop(context, raw_msg);
	let expected_proj = message.hash_to_signature_curve::<TinyBLS381>();

	// Convert w3f/bls output (ark 0.4 G1Affine) to bytes32[3] for comparison.
	// Both ark 0.4 and 0.5 use identical internal Fp representation (6 x u64 limbs),
	// so we transmute to our ark 0.5 G1Affine which has the same memory layout.
	let expected_bytes = {
		let affine: <TinyBLS381 as EngineBLS>::SignatureGroupAffine = expected_proj.into();
		let affine_v5: G1Affine = unsafe { core::mem::transmute(affine) };
		g1_to_bytes32x3(&affine_v5)
	};

	// Contract prepends cipher suite internally, just pass context || raw_msg
	let msg_input = [context.as_slice(), raw_msg.as_slice()].concat();

	// Deploy contract and call hashToG1
	let mut evm = create_evm();
	let mut nonce = 0u64;
	let contract = deploy_contracts(&mut evm, &mut nonce);

	let calldata = hashToG1Call { message: msg_input.into() }.abi_encode();

	let result = call(&mut evm, &mut nonce, contract, Bytes::from(calldata));

	match result {
		ExecutionResult::Success { gas, output: Output::Call(out), .. } => {
			let decoded = <hashToG1Call as SolCall>::abi_decode_returns(&out).unwrap();
			assert_eq!(decoded, expected_bytes, "hashToG1 output mismatch vs w3f/bls");
			println!("hashToG1 PASSED (w3f/bls compat) — gas: {}", gas.spent());
		},
		ExecutionResult::Revert { output, .. } => {
			panic!("hashToG1 reverted: 0x{}", alloy_primitives::hex::encode(&output));
		},
		other => panic!("hashToG1 failed: {:?}", other),
	}
}
