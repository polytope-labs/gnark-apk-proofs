// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for generating random BLS12-381 witnesses.

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::SeedableRng;

use crate::NUM_VALIDATORS;

/// Generate 1024 deterministic random G1 public keys from the given seed.
pub fn random_public_keys(seed: u64) -> Vec<G1Affine> {
	let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
	(0..NUM_VALIDATORS)
		.map(|_| G1Projective::rand(&mut rng).into_affine())
		.collect()
}

/// Build a complete test witness: 1024 random keys and the given participant
/// indices. The seed point is a protocol constant hardcoded in the circuit.
pub fn generate_test_witness(num_participants: u32, seed: u64) -> TestWitness {
	let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);

	let public_keys: Vec<G1Affine> = (0..NUM_VALIDATORS)
		.map(|_| G1Projective::rand(&mut rng).into_affine())
		.collect();

	// Select first `num_participants` indices (deterministic).
	let mut indices: Vec<u16> = (0..NUM_VALIDATORS as u16).collect();
	// Fisher-Yates shuffle with the same rng for determinism.
	for i in (1..indices.len()).rev() {
		let j = (Fr::rand(&mut rng).into_bigint().0[0] as usize) % (i + 1);
		indices.swap(i, j);
	}
	indices.truncate(num_participants as usize);

	TestWitness { public_keys, participation: indices }
}

/// A complete test witness ready for proving.
pub struct TestWitness {
	pub public_keys: Vec<G1Affine>,
	pub participation: Vec<u16>,
}
