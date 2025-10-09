// Package apk provides utilities for working with Aggregated Public Key proofs
package apk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// APKCircuit represents a circuit for aggregating BLS G1 public keys
// and proving that the sum matches an expected value
type APKCircuit struct {
	// Public keys in G1 (input points to be aggregated)
	// Fixed size array of 10 public keys for better compatibility
	PublicKeys [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// Accumulator for the total sum of public keys
	TotalAccumulator [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// Number of valid public keys to use (0-10)
	NumKeys int `gnark:",public"`

	Seed sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`

	// Expected sum (public input that the circuit will verify)
	ExpectedSum sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`
}

// Define defines the circuit constraints
func (circuit *APKCircuit) Define(api frontend.API) error {
	// Initialize BLS12-381 curve
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		panic(err)
	}

	// Aggregate public keys, start with seed
	curve.AssertIsOnCurve(&circuit.PublicKeys[0])
	circuit.TotalAccumulator[0] = *curve.AddUnified(&circuit.Seed, &circuit.PublicKeys[0])

	// Add the remaining public keys (only up to NumKeys)
	for i := 1; i < circuit.NumKeys; i++ {
		curve.AssertIsOnCurve(&circuit.PublicKeys[i])
		circuit.TotalAccumulator[i] = *curve.Add(&circuit.TotalAccumulator[i-1], &circuit.PublicKeys[i])
	}

	// Assert that the computed sum matches the expected sum
	curve.AssertIsEqual(&circuit.TotalAccumulator[9], &circuit.ExpectedSum)

	return nil
}
