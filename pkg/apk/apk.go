// Package apk provides utilities for working with Aggregated Public Key proofs
package apk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"

	// "github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
)

// APKProofCircuit represents a circuit for aggregating BLS G1 public keys
// and proving that the sum matches an expected value.
//
// The verifier should be able to decompose the partial & total sums into limbs. So they can
// present these values as public inputs to the circuit.APKProofCircuit
//
// The circuit expects these curve points to be delinearized.
type APKProofCircuit struct {
	// ============== Private Witness Variables ==============
	// Public keys in G1 (input points to be aggregated)
	// Fixed size array of 1024 public keys
	PublicKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// Accumulator for the total sum of public keys
	TotalAccumulator [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// Accumulator for the partial sum of public keys
	PartialAccumulator [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]

	// ======= Public Inputs ========
	// Bitlist that encodes the participating public keys
	Bitlist [5]frontend.Variable `gnark:",public"`

	// Start point for the aggregation
	Seed sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`

	// Expected sum (public input that the circuit will verify)
	ExpectedTotalSum sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`

	// Expected sum (public input that the circuit will verify)
	ExpectedPartialSum sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`
}

// Define defines the circuit constraints
func (circuit *APKProofCircuit) Define(api frontend.API) error {
	// // intialize the emulated field
	// fr, err := emulated.NewField[emulated.BLS12381Fr](api)
	// if err != nil {
	// 	return err
	// }

	// // initialize the poseidon hash function
	// hasher, err := poseidon2.NewMerkleDamgardHasher(api)
	// if err != nil {
	// 	return err
	// }

	// Initialize emulated BLS12-381 curve
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}

	var bits []frontend.Variable
	// iterate over Bitlist and append all bits
	for i := range len(circuit.Bitlist) {
		if i == 4 {
			subset := api.ToBinary(circuit.Bitlist[i], 24)
			bits = append(bits, subset...)
		} else {
			subset := api.ToBinary(circuit.Bitlist[i], 250)
			bits = append(bits, subset...)
		}
	}

	// delinearize pk_0
	// hasher.Write(circuit.PublicKeys[0].X.Limbs...)
	// hasher.Write(circuit.PublicKeys[0].Y.Limbs...)
	// pk_0 := *curve.ScalarMul(&circuit.PublicKeys[0], fr.NewElement(hasher.Sum()))

	// Aggregate public keys, start with seed
	curve.AssertIsOnCurve(&circuit.PublicKeys[0])
	circuit.TotalAccumulator[0] = *curve.AddUnified(&circuit.Seed, &circuit.PublicKeys[0])
	circuit.PartialAccumulator[0] = *curve.Select(bits[0], &circuit.TotalAccumulator[0], &circuit.Seed)

	// Add the remaining public keys (only up to NumKeys)
	for i := 1; i < 1024; i++ {
		curve.AssertIsOnCurve(&circuit.PublicKeys[i])
		// we need to compute t = H_1(pk_i) and pk_i^{t}, where H_1 : {0, 1}^{*} -> Z_q
		temp := *curve.AddUnified(&circuit.PartialAccumulator[i-1], &circuit.PublicKeys[i])

		circuit.TotalAccumulator[i] = *curve.AddUnified(&circuit.TotalAccumulator[i-1], &circuit.PublicKeys[i])
		circuit.PartialAccumulator[i] = *curve.Select(bits[i], &temp, &circuit.PartialAccumulator[i-1])
	}

	// Assert that the computed sums matches the expected sums
	curve.AssertIsEqual(&circuit.TotalAccumulator[1023], &circuit.ExpectedTotalSum)
	curve.AssertIsEqual(&circuit.PartialAccumulator[1023], &circuit.ExpectedPartialSum)

	return nil
}
