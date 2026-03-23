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

package apk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	cryptomimc "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// Test: Plain MiMC (no short hash wrapper) + ScalarMul
type mimcScalarMulCircuit struct {
	PK       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp] `gnark:",public"`
}

func (c *mimcScalarMulCircuit) Define(api frontend.API) error {
	fr, err := emulated.NewField[emulated.BLS12381Fr](api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}

	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hasher.Write(c.PK.X.Limbs...)
	hasher.Write(c.PK.Y.Limbs...)
	h := hasher.Sum()

	bits := api.ToBinary(h, 253)
	scalar := fr.FromBits(bits...)

	result := curve.ScalarMul(&c.PK, scalar)
	curve.AssertIsEqual(result, &c.Expected)
	return nil
}

func TestMimcScalarMul(t *testing.T) {
	_, _, G, _ := bls12381.Generators()
	var s fr.Element
	s.SetRandom()
	var point bls12381.G1Affine
	point.ScalarMultiplication(&G, s.BigInt(new(big.Int)))
	pk := sw_bls12381.NewG1Affine(point)

	// Native MiMC hash (direct, no short wrapper)
	h := cryptomimc.MIMC_BLS12_381.New()
	for _, limb := range pk.X.Limbs {
		b := limb.(*big.Int).Bytes()
		// MiMC expects field element sized input (32 bytes)
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		h.Write(padded)
	}
	for _, limb := range pk.Y.Limbs {
		b := limb.(*big.Int).Bytes()
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		h.Write(padded)
	}
	hashBytes := h.Sum(nil)
	ti := new(big.Int).SetBytes(hashBytes)
	// Reduce mod Fr to be safe
	ti.Mod(ti, ecc.BLS12_381.ScalarField())
	t.Logf("MiMC hash scalar: %s (bit length: %d)", ti.String(), ti.BitLen())

	var expected bls12381.G1Affine
	expected.ScalarMultiplication(&point, ti)

	circuit := &mimcScalarMulCircuit{}
	witness := &mimcScalarMulCircuit{
		PK:       pk,
		Expected: sw_bls12381.NewG1Affine(expected),
	}

	err := test.IsSolved(circuit, witness, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("MiMC+ScalarMul FAILED: %v", err)
	}
	t.Log("MiMC+ScalarMul MATCHED!")
}
