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
	"math/rand"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

// decomposeFpToLimbs decomposes a BLS12-381 Fp element into 6 x 64-bit limbs
// (little-endian order), matching gnark's emulated field decomposition for
// BLS12381Fp over BLS12-381 Fr native field.
func decomposeFpToLimbs(val *big.Int) [6]*big.Int {
	var limbs [6]*big.Int
	mask := new(big.Int).SetUint64(^uint64(0)) // 2^64 - 1
	tmp := new(big.Int).Set(val)
	for i := 0; i < 6; i++ {
		limbs[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	return limbs
}

// NativePublicKeysCommitment computes the Poseidon2 hash commitment over all
// public keys outside the circuit, matching the in-circuit computation.
// It decomposes each Fp coordinate into 6 x 64-bit limbs and hashes each limb
// as a BLS12-381 Fr element, matching the in-circuit hasher.Write(pk.X.Limbs...).
func NativePublicKeysCommitment(points []bls12381.G1Affine) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	// Each limb is written as a 32-byte big-endian Fr element
	const elemSize = 32
	buf := make([]byte, elemSize)

	for i := range points {
		xInt := points[i].X.BigInt(new(big.Int))
		yInt := points[i].Y.BigInt(new(big.Int))

		xLimbs := decomposeFpToLimbs(xInt)
		yLimbs := decomposeFpToLimbs(yInt)

		for _, limb := range xLimbs {
			for j := range buf {
				buf[j] = 0
			}
			b := limb.Bytes()
			copy(buf[elemSize-len(b):], b)
			h.Write(buf)
		}
		for _, limb := range yLimbs {
			for j := range buf {
				buf[j] = 0
			}
			b := limb.Bytes()
			copy(buf[elemSize-len(b):], b)
			h.Write(buf)
		}
	}

	digest := h.Sum(nil)
	return new(big.Int).SetBytes(digest)
}

// CreateBitlist creates a bitlist array with a specified number of randomly set bits
// numBitsToSet: the number of bits to randomly set (0-1024)
// Returns: a [5]frontend.Variable array formatted for the circuit and the indices that were set
func CreateBitlist(numBitsToSet int) ([5]frontend.Variable, []int) {
	bitlist := [5]frontend.Variable{}

	for i := 0; i < 5; i++ {
		bitlist[i] = new(big.Int)
	}

	if numBitsToSet <= 0 || numBitsToSet > 1024 {
		return bitlist, []int{}
	}

	allIndices := make([]int, 1024)
	for i := range allIndices {
		allIndices[i] = i
	}

	for i := len(allIndices) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		allIndices[i], allIndices[j] = allIndices[j], allIndices[i]
	}

	selectedIndices := allIndices[:numBitsToSet]

	for _, idx := range selectedIndices {
		var elemIdx int
		var bitPos int

		if idx < 1000 {
			elemIdx = idx / 250
			bitPos = idx % 250
		} else {
			elemIdx = 4
			bitPos = idx - 1000
		}

		val := bitlist[elemIdx].(*big.Int)
		val.SetBit(val, bitPos, 1)
	}

	return bitlist, selectedIndices
}

// CreateBitlistFromIndices creates a bitlist array from specific indices
// indices: the indices of bits to set (0-1023)
// Returns: a [5]frontend.Variable array formatted for the circuit
func CreateBitlistFromIndices(indices []int) [5]frontend.Variable {
	bitlist := [5]frontend.Variable{}

	for i := 0; i < 5; i++ {
		bitlist[i] = new(big.Int)
	}

	for _, idx := range indices {
		if idx < 0 || idx >= 1024 {
			continue
		}

		var elemIdx int
		var bitPos int

		if idx < 1000 {
			elemIdx = idx / 250
			bitPos = idx % 250
		} else {
			elemIdx = 4
			bitPos = idx - 1000
		}

		val := bitlist[elemIdx].(*big.Int)
		val.SetBit(val, bitPos, 1)
	}

	return bitlist
}

// DecodeBitlist decodes a bitlist to get the indices of set bits
func DecodeBitlist(bitlist [5]frontend.Variable) []int {
	var indices []int

	for elemIdx := 0; elemIdx < 5; elemIdx++ {
		val, ok := bitlist[elemIdx].(*big.Int)
		if !ok {
			continue
		}

		var bitsToCheck int
		var startIdx int

		if elemIdx < 4 {
			bitsToCheck = 250
			startIdx = elemIdx * 250
		} else {
			bitsToCheck = 24
			startIdx = 1000
		}

		for bitPos := 0; bitPos < bitsToCheck; bitPos++ {
			if val.Bit(bitPos) == 1 {
				indices = append(indices, startIdx+bitPos)
			}
		}
	}

	return indices
}

// CountSetBits counts the number of bits set in a bitlist
func CountSetBits(bitlist [5]frontend.Variable) int {
	count := 0

	for elemIdx := 0; elemIdx < 5; elemIdx++ {
		val, ok := bitlist[elemIdx].(*big.Int)
		if !ok {
			continue
		}

		var bitsToCheck int
		if elemIdx < 4 {
			bitsToCheck = 250
		} else {
			bitsToCheck = 24
		}

		for bitPos := 0; bitPos < bitsToCheck; bitPos++ {
			if val.Bit(bitPos) == 1 {
				count++
			}
		}
	}

	return count
}
