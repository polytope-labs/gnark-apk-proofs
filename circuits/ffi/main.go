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

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	const uint8_t* proof_data;
	uint32_t proof_len;
	const uint8_t* public_inputs_data;
	uint32_t public_inputs_len;
	const char* error;
} CProveResult;

typedef struct {
	const uint8_t* data;
	uint32_t len;
} CBuffer;
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"unsafe"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"
	"golang.org/x/crypto/sha3"

	"github.com/polytope-labs/gnark-apk-proofs/circuits/apk"
)

// handleStore maps uint64 handles to setup artifacts.
var handleStore sync.Map
var nextHandle atomic.Uint64

type groth16Setup struct {
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
}

type plonkSetup struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
	vk plonk.VerifyingKey
}

// Backend constants matching Rust enum.
const (
	backendGroth16 = 0
	backendPlonk   = 1
)

//export APKSetup
func APKSetup(backendType C.uint8_t) C.uint64_t {
	circuit := apk.APKProofCircuit{}

	switch uint8(backendType) {
	case backendGroth16:
		cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			return 0
		}
		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			return 0
		}
		h := nextHandle.Add(1)
		handleStore.Store(h, &groth16Setup{cs: cs, pk: pk, vk: vk})
		return C.uint64_t(h)

	case backendPlonk:
		cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
		if err != nil {
			return 0
		}
		srs, srsLag, err := unsafekzg.NewSRS(cs)
		if err != nil {
			return 0
		}
		pk, vk, err := plonk.Setup(cs, srs, srsLag)
		if err != nil {
			return 0
		}
		h := nextHandle.Add(1)
		handleStore.Store(h, &plonkSetup{cs: cs, pk: pk, vk: vk})
		return C.uint64_t(h)

	default:
		return 0
	}
}

//export APKFreeHandle
func APKFreeHandle(handle C.uint64_t) {
	handleStore.Delete(uint64(handle))
}

//export APKFreeResult
func APKFreeResult(result *C.CProveResult) {
	if result.proof_data != nil {
		C.free(unsafe.Pointer(result.proof_data))
	}
	if result.public_inputs_data != nil {
		C.free(unsafe.Pointer(result.public_inputs_data))
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
	}
}

// Witness format (all big-endian):
//   - 1024 x G1 points: each 96 bytes (X: 48 bytes || Y: 48 bytes)
//   - participation indices: 4 bytes count (uint32) + count x 2 bytes (uint16 each)
//   - seed: 96 bytes (G1 point)
const (
	g1Size       = 96 // 48-byte X + 48-byte Y
	numPubKeys   = 1024
	pubKeysBytes = numPubKeys * g1Size // 98304
)

//export APKProve
func APKProve(handle C.uint64_t, witnessData *C.uint8_t, witnessLen C.uint32_t, result *C.CProveResult) C.int32_t {
	val, ok := handleStore.Load(uint64(handle))
	if !ok {
		setError(result, "invalid handle")
		return -1
	}

	witness, err := parseWitness(witnessData, witnessLen)
	if err != nil {
		setError(result, err.Error())
		return -1
	}

	fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
	if err != nil {
		setError(result, fmt.Sprintf("failed to create witness: %v", err))
		return -1
	}

	var proofIface interface{ MarshalSolidity() []byte }

	switch setup := val.(type) {
	case *groth16Setup:
		proof, err := groth16.Prove(setup.cs, setup.pk, fullWitness,
			backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
		if err != nil {
			setError(result, fmt.Sprintf("failed to prove: %v", err))
			return -1
		}
		proofIface = proof.(interface{ MarshalSolidity() []byte })

	case *plonkSetup:
		proof, err := plonk.Prove(setup.cs, setup.pk, fullWitness)
		if err != nil {
			setError(result, fmt.Sprintf("failed to prove: %v", err))
			return -1
		}
		proofIface = proof.(interface{ MarshalSolidity() []byte })

	default:
		setError(result, "handle has unknown setup type")
		return -1
	}

	proofBytes := proofIface.MarshalSolidity()

	// Marshal public inputs (strip 12-byte header)
	pubWitness, err := fullWitness.Public()
	if err != nil {
		setError(result, fmt.Sprintf("failed to extract public witness: %v", err))
		return -1
	}
	pubBytes, err := pubWitness.MarshalBinary()
	if err != nil {
		setError(result, fmt.Sprintf("failed to marshal public witness: %v", err))
		return -1
	}
	pubBytes = pubBytes[12:]

	copyToResult(result, proofBytes, pubBytes)
	return 0
}

// parseWitness deserializes the FFI witness buffer into an APKProofCircuit.
//
// Wire format:
//
//	[0..98304)             1024 G1 points (96 bytes each: X||Y big-endian)
//	[98304..98308)         uint32 BE: number of participating indices
//	[98308..98308+n*2)     n x uint16 BE: participating validator indices
//	[last 96 bytes)        seed G1 point
func parseWitness(data *C.uint8_t, length C.uint32_t) (*apk.APKProofCircuit, error) {
	buf := C.GoBytes(unsafe.Pointer(data), C.int(length))
	totalLen := len(buf)

	// Minimum: pubkeys + 4-byte count + seed
	minLen := pubKeysBytes + 4 + g1Size
	if totalLen < minLen {
		return nil, fmt.Errorf("witness too short: %d < %d", totalLen, minLen)
	}

	// Parse public keys
	points := make([]bls12381.G1Affine, numPubKeys)
	var pubKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	offset := 0
	for i := 0; i < numPubKeys; i++ {
		pt, err := parseG1(buf[offset : offset+g1Size])
		if err != nil {
			return nil, fmt.Errorf("invalid public key %d: %v", i, err)
		}
		points[i] = pt
		pubKeys[i] = sw_bls12381.NewG1Affine(pt)
		offset += g1Size
	}

	// Parse participation indices
	if offset+4 > totalLen {
		return nil, fmt.Errorf("truncated at participation count")
	}
	numParticipants := int(beUint32(buf[offset : offset+4]))
	offset += 4

	if offset+numParticipants*2 > totalLen-g1Size {
		return nil, fmt.Errorf("truncated at participation indices")
	}

	participantIndices := make([]int, numParticipants)
	for i := 0; i < numParticipants; i++ {
		participantIndices[i] = int(beUint16(buf[offset : offset+2]))
		offset += 2
	}

	// Parse seed (last 96 bytes)
	seedBytes := buf[totalLen-g1Size:]
	seed, err := parseG1(seedBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid seed: %v", err)
	}

	// Compute bitlist from indices
	bitlist := apk.CreateBitlistFromIndices(participantIndices)

	// Compute expected APK: seed + Σ b_i * pk_i
	participantSet := make(map[int]bool, len(participantIndices))
	for _, idx := range participantIndices {
		if idx >= 0 && idx < numPubKeys {
			participantSet[idx] = true
		}
	}
	expectedAPK := seed
	for i := 0; i < numPubKeys; i++ {
		if participantSet[i] {
			expectedAPK.Add(&expectedAPK, &points[i])
		}
	}

	// Compute Poseidon2 commitment
	commitment := apk.NativePublicKeysCommitment(points)

	return &apk.APKProofCircuit{
		PublicKeys:          pubKeys,
		Bitlist:             bitlist,
		Seed:                sw_bls12381.NewG1Affine(seed),
		PublicKeysCommitment: commitment,
		ExpectedAPK:         sw_bls12381.NewG1Affine(expectedAPK),
	}, nil
}

func parseG1(data []byte) (bls12381.G1Affine, error) {
	var pt bls12381.G1Affine
	var x, y fp.Element
	x.SetBytes(data[0:48])
	y.SetBytes(data[48:96])
	pt.X = x
	pt.Y = y
	return pt, nil
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func beUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func setError(result *C.CProveResult, msg string) {
	result.error = C.CString(msg)
}

func copyToResult(result *C.CProveResult, proofBytes, pubBytes []byte) {
	result.proof_len = C.uint32_t(len(proofBytes))
	result.proof_data = (*C.uint8_t)(C.CBytes(proofBytes))
	result.public_inputs_len = C.uint32_t(len(pubBytes))
	result.public_inputs_data = (*C.uint8_t)(C.CBytes(pubBytes))
	result.error = nil
}

// APKGenerateTestWitness generates a valid test witness with random BLS12-381
// points. This is for integration testing only.
//
//export APKGenerateTestWitness
func APKGenerateTestWitness(numParticipants C.uint32_t, seed C.int64_t, result *C.CBuffer) C.int32_t {
	rng := rand.New(rand.NewSource(int64(seed)))

	_, _, G, _ := bls12381.Generators()

	// Generate seed point
	var seedScalar fr.Element
	seedScalar.SetRandom()
	var seedPoint bls12381.G1Affine
	seedPoint.ScalarMultiplication(&G, seedScalar.BigInt(new(big.Int)))

	// Generate 1024 random public keys
	points := make([]bls12381.G1Affine, numPubKeys)
	for i := range points {
		var s fr.Element
		s.SetRandom()
		points[i].ScalarMultiplication(&G, s.BigInt(new(big.Int)))
	}

	// Select participants
	n := int(numParticipants)
	if n > numPubKeys {
		n = numPubKeys
	}
	indices := make([]int, numPubKeys)
	for i := range indices {
		indices[i] = i
	}
	for i := len(indices) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}
	participants := indices[:n]

	// Serialize: [1024 x 96-byte G1] [4-byte count] [n x 2-byte indices] [96-byte seed]
	bufSize := numPubKeys*g1Size + 4 + n*2 + g1Size
	buf := make([]byte, bufSize)
	offset := 0

	// Public keys
	for i := range points {
		xBytes := points[i].X.Bytes()
		yBytes := points[i].Y.Bytes()
		copy(buf[offset:offset+48], xBytes[:])
		copy(buf[offset+48:offset+96], yBytes[:])
		offset += g1Size
	}

	// Participation count + indices
	binary.BigEndian.PutUint32(buf[offset:], uint32(n))
	offset += 4
	for _, idx := range participants {
		binary.BigEndian.PutUint16(buf[offset:], uint16(idx))
		offset += 2
	}

	// Seed point
	xBytes := seedPoint.X.Bytes()
	yBytes := seedPoint.Y.Bytes()
	copy(buf[offset:offset+48], xBytes[:])
	copy(buf[offset+48:offset+96], yBytes[:])

	result.data = (*C.uint8_t)(C.CBytes(buf))
	result.len = C.uint32_t(len(buf))
	return 0
}

//export APKFreeBuffer
func APKFreeBuffer(buf *C.CBuffer) {
	if buf.data != nil {
		C.free(unsafe.Pointer(buf.data))
	}
}

func main() {}
