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
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// encodeG1 serializes a point into the 96-byte FFI wire format (X || Y, big-endian).
func encodeG1(pt bls12381.G1Affine) []byte {
	xb := pt.X.Bytes()
	yb := pt.Y.Bytes()
	out := make([]byte, G1UncompressedSize)
	copy(out[0:48], xb[:])
	copy(out[48:96], yb[:])
	return out
}

// onCurveNotInSubgroup deterministically finds a point that satisfies the curve
// equation but lies outside the prime-order subgroup (BLS12-381 G1 has a large
// cofactor, so almost every on-curve point qualifies).
func onCurveNotInSubgroup(t *testing.T) bls12381.G1Affine {
	t.Helper()
	var x, one, four fp.Element
	x.SetUint64(2)
	one.SetUint64(1)
	four.SetUint64(4)
	for i := 0; i < 1000; i++ {
		var x3, rhs, y fp.Element
		x3.Square(&x).Mul(&x3, &x) // x³
		rhs.Add(&x3, &four)        // x³ + 4
		if y.Sqrt(&rhs) != nil {
			var pt bls12381.G1Affine
			pt.X = x
			pt.Y = y
			if pt.IsOnCurve() && !pt.IsInSubGroup() {
				return pt
			}
		}
		x.Add(&x, &one)
	}
	t.Fatal("failed to construct an on-curve, non-subgroup point")
	return bls12381.G1Affine{}
}

// TestParseG1_ValidGenerator confirms a canonical subgroup point round-trips.
func TestParseG1_ValidGenerator(t *testing.T) {
	_, _, g1, _ := bls12381.Generators()
	pt, err := ParseG1(encodeG1(g1))
	if err != nil {
		t.Fatalf("generator rejected: %v", err)
	}
	if !pt.Equal(&g1) {
		t.Fatal("parsed point does not equal generator")
	}
}

// TestParseG1_Identity confirms the all-zero padding encoding is accepted as
// the point at infinity (audit finding 24 / identity encoding).
func TestParseG1_Identity(t *testing.T) {
	pt, err := ParseG1(make([]byte, G1UncompressedSize))
	if err != nil {
		t.Fatalf("identity rejected: %v", err)
	}
	if !pt.IsInfinity() {
		t.Fatal("all-zero encoding did not decode to point at infinity")
	}
}

// TestParseG1_OffCurve rejects a point that fails the curve equation (finding 14).
func TestParseG1_OffCurve(t *testing.T) {
	_, _, g1, _ := bls12381.Generators()
	bad := g1
	var one fp.Element
	one.SetUint64(1)
	bad.Y.Add(&bad.Y, &one) // perturb Y so y² ≠ x³ + 4
	_, err := ParseG1(encodeG1(bad))
	if err == nil || !strings.Contains(err.Error(), "not on curve") {
		t.Fatalf("expected on-curve rejection, got %v", err)
	}
}

// TestParseG1_NotInSubgroup rejects an on-curve point outside the prime-order
// subgroup (audit findings 1, 3 enforced at the FFI boundary).
func TestParseG1_NotInSubgroup(t *testing.T) {
	pt := onCurveNotInSubgroup(t)
	if !pt.IsOnCurve() {
		t.Fatal("test point should be on curve")
	}
	_, err := ParseG1(encodeG1(pt))
	if err == nil || !strings.Contains(err.Error(), "subgroup") {
		t.Fatalf("expected subgroup rejection, got %v", err)
	}
}

// TestParseG1_WrongLength rejects malformed inputs.
func TestParseG1_WrongLength(t *testing.T) {
	for _, n := range []int{0, 48, 95, 97, 192} {
		if _, err := ParseG1(make([]byte, n)); err == nil {
			t.Fatalf("expected error for %d-byte input", n)
		}
	}
}

func TestValidateParticipationIndices_Valid(t *testing.T) {
	if err := ValidateParticipationIndices([]int{0, 1, 250, 999, 1000, 1023}, NumValidators); err != nil {
		t.Fatalf("valid indices rejected: %v", err)
	}
	if err := ValidateParticipationIndices(nil, NumValidators); err != nil {
		t.Fatalf("empty indices rejected: %v", err)
	}
}

func TestValidateParticipationIndices_OutOfRange(t *testing.T) {
	for _, idx := range []int{-1, NumValidators, NumValidators + 5} {
		err := ValidateParticipationIndices([]int{0, idx}, NumValidators)
		if err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("index %d: expected out-of-range error, got %v", idx, err)
		}
	}
}

func TestValidateParticipationIndices_Duplicate(t *testing.T) {
	err := ValidateParticipationIndices([]int{3, 7, 3}, NumValidators)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

// TestBitlistMapping_EdgeIndices locks the index→bit mapping at limb boundaries
// (audit finding 6: missing edge-case coverage) by round-tripping through decode.
func TestBitlistMapping_EdgeIndices(t *testing.T) {
	cases := [][]int{
		{0},         // first bit
		{249},       // last bit of limb 0
		{250},       // first bit of limb 1
		{999},       // last bit of limb 3
		{1000},      // first bit of limb 4
		{1023},      // last valid bit
		{0, 1023},   // both extremes
		{249, 250},  // limb 0/1 boundary
		{999, 1000}, // limb 3/4 boundary
	}
	for _, want := range cases {
		bitlist := CreateBitlistFromIndices(want)
		got := DecodeBitlist(bitlist)
		if len(got) != len(want) {
			t.Fatalf("indices %v: decoded %v", want, got)
		}
		set := make(map[int]bool)
		for _, i := range got {
			set[i] = true
		}
		for _, i := range want {
			if !set[i] {
				t.Fatalf("indices %v: missing %d in decoded %v", want, i, got)
			}
		}
	}
}
