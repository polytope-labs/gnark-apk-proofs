package apk

import (
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// TestCommitmentVectors locks the Poseidon2 PublicKeysCommitment over deterministic
// k*generator point sets, as 32-byte big-endian hex. The Rust port in
// rust/verifier/src/commitment.rs asserts the same vectors; if gnark-crypto's
// Poseidon2 parameters ever change, both this test and the Rust test must be
// regenerated together.
func TestCommitmentVectors(t *testing.T) {
	want := map[int]string{
		1:  "3b14900f1cd55f300914ca5b4393f0fa6a777d5999963f9520b12a60204272e2",
		2:  "528fad7e07c1ec6db4ad009230329123e643e1629733d60d2b4eaa9e45dc5704",
		3:  "14bac0391b3646f28d9b0b6b64acca1c8c585ade555494ce189aa2e4b62e9977",
		10: "4a401453041545fc28ebf4c3c2824f317d1c4a7b6bff644d6eb12d0edd1f64c5",
	}
	_, _, g1, _ := bls12381.Generators()
	for n, exp := range want {
		pts := make([]bls12381.G1Affine, n)
		for i := 0; i < n; i++ {
			pts[i].ScalarMultiplication(&g1, big.NewInt(int64(i+1)))
		}
		got := fmt.Sprintf("%064x", NativePublicKeysCommitment(pts))
		if got != exp {
			t.Errorf("n=%d: got %s want %s", n, got, exp)
		}
	}
}
