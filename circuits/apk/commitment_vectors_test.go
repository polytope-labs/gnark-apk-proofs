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
// Poseidon2 parameters or the limb packing (see LimbsPerElement) ever change,
// both this test and the Rust test must be regenerated together.
func TestCommitmentVectors(t *testing.T) {
	want := map[int]string{
		1:  "4df3ca8a29f6b37c04fefb167022ae638df17383caf668b718bf3b65aa320652",
		2:  "20b814b4a4cd0249ffee16a12c0e883eac49a18e91f104e0c777d7de9a797267",
		3:  "1d8d8ce5d1437ebe81c7a10c59d25ec6f53bffb9966d019f460157750a7a1cff",
		10: "5f9529f2a793ad64450341a6ef732dc1e1b71ddcca7d83f3704ff5e637a4b3bd",
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
