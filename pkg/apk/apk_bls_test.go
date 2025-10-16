package apk

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// createBitlist creates a bitlist array with a specified number of randomly set bits
// numBitsToSet: the number of bits to randomly set (0-1024)
// Returns: a [5]frontend.Variable array formatted for the circuit and the indices that were set
func createBitlist(numBitsToSet int) ([5]frontend.Variable, []int) {
	bitlist := [5]frontend.Variable{}

	// Initialize all elements to zero
	for i := 0; i < 5; i++ {
		bitlist[i] = new(big.Int)
	}

	if numBitsToSet <= 0 || numBitsToSet > 1024 {
		return bitlist, []int{}
	}

	// Create a list of all possible indices and shuffle to get random selection
	allIndices := make([]int, 1024)
	for i := range allIndices {
		allIndices[i] = i
	}

	// Fisher-Yates shuffle to randomize
	for i := len(allIndices) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		allIndices[i], allIndices[j] = allIndices[j], allIndices[i]
	}

	// Take the first numBitsToSet indices
	selectedIndices := allIndices[:numBitsToSet]

	// Set bits at selected indices
	for _, idx := range selectedIndices {
		// Determine which element and bit position
		var elemIdx int
		var bitPos int

		if idx < 1000 {
			// First 4 elements: 250 bits each
			elemIdx = idx / 250
			bitPos = idx % 250
		} else {
			// Last element: 24 bits (indices 1000-1023)
			elemIdx = 4
			bitPos = idx - 1000
		}

		// Set the bit using LSB encoding
		val := bitlist[elemIdx].(*big.Int)
		val.SetBit(val, bitPos, 1)
	}

	return bitlist, selectedIndices
}

// testSimpleAPKG1 creates a simple test case with manually selected participants
func testSimpleAPKG1(t *testing.T, numParticipants int) (circ, wit frontend.Circuit) {
	numPoints := 1024

	// Get the generator point for BLS12-381 G1
	_, _, G, _ := bls12381.Generators()

	var seed fr.Element
	seed.SetRandom()

	var init bls12381.G1Affine
	init.ScalarMultiplication(&G, seed.BigInt(new(big.Int)))

	// Generate points
	points := make([]bls12381.G1Affine, numPoints)
	scalars := make([]fr.Element, numPoints)

	for i := range numPoints {
		scalars[i].SetRandom()
		points[i].ScalarMultiplication(&G, scalars[i].BigInt(new(big.Int)))
	}

	// Convert to sw_emulated points
	var pubKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	// Create a simple bitlist with 50 random participants
	bitlist, participantIndices := createBitlist(numParticipants)

	t.Logf("Simple test: %d participants randomly selected", numParticipants)

	// Calculate expected partial sum for selected participants
	expectedPartialSum := init
	for _, idx := range participantIndices {
		expectedPartialSum.Add(&expectedPartialSum, &points[idx])
	}

	// Calculate expected total sum (all points)
	expectedTotalSum := init
	for i := range numPoints {
		expectedTotalSum.Add(&expectedTotalSum, &points[i])
	}

	// Create circuit and witness
	circuit := APKProofCircuit{}
	witness := APKProofCircuit{
		PublicKeys:         pubKeys,
		Bitlist:            bitlist,
		ExpectedPartialSum: sw_bls12381.NewG1Affine(expectedPartialSum),
		ExpectedTotalSum:   sw_bls12381.NewG1Affine(expectedTotalSum),
		Seed:               sw_bls12381.NewG1Affine(init),
	}

	return &circuit, &witness
}

func TestSimpleBLSG1APKCircuit(t *testing.T) {
	// Test with randomly selected participants
	circuit, witness := testSimpleAPKG1(t, 600)
	assert := test.NewAssert(t)
	err := test.IsSolved(circuit, witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
}

func TestAllBitsSetBLSG1APKCircuit(t *testing.T) {
	// Test with randomly selected participants
	circuit, witness := testSimpleAPKG1(t, 1024)
	assert := test.NewAssert(t)
	err := test.IsSolved(circuit, witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
}

func TestNoBitsSetBLSG1APKCircuit(t *testing.T) {
	// Test with randomly selected participants
	circuit, witness := testSimpleAPKG1(t, 0)
	assert := test.NewAssert(t)
	err := test.IsSolved(circuit, witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
}
