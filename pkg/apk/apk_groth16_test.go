package apk

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/stretchr/testify/assert"
)

// Groth16Harness encapsulates all components needed for Groth16 proving
type Groth16Harness struct {
	CS  constraint.ConstraintSystem
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey
	PKV groth16.ProvingKey // Optional: for verifying key verification
}

// SetupGroth16 compiles the circuit and performs trusted setup
func SetupGroth16(t *testing.T) (*Groth16Harness, error) {
	t.Log("Setting up Groth16 proving system...")

	// Create an empty circuit for compilation
	circuit := APKProofCircuit{}

	// Compile the circuit
	t.Log("Compiling circuit...")
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}

	t.Logf("Circuit compiled successfully. Number of constraints: %d", cs.GetNbConstraints())

	// Perform trusted setup
	t.Log("Performing trusted setup (generating proving and verifying keys)...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}

	t.Log("Trusted setup completed successfully")

	return &Groth16Harness{
		CS: cs,
		PK: pk,
		VK: vk,
	}, nil
}

// GenerateWitness creates a witness with random or specified participation
type WitnessConfig struct {
	NumParticipants int   // Number of participants (bits set)
	UseRandom       bool  // If true, randomly select participants
	SpecificIndices []int // If UseRandom is false, use these indices
	Seed            int64 // Random seed for reproducibility
}

func GenerateWitness(t *testing.T, config WitnessConfig) *APKProofCircuit {
	if config.Seed != 0 {
		rand.Seed(config.Seed)
	}

	numPoints := 1024

	// Get the generator point for BLS12-381 G1
	_, _, G, _ := bls12381.Generators()

	var seed fr.Element
	seed.SetRandom()

	var init bls12381.G1Affine
	init.ScalarMultiplication(&G, seed.BigInt(new(big.Int)))

	// Generate random points
	points := make([]bls12381.G1Affine, numPoints)
	for i := range numPoints {
		var scalar fr.Element
		scalar.SetRandom()
		points[i].ScalarMultiplication(&G, scalar.BigInt(new(big.Int)))
	}

	// Convert to sw_emulated points
	var pubKeys [1024]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range numPoints {
		pubKeys[i] = sw_bls12381.NewG1Affine(points[i])
	}

	// Create bitlist based on config
	var bitlist [5]frontend.Variable
	var participantIndices []int

	if config.UseRandom {
		bitlist, participantIndices = CreateBitlist(config.NumParticipants)
		t.Logf("Generated random bitlist with %d participants", config.NumParticipants)
	} else {
		bitlist = CreateBitlistFromIndices(config.SpecificIndices)
		participantIndices = config.SpecificIndices
		t.Logf("Generated bitlist with specific indices: %v", config.SpecificIndices)
	}

	// Calculate expected partial sum
	expectedPartialSum := init
	for _, idx := range participantIndices {
		if idx >= 0 && idx < numPoints {
			expectedPartialSum.Add(&expectedPartialSum, &points[idx])
		}
	}

	// Calculate expected total sum
	expectedTotalSum := init
	for i := range numPoints {
		expectedTotalSum.Add(&expectedTotalSum, &points[i])
	}

	return &APKProofCircuit{
		PublicKeys:         pubKeys,
		Bitlist:            bitlist,
		ExpectedPartialSum: sw_bls12381.NewG1Affine(expectedPartialSum),
		ExpectedTotalSum:   sw_bls12381.NewG1Affine(expectedTotalSum),
		Seed:               sw_bls12381.NewG1Affine(init),
	}
}

// TestGroth16ProveAndVerify tests the full Groth16 pipeline
func TestGroth16ProveAndVerify(t *testing.T) {
	// Setup the proving system
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	// Test cases with different participation levels
	testCases := []struct {
		name   string
		config WitnessConfig
	}{
		{
			name: "Small participation (10 keys)",
			config: WitnessConfig{
				NumParticipants: 10,
				UseRandom:       true,
				Seed:            42,
			},
		},
		{
			name: "Medium participation (100 keys)",
			config: WitnessConfig{
				NumParticipants: 100,
				UseRandom:       true,
				Seed:            43,
			},
		},
		{
			name: "Large participation (500 keys)",
			config: WitnessConfig{
				NumParticipants: 500,
				UseRandom:       true,
				Seed:            44,
			},
		},
		{
			name: "Deterministic participation",
			config: WitnessConfig{
				UseRandom:       false,
				SpecificIndices: []int{0, 10, 100, 500, 1000, 1023},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate witness
			witness := GenerateWitness(t, tc.config)

			// Create the witness
			t.Log("Creating witness...")
			fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
			assert.NoError(t, err, "Failed to create witness")

			// Generate the proof
			t.Log("Generating proof...")
			startProve := time.Now()
			proof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
			proveTime := time.Since(startProve)
			assert.NoError(t, err, "Failed to generate proof")
			t.Logf("Proof generated in %v", proveTime)

			// Extract public witness for verification
			publicWitness, err := fullWitness.Public()
			assert.NoError(t, err, "Failed to extract public witness")

			// Verify the proof
			t.Log("Verifying proof...")
			startVerify := time.Now()
			err = groth16.Verify(proof, harness.VK, publicWitness)
			verifyTime := time.Since(startVerify)
			assert.NoError(t, err, "Proof verification failed")
			t.Logf("Proof verified successfully in %v", verifyTime)
		})
	}
}

// TestGroth16InvalidProof tests that invalid proofs are rejected
func TestGroth16InvalidProof(t *testing.T) {
	// Setup the proving system
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	// Generate a valid witness
	witness := GenerateWitness(t, WitnessConfig{
		NumParticipants: 50,
		UseRandom:       true,
		Seed:            123,
	})

	// Create the witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err, "Failed to create witness")

	// Generate a valid proof
	t.Log("Generating valid proof...")
	validProof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
	assert.NoError(t, err, "Failed to generate proof")

	// Create a different witness (with different public inputs)
	differentWitness := GenerateWitness(t, WitnessConfig{
		NumParticipants: 100, // Different number of participants
		UseRandom:       true,
		Seed:            456,
	})

	differentFullWitness, err := frontend.NewWitness(differentWitness, ecc.BLS12_381.ScalarField())
	assert.NoError(t, err, "Failed to create different witness")

	// Extract public witness from the different witness
	wrongPublicWitness, err := differentFullWitness.Public()
	assert.NoError(t, err, "Failed to extract wrong public witness")

	// Try to verify the valid proof with wrong public inputs
	t.Log("Attempting to verify proof with wrong public inputs...")
	err = groth16.Verify(validProof, harness.VK, wrongPublicWitness)
	assert.Error(t, err, "Proof should not verify with wrong public inputs")
	t.Log("Invalid proof correctly rejected")
}

// TestGroth16EdgeCases tests edge cases like all bits set and no bits set
func TestGroth16EdgeCases(t *testing.T) {
	// Setup the proving system
	harness, err := SetupGroth16(t)
	assert.NoError(t, err, "Failed to setup Groth16")

	testCases := []struct {
		name   string
		config WitnessConfig
	}{
		{
			name: "No participants (only seed)",
			config: WitnessConfig{
				NumParticipants: 0,
				UseRandom:       true,
			},
		},
		{
			name: "All participants (1024 keys)",
			config: WitnessConfig{
				NumParticipants: 1024,
				UseRandom:       false,
				SpecificIndices: func() []int {
					indices := make([]int, 1024)
					for i := range indices {
						indices[i] = i
					}
					return indices
				}(),
			},
		},
		{
			name: "Single participant",
			config: WitnessConfig{
				UseRandom:       false,
				SpecificIndices: []int{512},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate witness
			witness := GenerateWitness(t, tc.config)

			// Create the witness
			fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_381.ScalarField())
			assert.NoError(t, err, "Failed to create witness")

			// Generate and verify proof
			proof, err := groth16.Prove(harness.CS, harness.PK, fullWitness)
			assert.NoError(t, err, "Failed to generate proof")

			publicWitness, err := fullWitness.Public()
			assert.NoError(t, err, "Failed to extract public witness")

			err = groth16.Verify(proof, harness.VK, publicWitness)
			assert.NoError(t, err, "Proof verification failed")

			t.Log("Edge case proof verified successfully")
		})
	}
}
