package apk

import (
	"math/big"
	"math/rand"

	"github.com/consensys/gnark/frontend"
	
)

// CreateBitlist creates a bitlist array with a specified number of randomly set bits
// numBitsToSet: the number of bits to randomly set (0-1024)
// Returns: a [5]frontend.Variable array formatted for the circuit and the indices that were set
func CreateBitlist(numBitsToSet int) ([5]frontend.Variable, []int) {
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

// CreateBitlistFromIndices creates a bitlist array from specific indices
// indices: the indices of bits to set (0-1023)
// Returns: a [5]frontend.Variable array formatted for the circuit
func CreateBitlistFromIndices(indices []int) [5]frontend.Variable {
	bitlist := [5]frontend.Variable{}

	// Initialize all elements to zero
	for i := 0; i < 5; i++ {
		bitlist[i] = new(big.Int)
	}

	// Set bits at specified indices
	for _, idx := range indices {
		if idx < 0 || idx >= 1024 {
			continue // Skip invalid indices
		}

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

	return bitlist
}

// DecodeBitlist decodes a bitlist to get the indices of set bits
// bitlist: the [5]frontend.Variable array to decode
// Returns: a slice of indices where bits are set
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
			// First 4 elements: 250 bits each
			bitsToCheck = 250
			startIdx = elemIdx * 250
		} else {
			// Last element: 24 bits (indices 1000-1023)
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
// bitlist: the [5]frontend.Variable array to count
// Returns: the number of bits set
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
