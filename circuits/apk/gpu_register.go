//go:build cuda

package apk

// Importing the cuda backend registers the GPU MSM/FFT hooks in gnark-crypto and
// enables the device-resident PLONK quotient rho-loop, so a -tags cuda build of
// this package proves on the GPU (https://github.com/polytope-labs/gnark-cuda).
import _ "github.com/consensys/gnark/backend/accelerated/cuda"
