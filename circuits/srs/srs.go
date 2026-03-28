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

// Package srs downloads and manages BLS12-381 KZG structured reference strings
// from the Filecoin Phase 1 Powers of Tau ceremony for use with gnark's PLONK prover.
package srs

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

const (
	// Filecoin Phase 1 ceremony raw challenge file (monomial basis).
	CeremonyURL = "https://trusted-setup.filecoin.io/phase1/challenge_19"

	g1Size = 96  // 48-byte X + 48-byte Y, big-endian
	g2Size = 192 // two Fp2 coordinates, each 2×48 bytes

	hashSize    = 64
	maxG1Count  = (1 << 28) - 1
	g1TauOffset = hashSize
	g2TauOffset = g1TauOffset + g1Size*maxG1Count

	numPairingChecks = 16
)

// DefaultDir returns the default SRS storage directory: $HOME/.config/gnark-apk-proofs/srs.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gnark-apk-proofs", "srs")
}

// LoadDefault loads the SRS from the default directory.
func LoadDefault(power int) (*kzg.SRS, *kzg.SRS, error) {
	return Load(DefaultDir(), power)
}

// Load reads canonical and Lagrange KZG SRS files from the given directory,
// downloading them from the Filecoin ceremony if they don't exist.
// The power parameter is log2 of the domain size (e.g. 23 for ~8M constraints).
func Load(dir string, power int) (*kzg.SRS, *kzg.SRS, error) {
	canonicalPath := dir + "/plonk_srs.canonical"
	lagrangePath := dir + "/plonk_srs.lagrange"

	if !fileExists(canonicalPath) || !fileExists(lagrangePath) {
		fmt.Printf("[srs] SRS files not found in %s, downloading from Filecoin ceremony...\n", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, fmt.Errorf("create SRS directory: %w", err)
		}
		if err := Download(power, dir+"/plonk_srs"); err != nil {
			return nil, nil, fmt.Errorf("download SRS: %w", err)
		}
		fmt.Printf("[srs] Download complete.\n")
	}

	var canonical, lagrange kzg.SRS
	if err := readSRS(canonicalPath, &canonical); err != nil {
		return nil, nil, err
	}
	if err := readSRS(lagrangePath, &lagrange); err != nil {
		return nil, nil, err
	}
	return &canonical, &lagrange, nil
}

// Download fetches the SRS from the Filecoin ceremony and writes
// <outputPrefix>.canonical and <outputPrefix>.lagrange files.
func Download(power int, outputPrefix string) error {
	if power < 1 || power > 27 {
		return fmt.Errorf("power must be between 1 and 27, got %d", power)
	}

	domainSize := 1 << power
	canonicalSize := domainSize + 3

	fmt.Printf("[srs] Downloading Phase 1 KZG SRS for PLONK (domain 2^%d = %d)\n", power, domainSize)
	fmt.Printf("[srs]   G1 tau: %d points (%d MB)\n", canonicalSize, canonicalSize*g1Size/1024/1024)

	g1TauBytes, err := downloadRange("G1 tau", g1TauOffset, canonicalSize*g1Size)
	if err != nil {
		return err
	}
	g2TauBytes, err := downloadRange("G2 tau", g2TauOffset, 2*g2Size)
	if err != nil {
		return err
	}

	fmt.Printf("[srs] Parsing and validating curve points...\n")
	g1Tau, err := parseG1Points(g1TauBytes, canonicalSize)
	if err != nil {
		return fmt.Errorf("parse G1 tau: %w", err)
	}
	g2Tau, err := parseG2Points(g2TauBytes, 2)
	if err != nil {
		return fmt.Errorf("parse G2 tau: %w", err)
	}

	_, _, g1Gen, g2Gen := bls12381.Generators()
	if !g1Tau[0].Equal(&g1Gen) {
		return fmt.Errorf("g1Tau[0] is not the G1 generator")
	}
	if !g2Tau[0].Equal(&g2Gen) {
		return fmt.Errorf("g2Tau[0] is not the G2 generator")
	}

	fmt.Printf("[srs] Running %d pairing consistency checks...\n", numPairingChecks)
	if err := verifyTauConsistency(g1Tau, g2Tau); err != nil {
		return err
	}

	fmt.Printf("[srs] Building canonical KZG SRS...\n")
	var canonical kzg.SRS
	canonical.Pk.G1 = g1Tau
	canonical.Vk.G2[0] = g2Tau[0]
	canonical.Vk.G2[1] = g2Tau[1]
	canonical.Vk.G1 = g1Gen
	canonical.Vk.Lines[0] = bls12381.PrecomputeLines(g2Tau[0])
	canonical.Vk.Lines[1] = bls12381.PrecomputeLines(g2Tau[1])

	fmt.Printf("[srs] Computing Lagrange basis via inverse DFT on %d G1 points...\n", domainSize)
	lagrangeG1 := make([]bls12381.G1Affine, domainSize)
	copy(lagrangeG1, g1Tau[:domainSize])

	startLag := time.Now()
	lagrangeG1, err = kzg.ToLagrangeG1(lagrangeG1)
	if err != nil {
		return fmt.Errorf("compute Lagrange basis: %w", err)
	}
	fmt.Printf("[srs] Lagrange basis computed in %v\n", time.Since(startLag).Round(time.Second))

	var lagrange kzg.SRS
	lagrange.Pk.G1 = lagrangeG1
	lagrange.Vk = canonical.Vk

	if err := writeSRS(outputPrefix+".canonical", &canonical); err != nil {
		return err
	}
	if err := writeSRS(outputPrefix+".lagrange", &lagrange); err != nil {
		return err
	}
	return nil
}

// --- File I/O ---

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readSRS(path string, srs *kzg.SRS) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := srs.ReadFrom(f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func writeSRS(path string, srs *kzg.SRS) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	n, err := srs.WriteTo(f)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("[srs] Wrote %s (%d MB)\n", path, n/1024/1024)
	return nil
}

// --- Download ---

func downloadRange(label string, offset, length int) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	req, err := http.NewRequest("GET", CeremonyURL, nil)
	if err != nil {
		return nil, err
	}
	end := offset + length - 1
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))

	totalMB := float64(length) / 1024 / 1024
	fmt.Printf("[srs]   [%s] Downloading %.1f MB (offset %d)...\n", label, totalMB, offset)
	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	data := make([]byte, 0, length)
	buf := make([]byte, 256*1024)
	var downloaded int
	lastLog := start
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			downloaded += n
			if now := time.Now(); now.Sub(lastLog) >= 2*time.Second {
				pct := float64(downloaded) / float64(length) * 100
				dlMB := float64(downloaded) / 1024 / 1024
				elapsed := now.Sub(start).Seconds()
				mbps := dlMB / elapsed
				fmt.Printf("[srs]   [%s] %.1f / %.1f MB (%.0f%%) — %.1f MB/s\n", label, dlMB, totalMB, pct, mbps)
				lastLog = now
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read failed: %w", readErr)
		}
	}
	if len(data) != length {
		return nil, fmt.Errorf("expected %d bytes, got %d", length, len(data))
	}

	elapsed := time.Since(start)
	mbps := float64(length) / 1024 / 1024 / elapsed.Seconds()
	fmt.Printf("[srs]   [%s] Done in %v (%.1f MB/s)\n", label, elapsed.Round(time.Second), mbps)
	return data, nil
}

// --- Point parsing ---

func parseG1Points(data []byte, count int) ([]bls12381.G1Affine, error) {
	points := make([]bls12381.G1Affine, count)
	for i := range count {
		off := i * g1Size
		var x, y fp.Element
		x.SetBytes(data[off : off+48])
		y.SetBytes(data[off+48 : off+96])
		points[i].X = x
		points[i].Y = y
		if !points[i].IsOnCurve() {
			return nil, fmt.Errorf("G1 point %d not on curve", i)
		}
	}
	return points, nil
}

func parseG2Points(data []byte, count int) ([]bls12381.G2Affine, error) {
	points := make([]bls12381.G2Affine, count)
	for i := range count {
		off := i * g2Size
		points[i].X.A1.SetBytes(data[off : off+48])
		points[i].X.A0.SetBytes(data[off+48 : off+96])
		points[i].Y.A1.SetBytes(data[off+96 : off+144])
		points[i].Y.A0.SetBytes(data[off+144 : off+192])
		if !points[i].IsOnCurve() {
			return nil, fmt.Errorf("G2 point %d not on curve", i)
		}
	}
	return points, nil
}

// --- Pairing verification ---

func verifyTauConsistency(g1Tau []bls12381.G1Affine, g2Tau []bls12381.G2Affine) error {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	maxIdx := len(g1Tau) - 1

	for range numPairingChecks {
		i := rng.Intn(maxIdx - 1)
		// e(g1Tau[i+1], g2Tau[0]) == e(g1Tau[i], g2Tau[1])
		var negB1 bls12381.G1Affine
		negB1.Neg(&g1Tau[i])
		ok, err := bls12381.PairingCheck(
			[]bls12381.G1Affine{g1Tau[i+1], negB1},
			[]bls12381.G2Affine{g2Tau[0], g2Tau[1]},
		)
		if err != nil {
			return fmt.Errorf("pairing check error at index %d: %w", i, err)
		}
		if !ok {
			return fmt.Errorf("tau sequential consistency check failed at index %d", i)
		}
	}
	return nil
}
