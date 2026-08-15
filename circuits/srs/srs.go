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

// DefaultPower is log2 of the PLONK FFT domain the APK circuit needs: the
// smallest power of two at or above its constraint count. The circuit compiles
// to 3,284,333 SCS constraints, so 2^22 = 4,194,304 covers it with headroom.
//
// Raise this if the circuit ever grows past the domain — PLONK setup fails
// outright otherwise. Note the canonical SRS may be larger than required (gnark
// checks `>=`), but the Lagrange SRS must match the domain exactly, so changing
// this invalidates any cached Lagrange basis for the old power.
const DefaultPower = 22

// LoadDefault loads the SRS from the default directory.
func LoadDefault(power int) (*kzg.SRS, *kzg.SRS, error) {
	return Load(DefaultDir(), power)
}

// Load reads canonical and Lagrange KZG SRS files from the given directory,
// downloading them from the Filecoin ceremony if they don't exist.
// The power parameter is log2 of the domain size (e.g. 22 for ~4M constraints).
//
// The canonical SRS is basis-independent, so one file serves every power at or
// below its size and is reused whenever it is large enough. The Lagrange basis
// is domain-specific and must match the requested power exactly, so it is
// cached per power and derived locally from the canonical points rather than
// re-downloaded.
func Load(dir string, power int) (*kzg.SRS, *kzg.SRS, error) {
	canonicalPath := dir + "/plonk_srs.canonical"
	lagrangePath := fmt.Sprintf("%s/plonk_srs_p%d.lagrange", dir, power)

	domainSize := 1 << power
	canonicalSize := domainSize + 3

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("create SRS directory: %w", err)
	}

	// The canonical file may have been produced for a larger power; that is
	// fine and preferred over downloading again. Only fetch when it is absent
	// or genuinely too small.
	var canonical kzg.SRS
	needDownload := true
	if fileExists(canonicalPath) {
		if err := readSRS(canonicalPath, &canonical); err != nil {
			return nil, nil, err
		}
		if len(canonical.Pk.G1) >= canonicalSize {
			needDownload = false
		} else {
			fmt.Printf("[srs] Cached canonical SRS has %d points, need %d; re-downloading.\n",
				len(canonical.Pk.G1), canonicalSize)
		}
	}
	if needDownload {
		fmt.Printf("[srs] Downloading canonical SRS for domain 2^%d from Filecoin ceremony...\n", power)
		if err := Download(power, dir+"/plonk_srs"); err != nil {
			return nil, nil, fmt.Errorf("download SRS: %w", err)
		}
		canonical = kzg.SRS{}
		if err := readSRS(canonicalPath, &canonical); err != nil {
			return nil, nil, err
		}
	}

	var lagrange kzg.SRS
	if fileExists(lagrangePath) {
		if err := readSRS(lagrangePath, &lagrange); err != nil {
			return nil, nil, err
		}
	}
	if len(lagrange.Pk.G1) != domainSize {
		// Derive the Lagrange basis for this domain from the canonical points.
		// Cheaper than another download, since the data is already local.
		fmt.Printf("[srs] Computing Lagrange basis for domain 2^%d from canonical SRS...\n", power)
		start := time.Now()
		lagrangeG1 := make([]bls12381.G1Affine, domainSize)
		copy(lagrangeG1, canonical.Pk.G1[:domainSize])
		lagrangeG1, err := kzg.ToLagrangeG1(lagrangeG1)
		if err != nil {
			return nil, nil, fmt.Errorf("compute Lagrange basis: %w", err)
		}
		lagrange = kzg.SRS{}
		lagrange.Pk.G1 = lagrangeG1
		lagrange.Vk = canonical.Vk
		fmt.Printf("[srs] Lagrange basis computed in %v\n", time.Since(start).Round(time.Second))
		if err := writeSRS(lagrangePath, &lagrange); err != nil {
			return nil, nil, err
		}
	}

	// gnark requires len(canonical) >= domain+3 and len(lagrange) == domain.
	// Fail here with a precise message rather than deep inside plonk.Setup.
	if len(canonical.Pk.G1) < canonicalSize {
		return nil, nil, fmt.Errorf("canonical SRS has %d points, need at least %d for domain 2^%d",
			len(canonical.Pk.G1), canonicalSize, power)
	}
	if len(lagrange.Pk.G1) != domainSize {
		return nil, nil, fmt.Errorf("lagrange SRS has %d points, need exactly %d for domain 2^%d",
			len(lagrange.Pk.G1), domainSize, power)
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
	// The Lagrange basis is domain-specific, so it is named per power; the
	// canonical file is basis-independent and shared across powers.
	if err := writeSRS(fmt.Sprintf("%s_p%d.lagrange", outputPrefix, power), &lagrange); err != nil {
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
	end := offset + length - 1
	totalMB := float64(length) / 1024 / 1024
	fmt.Printf("[srs]   [%s] Downloading %.1f MB (offset %d)...\n", label, totalMB, offset)
	start := time.Now()

	data := make([]byte, 0, length)
	buf := make([]byte, 256*1024)
	lastLog := start
	// The Filecoin ceremony gateway (Caddy) 502s on large ranges but serves small
	// ones fine, so fetch in chunks. Each chunk is retried as a unit (partial
	// chunk discarded) to keep resume logic simple.
	const chunkSize = 32 * 1024 * 1024
	const maxChunkRetries = 50
	for len(data) < length {
		chunkStart := offset + len(data)
		chunkLen := chunkSize
		if chunkStart+chunkLen-1 > end {
			chunkLen = end - chunkStart + 1
		}
		chunkEnd := chunkStart + chunkLen - 1
		var chunk []byte
		var ok bool
		for attempt := 0; attempt < maxChunkRetries; attempt++ {
			chunk = chunk[:0]
			client := &http.Client{Timeout: 5 * time.Minute}
			req, err := http.NewRequest("GET", CeremonyURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", chunkStart, chunkEnd))
			resp, err := client.Do(req)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				time.Sleep(2 * time.Second)
				continue
			}
			readErrFlag := false
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					chunk = append(chunk, buf[:n]...)
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					readErrFlag = true
					break
				}
			}
			resp.Body.Close()
			if !readErrFlag && len(chunk) == chunkLen {
				ok = true
				break
			}
			time.Sleep(1 * time.Second)
		}
		if !ok {
			return nil, fmt.Errorf("chunk [%d-%d] failed after retries", chunkStart, chunkEnd)
		}
		data = append(data, chunk...)
		if now := time.Now(); now.Sub(lastLog) >= 3*time.Second {
			fmt.Printf("[srs]   [%s] %.0f / %.0f MB (%.0f%%)\n", label, float64(len(data))/1024/1024, totalMB, float64(len(data))/float64(length)*100)
			lastLog = now
		}
	}
	if len(data) != length {
		return nil, fmt.Errorf("expected %d bytes, got %d after retries", length, len(data))
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
