# gnark-apk-proofs

Zero-knowledge proofs for BLS G1 aggregated public key (APK) verification, built with [gnark](https://github.com/consensys/gnark). Uses the PLONK proving system with on-chain Solidity verification via EIP-2537 precompiles.

## Overview

This project implements a ZK circuit that proves correct aggregation of BLS12-381 G1 public keys for a subset of validators, as described in ["Accountable Light Client Systems for PoS Blockchains"](https://eprint.iacr.org/2022/1205) (Ciobotaru et al., 2022).

The circuit:
- Accepts 1024 validator public keys as private witnesses
- Uses a bitlist to indicate participating validators
- Verifies a Poseidon2 hash commitment to the full validator set
- Computes `apk = Seed + Σ(b_i * pk_i)` and checks it against the expected aggregate

Rogue key attacks are prevented by requiring Proof of Possession (PoP) at registration.

The on-chain verifier combines APK proof verification (PLONK) with BLS aggregate signature verification in a single call, using EIP-2537 precompiles for BLS12-381 curve operations. It also provides an on-chain `hashToG1` function compatible with [w3f/bls](https://github.com/w3f/bls).

## Proving backends (CPU / GPU)

The circuit (1024 validators, ~3.3M constraints) proves under either backend; both produce identical proofs verified by the same Solidity/Rust verifier.

| Backend | Build | Hardware | Prove time |
|---|---|---|---|
| **CPU** (default) | `go build` / `cargo build` | any | ~17s |
| **GPU** (CUDA) | `go build -tags cuda` / `cargo build --features cuda` | NVIDIA + CUDA | **~4.2s** (RTX 5090) |

Both measured at domain 2^22. For reference the GPU took ~12.5s at the previous
2^23 domain, so the domain halving is worth roughly 3x on GPU — the NTT/MSM work
the GPU accelerates is domain-bound. Note the two GPU figures come from
different RTX 5090 hosts, so treat the ratio as indicative rather than exact.

The GPU path is a device-resident PLONK prover built on a [gnark fork](https://github.com/polytope-labs/gnark) (`gpu-plonk-prover` branch) + [libgnark_cuda](https://github.com/polytope-labs/gnark-cuda) (icicle/CUDA). It keeps the proof's polynomials on the device across the whole pipeline and is gated entirely behind `-tags cuda` — the default build is unchanged CPU-only. Building it requires libgnark_cuda + icicle at build time:

```bash
cd circuits
CGO_CFLAGS="-I<gnark-cuda>/include" \
CGO_LDFLAGS="-L<gnark-cuda>/build -L<icicle-install>/lib -L/usr/local/cuda/lib64" \
go test -tags cuda -run TestPlonkProveAndVerify -timeout 30m ./apk/
```

### GPU from the Rust prover

The Rust prover builds CPU-only by default; enable the icicle GPU backend with the `cuda` feature — **no env vars at build or run time**:

```toml
gnark-apk-prover = { git = "https://github.com/polytope-labs/gnark-apk-proofs", features = ["cuda"] }
```

`build.rs` fetches and builds pinned [`open-icicle`](https://github.com/ingonyama-zk/open-icicle) + [`gnark-cuda`](https://github.com/polytope-labs/gnark-cuda) from source and links them **statically** into the binary. The result is self-contained: it runs with no `LD_LIBRARY_PATH` and no `ICICLE_BACKEND_INSTALL_DIR` — the CUDA backend is `--whole-archive`d in and registers at startup (no dlopen). The only non-system runtime dependency is the stock CUDA runtime (`libcudart`), already on any CUDA host's loader path (the CUDA runtime stays dynamic on purpose — static `cudart` breaks kernel launches). It needs the **CUDA toolkit, CMake ≥ 3.24, and git** on a machine with an NVIDIA GPU (the CUDA arch is auto-detected via `native`); the first `--features cuda` build compiles icicle's kernels (~15 min), later builds are incremental.

> **CMake 3.24 is a hard minimum.** `build.rs` configures icicle with
> `-DCMAKE_CUDA_ARCHITECTURES=native`, which CMake only understands from 3.24.
> Older CMake (Ubuntu 22.04 ships 3.22) expands it to an empty architecture and
> the build dies inside compiler detection with a misleading
> `nvcc fatal : Unsupported gpu architecture 'compute_'`. Install a newer CMake
> rather than chasing the nvcc error.

Blackwell cards (RTX 5090, `sm_120`) additionally need **CUDA ≥ 12.8** — earlier toolkits cannot target the architecture, so the failure appears when compiling icicle's kernels rather than at runtime.

```bash
cargo test -p gnark-plonk-verifier --features gnark-apk-prover/cuda -- --ignored --nocapture
```

CI runs the CPU backend (the GPU build needs a CUDA host).

## Project Structure

```
gnark-apk-proofs/
├── Cargo.toml                 # Rust workspace root
├── circuits/                  # Go ZK circuit code
│   ├── go.mod
│   ├── apk/                   # APK proof circuit + tests
│   ├── ffi/                   # CGo exports for Rust FFI
│   └── srs/                   # SRS download + caching from Filecoin ceremony
├── rust/                      # Rust proving library
│   ├── ffi/                   # Low-level FFI bindings (builds Go into static archive)
│   ├── prover/                # Safe Rust API with builder pattern
│   └── verifier/              # Pure-Rust PLONK verifier (arkworks) + e2e tests
├── solidity/                  # Foundry/Solidity contracts
│   ├── foundry.toml
│   └── contracts/
│       ├── PlonkVerifier.sol  # Auto-generated gnark PLONK verifier
│       └── ApkProof.sol       # APK proof + BLS signature verifier + hashToG1
└── README.md
```

## Performance

**Circuit:** BLS G1 public key aggregation (1024 validators, Poseidon2 commitment)

### Constraint Count

| System | Constraint Type | Count     | FFT domain |
|--------|-----------------|-----------|------------|
| PLONK  | SCS             | 3,027,309 | 2^22       |

PLONK proving cost tracks the FFT domain size — the next power of two at or above
the constraint count — not the constraint count itself. Getting under
2^22 = 4,194,304 is therefore what matters, and two changes together achieved it
from an original 7,097,608:

**Limb packing (−2,457,600).** Each public key coordinate is emulated as six
64-bit limbs. Those limbs are packed three at a time into native field elements
before hashing, so a point costs four Poseidon2 compressions instead of twelve —
4,096 compressions over the validator set rather than 12,288. Three limbs span
192 bits, comfortably inside the 255-bit native field, so the packing is
injective and the commitment binds exactly as tightly as hashing limbs
individually.

**Incomplete point addition with a coset seed (−1,612,699).** Aggregation uses
`curve.Add`, the affine chord formula, rather than the complete
`curve.AddUnified`. `Add` is only valid while the two points have distinct
x-coordinates: in the degenerate case its λ constraint stops determining λ,
which would let a prover steer the accumulator and forge an aggregate. The
degenerate case is made unreachable by construction rather than by an in-circuit
guard: the protocol seed is a point on E(Fp) that is deliberately **not** in the
G1 subgroup (SSWU map without cofactor clearing), so the accumulator
`seed + Σ pk_i` lives in the coset `seed + G1`, disjoint from G1 — it can never
equal `±pk_i` or reach infinity, for participants and non-participants alike.
This is the construction of Ciobotaru et al. (eprint 2022/1205, §5.1), and it
costs zero constraints. `TestProtocolSeedOutsideSubgroup` locks the invariant;
`TestProtocolSeedVectors` locks the coordinates against the copy in
`ApkProof.sol`.

The coset argument leans on every **committed** key being in G1 — a property the
circuit cannot check and does not try to. It is not enforced by the in-circuit
constraints, nor by the FFI `ParseG1` (which runs only in the honest prover; a
malicious prover supplies the witness directly and bypasses it). It holds
because `PublicKeysCommitment` is a *trusted input*: the verifier checks the
proof against the committee commitment fixed by chain consensus, and the binding
commitment pins the prover to exactly those keys. So soundness reduces to "the
committee commitment is over G1 keys", which is committee registration's job.
Note a Proof-of-Possession does not establish this alone — for `Q = pk + T` with
`T` of cofactor order the pairing annihilates `T`, so a PoP verifies for a non-G1
`Q` unless registration also runs an explicit subgroup check (BLS `KeyValidate`).
This matches the paper's model, where key validity is a precondition delegated to
a trusted party rather than proven in the SNARK.

On-chain this is transparent: the contract adds the seed to the caller's APK via
the EIP-2537 `G1ADD` precompile, which checks on-curve only (no subgroup check),
and the seed never reaches the pairing precompile — the BLS check uses the APK
alone.

Note that identity points `(0,0)` are not neutral under aggregation. Padding
unused validator slots with the identity is fine — those slots are
non-participants, so the result is discarded by the participation `Select` — but
marking a padded slot as participating fails the proof instead of silently
contributing nothing.

Constraint-system solving, the one phase that scales with constraint count
rather than domain size, is a minor term throughout: 2.10s at 7.1M vs 2.04s at
4.64M. Solving is dominated by emulated-field hints in the point arithmetic, not
by the hash.

The prove-time figures below were measured at 3,284,333 constraints (an earlier
revision with an in-circuit x-collision guard instead of the coset seed); the
FFT domain is unchanged at 2^22, so they carry over.

### Off-chain (Go)

| Phase       | CPU     | GPU (RTX 5090) |
|-------------|---------|----------------|
| Compile     | 2.7s    | 2.7s           |
| Setup       | 3.9s    | 3.9s           |
| Witness gen | 98ms    | 98ms           |
| Solve       | 2.0s    | 0.65s          |
| Prove       | 17.4s   | **4.2s**       |
| Verify      | 3.1ms   | 3.1ms          |

Both at domain 2^22. Compile, setup and witness generation are backend-independent.

On CPU the same machine took 68.5s to prove at domain 2^23 before the addition
change — a 3.9x improvement, more than the ~2x the domain halving alone predicts,
since the smaller constraint system also eases memory pressure on the RAM-heavy
CPU path. The GPU figure was measured on a separate RTX 5090 host, so it is not
directly comparable to the CPU column on absolute hardware terms.

Setup additionally needs a Lagrange-basis SRS matching the domain exactly. It is
derived locally from the canonical SRS on first use (~1 minute) and cached per
power as `plonk_srs_p<power>.lagrange`, so only the first run pays for it. The
canonical SRS is basis-independent and reused across powers rather than
re-downloaded.

### On-chain (Solidity, EIP-2537, Prague EVM)

| Operation                       | Gas     |
|---------------------------------|---------|
| Full verify (APK proof + BLS)   | 550,840 |
| hashToG1                        | 38,256  |

| Metric            | Value                |
|-------------------|----------------------|
| Proof size        | 1,184 bytes          |
| Public inputs     | 576 bytes (18 x uint256) |

PLONK uses a universal SRS (no per-circuit trusted setup). Requires Pectra hardfork (EIP-2537 BLS12-381 precompiles).

## Solidity Contract

The `ApkProof` contract provides:

1. **`verify()`** — Combined APK proof + BLS aggregate signature verification in one call
2. **`hashToG1()`** — On-chain hash-to-curve (RFC 9380) compatible with [w3f/bls](https://github.com/w3f/bls)

```solidity
// Hash a message to G1 (w3f/bls compatible, cipher suite prepended internally)
bytes32[3] memory h_m = apkProof.hashToG1(message);

// Verify APK proof + BLS signature
apkProof.verify(
    commitment,                    // publicKeysCommitment (Poseidon2 over the validator set)
    bitlist,                       // uint256[5]
    aggregatePublicKey,            // apk ∈ G1, bytes32[3] — seed added on-chain
    plonkProof,
    h_m,                           // H(m) ∈ G1, bytes32[3]
    aggregateSignature,            // bytes32[3]
    aggregatePublicKeyG2           // bytes32[6]
);
```

## Rust Library

The Rust crate provides a builder-pattern API for generating proofs, backed by the Go gnark prover via static FFI.

### Usage as a dependency

```toml
[dependencies]
gnark-apk-prover = { git = "https://github.com/polytope-labs/gnark-apk-proofs", branch = "main" }
```

**Requires Go 1.25+** installed — the build script compiles the Go circuit code into a static archive that is linked into your Rust binary. No shared libraries needed at runtime.

### Example

```rust
use gnark_apk_prover::{ProofBuilder, G1Affine, ProverContext};

// One-time setup (expensive: ~45s for PLONK)
// SRS is cached at $HOME/.config/gnark-apk-proofs/srs (downloaded automatically on first run)
let ctx = ProverContext::setup(None)?;

// Build and generate a proof
let proof = ProofBuilder::new(&ctx)
    .public_keys(validator_keys)   // Vec<G1Affine>, exactly 1024
    .participation(indices)         // Vec<u16>, participating validator indices
    .prove()?;

// proof.proof_bytes  — ready for Solidity verifier (1184 bytes)
// proof.public_inputs — 576 bytes (18 x uint256)
```

### Build

```bash
cargo build
```

### End-to-end test

Generates a PLONK proof via Go FFI, signs with BLS (using w3f/bls hash-to-curve), and verifies on-chain in revm:

```bash
cargo test -p gnark-plonk-verifier --test bls_verify -- --ignored --nocapture
```

## Go Circuit

### Prerequisites

- Go 1.25+
- [Foundry](https://book.getfoundry.sh/) (for Solidity compilation)

### Run circuit tests

```bash
cd circuits
go test -v -timeout 30m ./apk/
```

### Generate Solidity verifier and proof fixtures

```bash
cd circuits
go test -v -run "TestExportPlonkForFoundry" -timeout 30m ./apk/
```

## References

- [gnark](https://github.com/consensys/gnark) — ZKP framework
- [Accountable Light Client Systems for PoS Blockchains](https://eprint.iacr.org/2022/1205) — Ciobotaru et al., 2022
- [Efficient Aggregatable BLS Signatures with Chaum-Pedersen Proofs](https://eprint.iacr.org/2022/1611) — BLS scheme
- [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) — BLS12-381 precompiles
- [w3f/bls](https://github.com/w3f/bls) — Web3 Foundation BLS library

## License

Apache License 2.0
