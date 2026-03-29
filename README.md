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
│   └── verifier/              # Pure-Rust PLONK verifier (arkworks)
├── solidity/                  # Foundry/Solidity contracts
│   ├── foundry.toml
│   └── contracts/
│       ├── PlonkVerifier.sol  # Auto-generated gnark PLONK verifier
│       ├── ApkProof.sol       # Human-readable wrapper
│       └── test/              # Gas benchmarks + proof fixtures
└── README.md
```

## Performance

**Circuit:** BLS G1 public key aggregation (1024 validators, Poseidon2 commitment)

### Constraint Count

| System | Constraint Type | Count     |
|--------|-----------------|-----------|
| PLONK  | SCS             | 7,097,960 |

### Off-chain (Go)

| Phase       | Time              |
|-------------|-------------------|
| Compile     | 5.5s              |
| SRS / Setup | 44.8s (universal) |
| Witness gen | 157ms             |
| Prove       | 40.0s             |
| Verify      | 3.3ms             |

### On-chain (Solidity, EIP-2537, Prague EVM)

| Metric            | Value                    |
|-------------------|--------------------------|
| Verification gas  | 385,183                  |
| Contract bytecode | 11,607 bytes             |
| Proof size        | 1,184 bytes              |
| Public inputs     | 960 bytes (30 x uint256) |

PLONK uses a universal SRS (no per-circuit trusted setup). Requires Pectra hardfork (EIP-2537 BLS12-381 precompiles).

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
// proof.public_inputs — 960 bytes (30 x uint256)
```

### Build

```bash
cargo build
```

### End-to-end test

Generates a PLONK proof via Go FFI and verifies it with the pure-Rust verifier:

```bash
cargo test -p gnark-plonk-verifier --test verify_proof -- --ignored
```

## Go Circuit

### Prerequisites

- Go 1.25+
- [Foundry](https://book.getfoundry.sh/) (for Solidity tests)

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

## Solidity Verifiers

The `ApkProof` contract provides a human-readable API that accepts raw BLS12-381 G1 points (96-byte uncompressed format) and handles the gnark witness encoding internally. It wraps the auto-generated `PlonkVerifier` directly:

```solidity
apkProof.verify(ApkPublicInputs({
    bitlist: [...],
    publicKeysCommitment: ...,
    apk: aggregatePublicKey         // 96-byte G1 point (seed added on-chain)
}));
```

### Run Solidity gas benchmarks

```bash
cd solidity
forge test -vvv
```

## References

- [gnark](https://github.com/consensys/gnark) — ZKP framework
- [Accountable Light Client Systems for PoS Blockchains](https://eprint.iacr.org/2022/1205) — Ciobotaru et al., 2022
- [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) — BLS12-381 precompiles

## License

Apache License 2.0
