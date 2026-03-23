# gnark-apk-proofs

Zero-knowledge proofs for BLS G1 aggregated public key (APK) verification, built with [gnark](https://github.com/consensys/gnark). Supports both Groth16 and PLONK proving systems with on-chain Solidity verification via EIP-2537 precompiles.

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
│   └── ffi/                   # CGo exports for Rust FFI
├── rust/                      # Rust proving library
│   ├── ffi/                   # Low-level FFI bindings (builds Go into static archive)
│   └── prover/                # Safe Rust API with builder pattern
├── solidity/                  # Foundry/Solidity contracts
│   ├── foundry.toml
│   └── contracts/
│       ├── Groth16Verifier.sol
│       ├── PlonkVerifier.sol
│       ├── APKVerifier.sol    # Human-readable wrapper
│       └── test/              # Gas benchmarks + proof fixtures
└── README.md
```

## Performance

**Circuit:** BLS G1 public key aggregation (1024 validators, Poseidon2 commitment)

### Constraint Counts

| System  | Constraint Type | Count     |
|---------|-----------------|-----------|
| Groth16 | R1CS            | 3,316,047 |
| PLONK   | SCS             | 7,097,960 |

### Off-chain (Go)

| Phase        | Groth16          | PLONK           |
|--------------|------------------|-----------------|
| Compile      | 15.6s            | 5.5s            |
| SRS / Setup  | 1m 55s (trusted) | 44.8s (universal) |
| Witness gen  | 157ms            | 157ms           |
| Prove        | 6.0s             | 40.0s           |
| Verify       | 2.6ms            | 3.3ms           |

### On-chain (Solidity, EIP-2537, Prague EVM)

| Metric             | Groth16          | PLONK            |
|--------------------|------------------|------------------|
| Verification gas   | 547,162          | 385,183          |
| Contract bytecode  | 9,006 bytes      | 11,607 bytes     |
| Proof size         | 576 bytes        | 1,184 bytes      |
| Public inputs      | 960 bytes (30 x uint256) | 960 bytes (30 x uint256) |

### Trade-offs

- **Groth16**: ~6.6x faster proving, but ~42% more expensive on-chain verification. Requires a per-circuit trusted setup.
- **PLONK**: Cheaper on-chain verification, universal SRS (no trusted setup), but slower proving.
- Both require Pectra hardfork (EIP-2537 BLS12-381 precompiles).

## Rust Library

The Rust crate provides a builder-pattern API for generating proofs, backed by the Go gnark prover via static FFI.

### Usage as a dependency

```toml
[dependencies]
gnark-apk-prover = { git = "https://github.com/polytope-labs/gnark-apk-proofs" }
```

**Requires Go 1.25+** installed — the build script compiles the Go circuit code into a static archive that is linked into your Rust binary. No shared libraries needed at runtime.

### Example

```rust
use gnark_apk_prover::{APKProofBuilder, Backend, G1Affine, ProverContext};

// One-time setup (expensive: ~2 min for Groth16, ~45s for PLONK)
let ctx = ProverContext::setup(Backend::Groth16)?;

// Build and generate a proof
let proof = APKProofBuilder::new()
    .public_keys(validator_keys)   // Vec<G1Affine>, exactly 1024
    .participation(indices)         // Vec<u16>, participating validator indices
    .seed(seed_point)               // G1Affine
    .prove(&ctx)?;

// proof.proof_bytes  — ready for Solidity verifier (576 bytes Groth16 / 1184 PLONK)
// proof.public_inputs — 960 bytes (30 x uint256)
```

### Run Rust tests

```bash
# Fast compile check
cargo build

# Integration test (generates a real proof, ~2 min)
cargo test -- --ignored
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

### Generate Solidity verifiers and proof fixtures

```bash
cd circuits
go test -v -run "TestExportGroth16ForFoundry" -timeout 30m ./apk/
go test -v -run "TestExportPlonkForFoundry" -timeout 30m ./apk/
```

## Solidity Verifiers

The `APKVerifier` contract provides a human-readable API that accepts raw BLS12-381 G1 points (96-byte uncompressed format) and handles the gnark witness encoding internally. It takes a single `IProofVerifier` backend (either `Groth16VerifierAdapter` or `PlonkVerifierAdapter`):

```solidity
apkVerifier.verify(proof, APKPublicInputs({
    bitlist: [...],
    publicKeysCommitment: ...,
    seed: seedBytes,                // 96-byte G1 point
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
