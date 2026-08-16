# gnark-apk-proofs

Zero-knowledge proofs for BLS12-381 aggregated public key (APK) verification, with on-chain verification on Ethereum via EIP-2537 precompiles.

Given a fixed validator set and a bitlist of participants, the circuit proves that a claimed aggregate public key is the correct sum of the participating validators' keys — without revealing the individual keys. It implements the aggregation SNARK from ["Accountable Light Client Systems for PoS Blockchains"](https://eprint.iacr.org/2022/1205) (Ciobotaru et al.), built on [gnark](https://github.com/consensys/gnark)'s PLONK backend.

The repository ships three consumers of the same proof:
- a **Rust prover** (safe wrapper over the Go/gnark prover via static FFI),
- a **pure-Rust PLONK verifier** (arkworks), and
- a **Solidity verifier** that combines APK-proof verification with BLS aggregate-signature verification in one call.

## How it works

The circuit takes 1024 validator public keys (`G1`) as a **private** witness, and three **public** inputs:

| Public input | Meaning |
|---|---|
| `bitlist` (`uint256[5]`) | which validators participate — 1024 bits packed into 5 field elements |
| `publicKeysCommitment` | Poseidon2 hash over all 1024 keys, binding the proof to a specific validator set |
| `expectedApk` (`G1`) | the claimed aggregate: `seed + Σ bᵢ·pkᵢ` |

Inside the circuit it (1) recomputes the Poseidon2 commitment from the witnessed keys and checks it against `publicKeysCommitment`, and (2) sums the participating keys and checks the result against `expectedApk`. The commitment ties the proof to a set the verifier trusts; the aggregation proves the APK is correct for that set.

Two design points make it cheap:

- **Packed hashing.** Each coordinate's six 64-bit limbs are packed three-to-a-field-element before hashing (4 Poseidon2 compressions per point instead of 12).
- **Incomplete point addition.** Aggregation uses the affine chord formula, which is only valid when operands have distinct x-coordinates. Rather than guard each step, the protocol **seed is placed outside the G1 subgroup**, so the running accumulator stays in a coset disjoint from G1 and the degenerate case is unreachable by construction (Ciobotaru et al. §5.1).

Soundness rests on every *committed* key being in G1 — a property the circuit does not check. It holds because `publicKeysCommitment` is a trusted input: the verifier checks against the committee commitment fixed by chain consensus, and committee registration subgroup-checks keys (BLS `KeyValidate`). A proof-of-possession alone does **not** guarantee G1 membership. See the soundness note in [`circuits/apk/apk.go`](circuits/apk/apk.go) for the full argument.

## Benchmarks

Circuit: **3,027,309** PLONK constraints, FFT domain **2²²**. PLONK proving cost tracks the domain (the next power of two above the constraint count), so staying under 2²² = 4,194,304 is what matters.

**Proving** (single proof, 1024 validators):

| Phase | CPU | GPU (RTX 5090) |
|---|---|---|
| Compile | 2.7s | 2.7s |
| Setup | 3.9s | 3.9s |
| Witness | 0.1s | 0.1s |
| **Prove** | **17.4s** | **4.2s** |
| Verify | 3ms | 3ms |

CPU is `go build` / `cargo build`; GPU needs `-tags cuda` / `--features cuda` (see [GPU proving](#gpu-proving)). The two figures come from different RTX 5090 hosts, so treat the GPU/CPU ratio as indicative. First-time setup also derives a domain-specific Lagrange SRS (~1 min, cached per power); the canonical SRS is downloaded once and reused.

**On-chain** (Solidity, EIP-2537, Prague EVM):

| | |
|---|---|
| Full `verify()` (APK proof + BLS) | 550,840 gas |
| `hashToG1()` | 38,256 gas |
| Proof size | 1,184 bytes |
| Public inputs | 576 bytes (18 × uint256) |

## Rust prover

Generates proofs by linking the Go/gnark prover into your binary as a static archive — no shared libraries at runtime. **Requires Go 1.25+** at build time.

```toml
[dependencies]
gnark-apk-prover = { git = "https://github.com/polytope-labs/gnark-apk-proofs", branch = "main" }
```

```rust
use gnark_apk_prover::{ProofBuilder, ProverContext, G1Affine};

// One-time setup. Downloads + caches the SRS at $HOME/.config/gnark-apk-proofs/srs.
let ctx = ProverContext::setup(None)?;

let proof = ProofBuilder::new(&ctx)
    .public_keys(validator_keys)   // Vec<G1Affine>, up to 1024 (identity-padded)
    .participation(indices)        // Vec<u16>, participating validator indices
    .prove()?;

// Ready for the on-chain verifier:
//   proof.solidity_proof          — 1184-byte proof calldata
//   proof.solidity_public_inputs  — 576-byte public inputs
```

### GPU proving

Enable the icicle/CUDA backend with the `cuda` feature — no env vars at build or run time; `build.rs` fetches and statically links [`open-icicle`](https://github.com/ingonyama-zk/open-icicle) + [`gnark-cuda`](https://github.com/polytope-labs/gnark-cuda).

```toml
gnark-apk-prover = { git = "...", features = ["cuda"] }
```

Requirements: **CUDA toolkit ≥ 12.8** (Blackwell/`sm_120` support), **CMake ≥ 3.24**, and git, on an NVIDIA host. The first build compiles icicle's kernels (~15 min); later builds are incremental.

> CMake < 3.24 does not understand `-DCMAKE_CUDA_ARCHITECTURES=native` and fails deep in compiler detection with a misleading `nvcc fatal : Unsupported gpu architecture 'compute_'`. Ubuntu 22.04 ships 3.22 — install a newer CMake.

## Rust verifier

A dependency-free (no EVM) PLONK verifier for gnark BLS12-381 proofs, plus helpers to recompute the commitment.

```rust
use gnark_plonk_verifier::{
    verify, PlonkProof, VerifyingKey, public_keys_commitment_bytes_checked,
};

// Recompute the committee commitment from a known key set. The *_checked form
// asserts every point is in G1 (identity padding allowed); the returned 32-byte
// value is the big-endian `publicKeysCommitment` argument of the Solidity verifier.
let commitment: [u8; 32] = public_keys_commitment_bytes_checked(&keys)?;

// Verify a proof natively.
let vk = VerifyingKey::try_from(vk_bytes.as_slice())?;
let proof = PlonkProof::try_from((proof_bytes.as_slice(), vk.qcp.len()))?;
verify(&proof, &vk, &public_inputs)?;
```

Use `public_keys_commitment_bytes_checked` (not the unchecked `public_keys_commitment`) when deriving the commitment from points of uncertain provenance — the subgroup check is what ties the commitment to the circuit's soundness precondition.

## Solidity verifier

The `ApkProof` contract combines APK-proof verification (PLONK) and BLS aggregate-signature verification into one call, and exposes an on-chain `hashToG1` compatible with [w3f/bls](https://github.com/w3f/bls). Needs the Pectra hardfork (EIP-2537 precompiles).

```solidity
// H(m) ∈ G1 (cipher suite prepended internally)
bytes32[3] memory h_m = apkProof.hashToG1(message);

apkProof.verify(
    commitment,           // publicKeysCommitment (uint256, from the Rust verifier helper)
    bitlist,              // uint256[5]
    aggregatePublicKey,   // apk ∈ G1, bytes32[3] — the protocol seed is added on-chain
    plonkProof,           // bytes
    h_m,                  // H(m) ∈ G1, bytes32[3]
    aggregateSignature,   // bytes32[3]
    aggregatePublicKeyG2  // bytes32[6]
);
```

`PlonkVerifier.sol` (the low-level gnark-generated verifier) is regenerated from the circuit; `ApkProof.sol` wraps it with the BLS check and hardcodes the protocol seed.

## Repository layout

```
circuits/            Go — the ZK circuit
  apk/               circuit definition, commitment, tests
  ffi/               CGo exports consumed by the Rust FFI
  srs/               SRS download + caching (Filecoin ceremony)
rust/
  ffi/               low-level bindings; builds Go into a static archive
  prover/            safe builder-pattern prover API
  verifier/          pure-Rust PLONK verifier + end-to-end tests
solidity/contracts/
  PlonkVerifier.sol  auto-generated gnark PLONK verifier
  ApkProof.sol       APK proof + BLS verifier + hashToG1
```

## Development

```bash
# Circuit tests
cd circuits && go test -v -timeout 30m ./apk/

# Regenerate the Solidity verifier + proof fixtures
cd circuits && go test -v -run TestExportPlonkForFoundry -timeout 30m ./apk/

# End-to-end: Go prover → Rust verifier → Solidity in revm
cargo test -p gnark-plonk-verifier --test bls_verify -- --ignored --nocapture
```

Prerequisites: Go 1.25+, Rust, and [Foundry](https://book.getfoundry.sh/) (Solidity compilation). CI runs the CPU backend; the GPU build needs a CUDA host.

## References

- [Accountable Light Client Systems for PoS Blockchains](https://eprint.iacr.org/2022/1205) — Ciobotaru et al.
- [gnark](https://github.com/consensys/gnark) — ZKP framework
- [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) — BLS12-381 precompiles
- [w3f/bls](https://github.com/w3f/bls) — BLS library

## License

Apache License 2.0
