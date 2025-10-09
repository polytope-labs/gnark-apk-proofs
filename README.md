# gnark-apk-proofs

A Go project for working with Aggregated Public Key (APK) Zero-Knowledge Proofs using the gnark framework.

## Overview

This project demonstrates how to create and verify zero-knowledge proofs related to aggregated public keys using the [gnark](https://github.com/consensys/gnark) framework from ConsenSys.

## Project Structure

```
gnark-apk-proofs/
├── pkg/         # Public library code
└── go.mod       # Go module definition
```

## Getting Started

### Prerequisites

- Go 1.21 or later
- Basic understanding of zero-knowledge proofs and gnark framework

### Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/gnark-apk-proofs.git
cd gnark-apk-proofs
```

Install dependencies:

```bash
go mod tidy
```

### Running the Test

```bash
go test ./pkg/apk -run TestBLSG1APKCircuit
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

- [gnark](https://github.com/consensys/gnark) - The ZKP framework this project is built on