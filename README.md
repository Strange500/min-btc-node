# Bitcoin SPV Mini-Node

A robust, dependency-minimal Bitcoin SPV (Simplified Payment Verification) client written from scratch in Rust.

This project provides an autonomous, highly performant Bitcoin network client that connects directly to the P2P network, synchronizes block headers, and monitors mempool transactions. It maintains a strict state-machine architecture designed to minimize overhead and avoid heavy third-party frameworks.

## Architecture & Design Principles

* **State-Machine Driven**: Complete decoupling of business logic from I/O. The protocol parser yields actionable primitives (`PeerAction`) that are subsequently handled by the asynchronous networking layer.
* **Zero Over-Engineering**: Adheres to strict performance boundaries. Avoids heavy serialization frameworks in favor of manual byte-boundary parsing for standard and SegWit data structures.
* **Asynchronous Networking**: Built on `tokio` for concurrent peer connection pool management and resilient timeout handling.
* **Lean Observability**: A lightweight terminal UI (TUI) powered by `ratatui` handles real-time visual logging without bloated tracing pipelines.

## Project Structure

This repository is organized as a Cargo workspace containing two core components:

### 1. Bitcoin Mini-Node (`node`)
The autonomous SPV network client responsible for handling the P2P layer and blockchain state.
* **Network Handshake**: Fully implements the Bitcoin protocol handshake (`version`, `verack`) and heartbeat keep-alives (`ping`, `pong`).
* **Header Synchronization**: Automatically negotiates and downloads block headers via `getheaders`.
* **PoW Validation**: Cryptographically validates the double SHA-256 Proof-of-Work constraints for all ingested headers.
* **Client-Side Filtering**: Discards legacy network Bloom filters in favor of local Base58 address decoding and silent client-side `Tx` filtering for optimal reliability.
* **Binary Persistence**: Persists headers to a compact, raw binary `.dat` file (80 bytes per block) to minimize disk overhead and syscalls.

### 2. Script Execution Engine (`script-engine`)
A stateless, standalone Stack-Based Virtual Machine (VM) responsible for evaluating Bitcoin locking (`scriptPubKey`) and unlocking (`scriptSig`/Witness) scripts.
* **Tokenization**: Parsing raw byte arrays into executable Bitcoin Opcodes and strict data pushes.
* **State Management**: Implementation of the Main Stack, Alternate Stack, and an Execution Stack for handling control flow (e.g., `OP_IF` / `OP_ELSE`).
* **Opcode Execution**: Processing stack manipulation, bitwise logic, and cryptographic operations (e.g., `OP_CHECKSIG`, `OP_HASH160`) using `secp256k1`.
* **Consensus Safeguards**: Strict enforcement of protocol limits, including the 520-byte max element size, 1000 max stack depth, opcode limits, and the clean stack validation rule.
* **Transaction Types**: Support for evaluating standard output types, including P2PKH and native SegWit (P2WPKH).

## Non-Goals

To maintain its status as an SPV light client, this node intentionally **does not**:
* Download or store full blocks.
* Validate cryptographic signatures (ECDSA/Schnorr) or prevent double-spends natively (relies on SPV proofs).
* Manage private keys or sign outbound transactions.
* Participate in Proof-of-Work mining.

## Getting Started

### Prerequisites

This project utilizes [Nix Flakes](https://nixos.wiki/wiki/Flakes) to guarantee a reproducible build environment.

### Running the Node

To build and run the client immediately:
```bash
nix run
```

To enter the development shell for standard `cargo` operations:
```bash
nix develop
cargo test
cargo run --release
```




docs used: 

https://learnmeabitcoin.com  
https://en.bitcoin.it  
https://bips.dev/  