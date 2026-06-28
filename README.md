# Bitcoin SPV Mini-Node

A robust, dependency-minimal Bitcoin SPV (Simplified Payment Verification) client written from scratch in Rust.

This project provides an autonomous, highly performant Bitcoin network client that connects directly to the P2P network, synchronizes block headers, and monitors mempool transactions. It maintains a strict state-machine architecture designed to minimize overhead and avoid heavy third-party frameworks.

## Architecture & Design Principles

* **State-Machine Driven**: Complete decoupling of business logic from I/O. The protocol parser yields actionable primitives (`PeerAction`) that are subsequently handled by the asynchronous networking layer.
* **Zero Over-Engineering**: Adheres to strict performance boundaries. Avoids heavy serialization frameworks in favor of manual byte-boundary parsing for standard and SegWit data structures.
* **Asynchronous Networking**: Built on `tokio` for concurrent peer connection pool management and resilient timeout handling.
* **Lean Observability**: A lightweight terminal UI (TUI) powered by `ratatui` handles real-time visual logging without bloated tracing pipelines.

## Capabilities

* **Network Handshake**: Fully implements the Bitcoin protocol handshake (`version`, `verack`) and heartbeat keep-alives (`ping`, `pong`).
* **Header Synchronization**: Automatically negotiates and downloads block headers via `getheaders`.
* **PoW Validation**: Cryptographically validates the double SHA-256 Proof-of-Work constraints for all ingested headers.
* **Binary Persistence**: Persists headers to a compact, raw binary `.dat` file (80 bytes per block) to minimize disk overhead and syscalls.
* **Mempool Monitoring**: Parses `inv` broadcasts and requests live `tx` payloads via `getdata`, deserializing legacy and SegWit transaction formats natively.

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
