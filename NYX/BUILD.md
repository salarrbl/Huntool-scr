# Build Guide — Project NYX

## Prerequisites

- Rust **Stable** 1.75 or newer.
- `cargo` and `rustc`.
- Optional: `cargo-fuzz` for fuzz testing (`cargo install cargo-fuzz`).

## Quick Start

```bash
# Clone the repository (or navigate to existing source)
cd nyx

# Format and lint (mandatory before any commit)
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# Build the full workspace
cargo build --release

# Run the test suite (unit + property-based)
cargo test --workspace

# Run benchmarks (Phase 0 includes crypto benchmarks)
cargo bench -p nyx-crypto
cargo bench -p nyx-protocol

# Fuzz the protocol parser
cargo fuzz run fuzz_frame_parse
```

## Workspace Layout

| Crate | Purpose |
|-------|---------|
| `nyx-common` | Errors, constants, shared types. |
| `nyx-crypto` | Primitives, key management, zeroization. |
| `nyx-protocol` | Binary frame format, serialization. |
| `nyx-storage` | Encrypted persistence envelopes. |
| `nyx-core` | Identity and contact models. |
| `nyx-network` | Tor transport (Phase 1). |
| `nyx-config` | TOML configuration (Phase 1). |
| `nyx-ui` | Ratatui interface (Phase 2). |
| `nyx-cli` | Entry point binary. |

## Security Policy

See `THREAT_MODEL_AND_DESIGN.md` before contributing. Every feature requires a documented threat analysis.
