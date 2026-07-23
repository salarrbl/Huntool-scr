# Project NYX

A production-grade, security-first, terminal-based anonymous peer-to-peer messenger built in Rust.

## Phase 0 Status

Phase 0 delivers the cryptographic kernel, binary wire protocol, and workspace scaffold.

### What Exists
- **nyx-common** — shared errors and constants (leaf crate, zero external deps).
- **nyx-crypto** — X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, Argon2id, BLAKE3 hashing, secure RNG, zeroization.
- **nyx-protocol** — compact binary frame parser/serializer with strict length checks and property-based tests.
- **nyx-storage** — authenticated encrypted envelope for local persistence.
- **nyx-core** — identity and contact abstractions.
- **nyx-network / nyx-ui** — stubs, reserved for Phase 1 & 2.

### What Does Not Exist Yet
- Tor transport layer.
- Terminal UI (Ratatui).
- Noise handshake / Double Ratchet.
- Cover traffic or timing obfuscation.

## Building

Requires Rust 1.75+ (stable).

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Architecture

```
nyx-cli
  -> nyx-ui
    -> nyx-core
      -> nyx-protocol -> nyx-crypto
      -> nyx-storage   -> nyx-crypto
nyx-common (leaf crate)
```

## Security

See [THREAT_MODEL_AND_DESIGN.md](THREAT_MODEL_AND_DESIGN.md) for the complete Phase 0 threat model, cryptographic rationale, and security review checklist.

## License

AGPL-3.0-or-later
