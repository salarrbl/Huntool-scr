# Project NYX — Phase 0 Threat Model & Architectural Design

> **Security Principle:** Every feature must be justified against a documented threat before implementation. This document governs Phase 0 (Cryptographic Core & Binary Protocol).

---

## 1. Design Overview

Phase 0 establishes the root of trust for all subsequent layers. It consists of:

- **Layer Isolation:** A Cargo workspace enforces dependency direction. `nyx-crypto` has zero network, filesystem, or UI dependencies. It is a pure cryptographic kernel.
- **Primitive Selection:** All primitives are widely audited, standardized, and implemented by reputable Rust crates.
- **Memory Hygiene:** All sensitive key material uses `zeroize` with `ZeroizeOnDrop` or explicit `Zeroizing<T>` wrappers.
- **Binary Protocol:** A custom compact binary frame replaces JSON/XML to eliminate parser ambiguity and minimize metadata leakage.
- **Persistence:** All on-disk data is encrypted with authenticated encryption (`ChaCha20-Poly1305`) using keys derived via `Argon2id` from user passphrases.

---

## 2. Threat Model

### 2.1 Assumptions

We assume an attacker can:

- Observe or tamper with network traffic (mitigated in later phases; Phase 0 assumes no active transport yet).
- Capture and inspect local storage after the application terminates.
- Attempt replay attacks by recording and re-injecting frames.
- Supply malformed protocol frames to exploit parser vulnerabilities.
- Achieve limited memory inspection if the host OS is compromised while NYX is running.

### 2.2 Mitigations

| Threat | Phase 0 Mitigation | Future Phase Enhancement |
|--------|-------------------|--------------------------|
| **Local Storage Inspection** | All persistent data encrypted with AEAD. Passphrase hashed with `Argon2id` (memory-hard). | RAM-only mode, `mlock`, encrypted swap |
| **Memory Scraping** | Key material wrapped in `ZeroizeOnDrop`. Minimal key lifetime. | Secure enclaves, explicit `mlock`, panic zeroization |
| **Replay Attacks** | Wire protocol includes a strictly increasing sequence counter inside the encrypted payload (enforced by `nyx-protocol`). | Full Double Ratchet per-message keys |
| **Parser Exploits** | Constant-size headers. Length fields validated with `checked_add` before allocation. Hard upper bounds on frame size. | Fuzz corpus expansion, formal grammar |
| **Nonce Reuse** | 96-bit random nonces from `OsRng`. Keys are session-specific via HKDF. | Full ratchet ensures key rotation per message |
| **Side-Channel Timing** | Use `dalek` constant-time field operations. No branching on secrets. | Cache-line mitigation, vectorized constant-time |

---

## 3. Cryptographic Design Rationale

### 3.1 Primitives

| Primitive | Purpose | Justification |
|-----------|---------|---------------|
| **X25519** | ECDH key agreement | RFC 7748, `x25519-dalek` audited by NCC Group, 128-bit security level, compact keys |
| **Ed25519** | Identity signatures | RFC 8032, same audit base as X25519, prevents long-term identity forgery |
| **ChaCha20-Poly1305** | AEAD encryption | Resistant to timing attacks on all platforms (unlike AES-NI-dependent AES-GCM); used in TLS 1.3 and WireGuard |
| **BLAKE3** | Hashing / KDF | Fast, parallelizable, immune to length-extension; used as HKDF hash and standalone KDF |
| **HKDF-BLAKE3** | Key derivation | NIST SP 800-56C compliant extraction-and-expansion; domain separation for sub-keys |
| **Argon2id** | Passphrase hashing | Winner of Password Hashing Competition; memory-hard resistance to GPU/ASIC cracking |

### 3.2 Why Not Post-Quantum by Default?

Phase 0 uses classical X25519/Ed25519. Post-quantum hybrid mode (ML-KEM + X25519) is planned behind a compile-time feature flag because:
1. PQ algorithms increase payload sizes and computational cost.
2. Not all PQ parameter sets have equivalent audit coverage yet.
3. The threat of a cryptographically relevant quantum computer against ephemeral messaging is currently lower than classical key-exfiltration or implementation bugs.

---

## 4. Architecture Security

### 4.1 Crate Boundary Enforcement

```
nyx-cli
  -> nyx-ui
    -> nyx-core
      -> nyx-protocol
        -> nyx-crypto
      -> nyx-storage
        -> nyx-crypto
  -> nyx-network (future)
    -> nyx-protocol
      -> nyx-crypto
nyx-common (types, errors — leaf crate, zero external deps)
```

**Why this is safe:**
- `nyx-crypto` cannot access the filesystem or network. A supply-chain attack in `tokio` or `ratatui` cannot reach the key layer.
- `nyx-storage` uses `nyx-crypto` but cannot reach `nyx-network`, preventing exfiltration via a storage bug.
- `nyx-common` is a leaf crate. It defines the shared vocabulary but adds no transitive dependencies that could inject malicious code into the crypto layer.

### 4.2 Zeroization Strategy

- All key structs derive `ZeroizeOnDrop`.
- Shared secrets are immediately fed into HKDF and the original `SharedSecret` is dropped.
- The `zeroize` crate uses volatile writes and compiler fences to inhibit dead-store elimination.

**Known Limitation:** Rust's LLVM backend may optimize copies of stack values during moves. We minimize time keys spend on the stack and avoid large key arrays in closures. For Phase 0 this is acceptable; future phases may require secured heap allocators or `mlock`.

---

## 5. Protocol Frame Design

### 5.1 Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic (4 bytes)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (1)   | Flags (1)     | Message Type (1)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reserved (1)  |                Length (4)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                        Nonce (12 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                    Encrypted Payload (variable)               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+              Authentication Tag (16 bytes)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic:** `0x4E595800` (ASCII "NYX\0"). Prevents accidental interpretation of non-NYX streams.
- **Version:** Starts at `0x01`. Only exact version match accepted — no auto-negotiation to downgrade attacks.
- **Flags:** Future use (e.g., PQ-hybrid indicator, padding-presence).
- **Message Type:** Distinguishes handshake, data, control.
- **Length:** Total ciphertext length, little-endian, max `MAX_FRAME_SIZE`.
- **Nonce:** Random 96-bit IV generated per frame by `OsRng`.
- **Tag:** Poly1305 MAC.

### 5.2 Why This Format Is Secure

- **Fixed header size:** Eliminates length-based side channels in header parsing.
- **Explicit length check:** Prevents memory exhaustion from malicious length fields.
- **Random nonces per frame:** Even if a key is reused across sessions (implementation bug), random nonces reduce collision probability to negligible levels.
- **No inline compression:** Compression before encryption is omitted to prevent CRIME/BREACH-class attacks.
- **No extensibility in the clear:** Flags are present but version match is strict to prevent downgrade probes.

---

## 6. Possible Attacks on Phase 0 Components

### 6.1 Malformed Frame Allocation DoS
An attacker sends a frame with `Length = u32::MAX`. Countermeasure: hard limit `MAX_FRAME_SIZE = 65_536` bytes. All length values validated via `checked_add` before buffer allocation. Rejection is early and does not involve the crypto layer.

### 6.2 Key Reuse via Clone/Copy
If a key type accidentally derives `Clone`, an attacker exploiting memory safety could duplicate keys. Countermeasure: wrapper structs do not implement `Clone` or `Copy` unless explicitly required (and even then only for public keys). Secret key wrappers explicitly forbid `Clone`.

### 6.3 Timing Attacks on AEAD Verification
`ChaCha20Poly1305::decrypt` returns an error if the tag is invalid. Standard RustCrypto AEAD implementation compares tags in constant time. We never branch on partial MAC verification results.

### 6.4 Passphrase Brute Force
Countermeasure: Argon2id with default parameters tuned for interactive login (~1s compute time, ~64MB RAM). Users can increase `t` and `m` in configuration.

---

## 7. Known Limitations

- **Phase 0 has no forward secrecy ratchet.** Forward secrecy requires an active session to rotate keys. The current AEAD uses session-static keys. The Double Ratchet integration is Phase 2.
- **No cover traffic or timing obfuscation.** These require the transport layer (Tor) to be active. Phase 0 is offline-capable only.
- **No secure deletion of freed heap memory.** `zeroize` handles stack-bound structs, but the allocator may retain copies of freed heap blocks. Future phases may integrate a dedicated secure allocator.
- **No hardware security module (HSM) or TPM integration.** Private keys exist in process memory. This is acceptable for the threat model of a software-only messenger but acknowledged as a limitation.

---

## 8. Security Review Checklist (Phase 0)

- [x] No custom cryptographic primitives invented.
- [x] All crypto dependencies are audited, standard crates.
- [x] All secret key types implement `ZeroizeOnDrop`.
- [x] Protocol parser fails closed on all malformed inputs.
- [x] Frame length is bounded and validated before memory allocation.
- [x] Random nonces generated from `OsRng` (CSPRNG).
- [x] Passphrase-to-key uses memory-hard Argon2id.
- [x] Encrypted storage uses authenticated encryption (no unauthenticated modes).
- [x] `unsafe` Rust is forbidden in `nyx-crypto` and `nyx-protocol`.
- [x] `clippy` warnings treated as fatal in CI.
- [x] Property-based tests exist for serialization round-trips.
