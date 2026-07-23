# Project NYX — Phase 1 Design & Threat Model

## 1. Design Overview

Phase 1 adds peer-to-peer connectivity over Tor Onion Services with a mutually authenticated Noise handshake. Key additions:

- **Tor Transport:** Outbound TCP routed through Tor SOCKS5 proxy (`127.0.0.1:9050`). Inbound Onion v3 services created via Tor Control Port.
- **Noise Handshake:** Pattern `Noise_XX_25519_ChaChaPoly_SHA256` using `snow`. Both peers authenticate via Ed25519 signatures over the handshake transcript.
- **Offline Queue:** Messages for unreachable contacts are encrypted to their static DH key and persisted in `nyx-storage`. Delivered on next successful connection.
- **Connection Manager:** Retry with capped exponential backoff + jitter, routed exclusively through Tor.

## 2. Architecture

```
nyx-cli
 -> nyx-core (session manager, offline queue)
   -> nyx-protocol (Noise state machine, frame wrapping)
   -> nyx-network (Tor connection pool, SOCKS5 transport)
     -> tokio::net::TcpStream (via SOCKS5 proxy)
     -> torut (Control Port for Onion Service CRUD)
   -> nyx-storage (encrypted queue envelopes)
     -> nyx-crypto
```

### Why this is secure
- **No clearnet path:** If Tor proxy is down, connections fail closed. There is no fallback code path.
- **Tor-only DNS:** Hostname resolution for `.onion` addresses happens inside Tor. No local DNS lookups.
- **Mutual authentication:** Noise `XX` requires both peers to present a static key. We bind these static keys to Ed25519 identities by signing the handshake hash. An impostor cannot connect without possessing the target's Ed25519 secret key.
- **Session isolation:** Each P2P session gets its own Noise CipherState after handshake. Session keys are ephemeral and do not persist.
- **Queue encryption:** Offline messages use the recipient's static X25519 key. Without the corresponding secret key (held only by the recipient), the ciphertext is unrecoverable even if the local disk is seized.

## 3. Threat Model

### Assumptions
- Attacker controls a fraction of Tor relays (< network consensus threshold).
- Attacker can probe any known Onion v3 address.
- Attacker has all network traffic outside the Tor tunnel (i.e., can see encrypted Tor cells but not plaintext).
- Attacker may attempt to replay handshake and data frames.

### Mitigations & Limitations

| Threat | Mitigation | Limitation |
|--------|-----------|-------------|
| **Clearnet leak** | Hardcoded SOCKS5 proxy. Init fails if proxy unreachable. | If host OS routes `localhost` externally, traffic escapes Tor. We assume the OS routes `127.0.0.1` correctly. |
| **Handshake replay** | Noise cipher states reject non-sequential handshake messages. We add a 64-bit counter in the encrypted payload for extra replay protection. | Full Double Ratchet in Phase 2 makes replay of *data* messages impossible. |
| **Onion service DoS** | Connection manager drops repeated failed attempts from unknown identities after backoff. | No rate-limiting at the Onion v3 level yet. Tor itself provides some circuit-scale rate limiting. |
| **Queue compromise** | Queue entries encrypted with recipient pubkey + AEAD. | Local metadata (queue size, timestamps) is plaintext. Future phases pad and cover-traffic the queue. |
| **Man-in-the-middle** | Noise XX mutual auth + Ed25519 identity binding prevents active MITM if keys are verified out-of-band. | If users skip fingerprint verification, MITM is possible. UI will warn loudly. |

## 4. Design Decisions

### 4.1 Why `Noise_XX`?
- `XX` provides mutual authentication with 3 messages (initiator static/ephemeral, responder static/ephemeral). Both sides transmit static keys.
- We cannot use `Noise_IK` because we have no pre-published static key directory. All contacts are added manually.
- `XX` is the de-facto standard for P2P messengers (used by WireGuard, Signal's initial setup, etc.).

### 4.2 Why `snow` crate?
- `snow` is the only widely audited Noise implementation for Rust (by NCC Group).
- It provides state-machine-safe handshake progression. Implementing Noise by hand is a known source of severe vulnerabilities (missing MAC verification, state confusion).
- We bind `snow`'s state machine output to our binary frame format for transport.

### 4.3 Why Tor Control Port instead of `arti-client`?
- `arti-client` is excellent for outbound client circuits but does not yet have full Onion Service server hosting APIs.
- Tor Control Port is the official interface for creating ephemeral Onion v3 services. `torut` is a thin Rust wrapper over it.
- This requires a running Tor daemon, which is acceptable for a terminal messenger that expects system-level Tor.

## 5. Offline Queue Format

```
+---------------------------------------------------+
|  Queue Entry Header                               |
|  - Recipient Onion Address (variable, <= 100 B)   |
|  - Payload Length (u32 LE)                        |
|  - Timestamp (u64 LE)                             |
+---------------------------------------------------+
|  Encrypted Payload (AEAD envelope)                |
+---------------------------------------------------+
```

Stored in a single append-only encrypted log file managed by `nyx-storage`. Entries are deleted after successful delivery.

## 6. Protocol State Machine (Noise XX)

```
Initiator                                    Responder
  |                                              |
  | --- e (ephemeral X25519) ----------------->  |  <- WriteMessage State A
  |                                              |  <- ReadMessage State B
  | <--- e, ee, s, es (Responder static) ------  |  <- WriteMessage State C
  |  <- ReadMessage State D                      |
  | --- s, se (Initiator static) ------------->  |  <- WriteMessage State E
  |                                              |  <- ReadMessage State F
  | =========== Handshake Complete ============= |
  | <--- [encrypted payload] ------------------> |  <- CipherState shared
```

After handshake, each peer holds a `CipherState` for sending and receiving. We wrap `snow`'s `CipherState` into a `Session` object that speaks our binary frames.

## 7. Security Review Checklist (Phase 1)

- [ ] `snow` configured with no PSK (pure public-key handshake).
- [ ] Ed25519 signature over handshake hash before application data.
- [ ] SOCKS5 proxy is the only outbound socket path.
- [ ] Onion Service listens on `127.0.0.1` only (no clearnet bind).
- [ ] Retry logic never bypasses proxy.
- [ ] Offline queue authenticated-encrypted, not just encrypted.
- [ ] Session keys are erased after session close (Drop impl zeroizes).
- [ ] Unknown handshake fingerprints are rejected; no silent acceptance.
