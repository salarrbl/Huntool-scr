# Project NYX — Phase 2 Design: Noise Handshake & Double Ratchet

## 1. Design Overview

Phase 2 replaces the symmetric-only session with a mutually authenticated Noise handshake and adds a Double Ratchet for per-message forward secrecy.

### What Exists Now
- Phase 0: Crypto primitives, binary frame format, encrypted storage.
- Phase 1: Tor transport, connection retry, offline queue.

### What Phase 2 Adds
- **Noise Protocol:** Pattern `Noise_XX_25519_ChaChaPoly_SHA256` using the `snow` crate.
- **Double Ratchet:** Ephemeral key ratchet for sender and receiver, with symmetric-key ratchet for cipher states.
- **Session Management:** Persistent session state encrypted and stored in `nyx-storage`.
- **Handshake Replay Protection:** Strict message ordering enforced by handshake counter and per-message nonce.

## 2. Architecture

```
nyx-core
  -> SessionManager (handles handshake, stores sessions)
    -> NoiseState (snow::HandshakeState)
      -> DoubleRatchet (sender + receiver ratchets)
        -> CipherState (encrypt/decrypt)
          -> nyx-protocol::Frame
```

### Why this is secure
- **Mutual authentication:** Both peers present static keys signed by Ed25519. The handshake transcript is signed after completion to bind identity to the session.
- **Forward secrecy:** Each message uses a new symmetric key derived from the ratchet. Compromise of long-term keys does not expose past messages.
- **Future secrecy:** The Double Ratchet provides weak future secrecy: if a sender’s key is compromised, only messages *after* the compromise are exposed (not before).
- **Replay protection:** Handshake and message counters prevent replay of old frames.

## 3. Threat Model

### Assumptions
- Attacker can observe all Tor traffic (guard/middle/exit nodes).
- Attacker can attempt to replay handshake and data frames.
- Attacker may compromise local storage after shutdown (but not during runtime).

### Mitigations & Limitations

| Threat | Mitigation | Limitation |
|--------|-----------|-------------|
| **Handshake replay** | Handshake counter and strict message ordering in `snow` state machine. | If handshake counter wraps, session must be re-established. |
| **Message replay** | Per-message nonce derived from sender ratchet counter. | No out-of-order delivery; messages must be processed in order. |
| **Key compromise impersonation** | Static keys are bound to Ed25519 signatures. If static key is compromised, attacker can impersonate but cannot decrypt past messages (forward secrecy). | If both static and ephemeral keys are compromised at the same time, session is fully exposed. |
| **Session state compromise** | Session state encrypted with a key derived from the handshake. | If disk is seized while session is open, keys are in RAM. Mitigation: panic mode (Phase 3). |

## 4. Noise Handshake

We use `Noise_XX_25519_ChaChaPoly_SHA256`.

### Handshake Flow

```
Initiator (A)                            Responder (B)
  |                                          |
  | e (ephemeral X25519) ----------------->  |
  |                                          |  <- WriteMessage State A
  | <--- e, ee, s, es (B static) ----------  |
  |                                          |  <- WriteMessage State C
  | --- s, se (A static) ----------------->  |
  |                                          |  <- WriteMessage State E
  | =========== Handshake Complete ========== |
```

After handshake, both sides call `get_handshake_hash()` and sign it with their Ed25519 identity keys. The signatures are exchanged in the first data frame (or a dedicated `HandshakeCommit` frame). If signatures do not match the expected identity, the session is dropped.

### Why `XX`?
- Both peers authenticate via static keys.
- No pre-published directory; contacts are added manually.
- `XX` is the standard for P2P authenticated handshakes.

## 5. Double Ratchet

### Sender Ratchet
- Every message increments a counter and derives a new symmetric key via HKDF.
- Key derivation: `HKDF(send_ck, "nyx-ratchet", counter_bytes, 32)`
- `send_ck` is the chain key, updated after each message.

### Receiver Ratchet
- Receiver maintains the same ratchet state as sender.
- On receiving a message, it derives the expected key and verifies the nonce.
- If out of order, message is queued for later delivery (not implemented in Phase 2; assume in-order).

### Key Separation
- Sender and receiver have independent ratchets.
- Each ratchet produces a `CipherState` for encryption/decryption.

## 6. Session Persistence

Session state is encrypted and stored in `nyx-storage`.

```rust
struct SessionState {
    id: String,
    peer_onion: String,
    peer_identity_pub: [u8; 32],
    handshake_hash: [u8; 32],
    sender_ratchet: RatchetState,
    receiver_ratchet: RatchetState,
    last_received_counter: u64,
}
```

Encryption key for session state is derived from the handshake hash + a local salt. This ensures that even if disk is seized, the session state cannot be decrypted without the handshake transcript.

## 7. Frame Format Additions

Phase 2 adds a `SessionId` and `Counter` to the encrypted payload of data frames.

```
[encrypted payload]
+-------------------+
| Session ID (32)   |
+-------------------+
| Counter (8 LE)    |
+-------------------+
| Message Type (1)  |
+-------------------+
| Payload (variable)|
+-------------------+
```

- **Session ID** binds the frame to a specific session.
- **Counter** is the sender ratchet counter. Receiver uses it to derive the correct key.
- **Message Type** distinguishes text, file chunk, control.

## 8. Security Review Checklist (Phase 2)

- [ ] `snow` configured with `Noise_XX_25519_ChaChaPoly_SHA256` and no PSK.
- [ ] Ed25519 signature over handshake hash exchanged before any application data.
- [ ] Handshake transcript is verified against the peer’s identity.
- [ ] Double Ratchet keys are derived via HKDF with unique context.
- [ ] Session state encrypted with a key derived from handshake hash.
- [ ] All sensitive memory zeroized on drop (ratchet keys, chain keys).
- [ ] Replay protection enforced by counters and strict ordering.
- [ ] No clearnet fallback; all frames routed through Tor.
