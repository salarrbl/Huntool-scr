# Project NYX — Phase 3 Design: Terminal UI & Identity Management

## 1. Design Overview

Phase 3 integrates a Ratatui-based TUI with identity management, contact list, chat view, and session handling.

### What Exists Now
- Phase 0: Crypto primitives, binary protocol, encrypted storage.
- Phase 1: Tor transport, connection retry, offline queue.
- Phase 2: Noise handshake placeholders, session abstractions.

### What Phase 3 Adds
- **TUI Skeleton:** Ratatui app with:
  - Contact list pane (left)
  - Chat pane (center)
  - Input bar (bottom)
  - Status bar (top)
- **Identity Manager:** UI to create, import, export, and select identities.
- **Session Manager:** UI to initiate/accept sessions, show connection status.
- **Message Rendering:** Plaintext messages with optional timestamps.
- **Input Handling:** Keyboard-driven navigation, Enter to send.

## 2. Architecture

```
nyx-cli (main.rs)
  -> nyx-ui (app.rs)
    -> nyx-core (session, identity, queue)
      -> nyx-network (Tor transport)
      -> nyx-protocol (Noise handshake)
      -> nyx-crypto / nyx-storage
```

### Why this is secure
- **No telemetry:** TUI runs entirely offline; no analytics or crash reporting.
- **No clipboard exposure:** Messages are rendered as text; no copy-to-clipboard unless user explicitly requests (future phase).
- **No external APIs:** All UI state lives in memory; no network calls except Tor transport.
- **Session isolation:** Each identity has its own session pool and Tor circuit (future phase).

## 3. Threat Model

### Assumptions
- Attacker can observe terminal screen (shoulder surfing).
- Attacker can capture terminal emulator memory after shutdown.
- Attacker can access local storage after shutdown.

### Mitigations & Limitations

| Threat | Mitigation | Limitation |
|--------|-----------|-------------|
| **Screen capture** | No sensitive data in scrollback; messages are ephemeral in RAM. | If user scrolls up, plaintext may remain in terminal emulator scrollback. Future: implement scrollback encryption. |
| **Memory scraping** | Sensitive keys are zeroized on drop; UI state does not retain plaintext messages after session close. | If UI panics, Rust unwinding may leave copies in heap. Mitigation: panic = abort in release. |
| **Clipboard exposure** | No clipboard integration in Phase 3. | Future: secure clipboard handling with X11/Wayland selection ownership. |
| **UI spoofing** | No external content rendering (no HTML, no images). | If terminal emulator is compromised (e.g., malicious escape sequences), UI can be spoofed. Mitigation: use a hardened terminal like `foot` or `alacritty`; disable OSC sequences. |

## 4. UI Layout

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ [NYX] Session: session-abc123 | Identity: alice@onion | Tor: online          │
├───────────────────────────────────────────────────────────────────────────────┤
│ Contacts                                                                     │
│  • Bob (bob.onion) [online]                                                  │
│  • Charlie (charlie.onion) [offline]                                         │
│  • Eve (eve.onion) [queued]                                                   │
├───────────────────────────────────────────────────────────────────────────────┤
│ Chat with Bob                                                                 │
│  14:23 Alice: Hi Bob!                                                         │
│  14:24 Bob:  Hey Alice, how are you?                                          │
│  14:25 Alice: Good, thanks.                                                   │
│                                                                               │
├───────────────────────────────────────────────────────────────────────────────┤
│ > Hello Bob                                                                   │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Components
- **Status Bar (top):** Session ID, identity, Tor status.
- **Contact List (left):** Clickable contacts with online/offline/queued status.
- **Chat Pane (center):** Rendered messages with timestamps.
- **Input Bar (bottom):** Text input for composing messages.

### Navigation
- `Tab` switches focus between panes.
- `↑/↓` scrolls chat pane.
- `Enter` sends message.
- `Esc` cancels input or exits compose mode.

## 5. Identity Management UI

### Identity Selector
- List all identities from `nyx-storage`.
- Show nickname and avatar hash.
- Allow creation of new identities with:
  - Ed25519 key generation
  - Onion v3 address (placeholder until Phase 1 integration)
  - Passphrase-protected export bundle

### Identity Export/Import
- Export: encrypt identity bundle with Argon2id + user passphrase.
- Import: decrypt bundle, verify signature, add to storage.
- No cloud sync; user must transfer bundle manually (USB, QR, etc.).

## 6. Session Lifecycle UI

### Initiate Session
1. User selects contact.
2. UI calls `Session::establish(is_initiator=true)`.
3. Noise handshake messages exchanged over Tor.
4. On success, show "Session established" and enable chat input.

### Accept Session
1. Tor listener receives incoming handshake.
2. UI shows "Incoming session from <onion>" with fingerprint.
3. User accepts or rejects.
4. If accepted, handshake completes and chat is enabled.

### Connection Status
- **Online:** Tor circuit active, Noise handshake complete.
- **Connecting:** Retry loop active.
- **Offline:** Tor proxy unreachable.
- **Queued:** Contact offline; message queued for later delivery.

## 7. Message Rendering

### Plaintext Messages
- No markdown or rich text to avoid parsing vulnerabilities.
- Timestamps in local time (configurable format).
- No inline images or links (future: allow with user confirmation).

### Read Receipts (Future Phase 4)
- Not implemented in Phase 3.

## 8. Security Review Checklist (Phase 3)

- [ ] TUI runs entirely offline; no telemetry or analytics.
- [ ] All sensitive memory zeroized on drop (identities, sessions).
- [ ] No clipboard integration; no external content rendering.
- [ ] Identity export bundles encrypted with Argon2id.
- [ ] Session handshake UI shows fingerprint verification prompt.
- [ ] No plaintext secrets stored in scrollback.
- [ ] Panic mode (Phase 4) not yet implemented; assume panic=abort.
- [ ] Tor status is displayed but not configurable (hardcoded proxy).
