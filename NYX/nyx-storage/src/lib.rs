//! Encrypted local storage primitives.
//!
//! All data at rest is encrypted with ChaCha20-Poly1305. The passphrase
//! to key derivation uses Argon2id. This crate performs no network I/O.

pub mod envelope;
