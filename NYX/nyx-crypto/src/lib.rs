//! Cryptographic kernel for Project NYX.
//!
//! This crate is **dependency-leaf** for secrets. It never performs I/O,
//! network operations, or filesystem access. All sensitive material is
//! zeroized on drop.

pub mod identity;
pub mod kdf;
pub mod rng;
pub mod symmetric;

pub use ed25519_dalek::{Signature, VerifyingKey};
pub use x25519_dalek::PublicKey as X25519PublicKey;

/// Size of an X25519 or Ed25519 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of a public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a ChaCha20-Poly1305 symmetric key in bytes.
pub const SYMMETRIC_KEY_SIZE: usize = 32;

/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;
