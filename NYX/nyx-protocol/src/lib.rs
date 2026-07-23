//! Compact binary wire protocol for Project NYX.
//!
//! The frame format is deliberately simple:
//! Fixed header → nonce → encrypted payload (ciphertext + Poly1305 tag).
//! No JSON, no dynamic fields, no parser ambiguity.

pub mod frame;
pub mod session;
pub mod types;

/// Wire magic bytes: `NYX\0`.
pub const NYX_MAGIC: [u8; 4] = [0x4E, 0x59, 0x58, 0x00];

/// Current protocol version. Rejection of any other version prevents downgrade.
pub const NYX_PROTOCOL_VERSION: u8 = 0x01;

/// Size of the protocol header in bytes.
pub const NYX_HEADER_SIZE: usize = 24;

/// Maximum payload size in a single frame (64 KiB).
pub const NYX_MAX_FRAME_SIZE: usize = 65_536;
