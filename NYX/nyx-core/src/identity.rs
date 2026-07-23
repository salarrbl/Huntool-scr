use nyx_crypto::VerifyingKey;
use nyx_crypto::identity::{DhKeypair, IdentityKeypair};
use zeroize::ZeroizeOnDrop;

/// A user's identity within NYX.
///
/// Each identity owns a long-term Ed25519 signing keypair and an X25519
/// key agreement keypair. Identities are strictly isolated: no cross-identity
/// key reuse.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    /// Long-term signature identity.
    pub id_keypair: IdentityKeypair,
    /// Key agreement identity.
    pub dh_keypair: DhKeypair,
    /// Human-readable label (not unique, not security sensitive).
    pub nickname: String,
    /// Optional 32-byte avatar hash (BLAKE3).
    pub avatar_hash: Option<[u8; 32]>,
}

impl Identity {
    pub fn id_public_key(&self) -> VerifyingKey {
        self.id_keypair.verifying_key()
    }
}
