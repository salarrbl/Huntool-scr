use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nyx_common::error::{NyxError, NyxResult};
use nyx_crypto::symmetric::SymmetricKey;
use rand_core::{CryptoRng, RngCore};

/// Encrypted storage envelope.
///
/// Wire format on disk:
/// salt (16) || nonce (12) || ciphertext+tag
///
/// The encryption key is **not** stored here; it must be derived via
/// `argon2id` from the user's passphrase and the stored `salt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEnvelope {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl StorageEnvelope {
    /// Encrypt plaintext using the provided symmetric key.
    ///
    /// A random salt and nonce are generated from `rng`.
    pub fn seal(
        plaintext: &[u8],
        key: &SymmetricKey,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> NyxResult<Self> {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| NyxError::StorageError(e.to_string()))?;
        let n = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(n, plaintext)
            .map_err(|e| NyxError::StorageError(e.to_string()))?;

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt and authenticate the envelope.
    pub fn open(&self, key: &SymmetricKey) -> NyxResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| NyxError::StorageError(e.to_string()))?;
        let n = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(n, self.ciphertext.as_ref())
            .map_err(|_| NyxError::AuthenticationFailed)?;
        Ok(plaintext)
    }

    /// Serialize the envelope to a flat byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 12 + self.ciphertext.len());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize an envelope from raw bytes.
    pub fn from_bytes(data: &[u8]) -> NyxResult<Self> {
        if data.len() < 28 {
            return Err(NyxError::InsufficientData);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[0..16]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[16..28]);
        let ciphertext = data[28..].to_vec();
        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyx_crypto::rng::SecureRng;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn storage_roundtrip(plaintext in any::<Vec<u8>>()) {
            let mut rng = SecureRng::new();
            let key = SymmetricKey::generate(&mut rng);
            let envelope = StorageEnvelope::seal(&plaintext, &key, &mut rng).unwrap();
            let bytes = envelope.to_bytes();
            let parsed = StorageEnvelope::from_bytes(&bytes).unwrap();
            let decrypted = parsed.open(&key).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }
    }
}
