use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nyx_common::error::{NyxError, NyxResult};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit symmetric key for ChaCha20-Poly1305.
///
/// **Security:** Does **not** implement `Clone` to prevent accidental
/// duplication of key material in memory. If duplication is required,
/// explicitly copy bytes and wrap a new instance.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Wrap raw bytes as a symmetric key.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Attempt to create a key from a byte slice.
    pub fn from_slice(slice: &[u8]) -> NyxResult<Self> {
        let mut arr = [0u8; 32];
        if slice.len() != 32 {
            return Err(NyxError::InvalidKeyMaterial);
        }
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a fresh random key.
    pub fn generate(rng: &mut (impl CryptoRng + rand_core::RngCore)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// AEAD ciphertext bundle: nonce || ciphertext+tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadEnvelope {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // includes Poly1305 tag at tail
}

impl AeadEnvelope {
    /// Encrypt plaintext under `key` using a random nonce.
    pub fn encrypt(
        plaintext: &[u8],
        key: &SymmetricKey,
        rng: &mut (impl CryptoRng + rand_core::RngCore),
    ) -> NyxResult<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| NyxError::CryptoError(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| NyxError::CryptoError(e.to_string()))?;
        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt and authenticate.
    pub fn decrypt(&self, key: &SymmetricKey) -> NyxResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| NyxError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| NyxError::AuthenticationFailed)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SecureRng;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn aead_roundtrip(plaintext in any::<Vec<u8>>()) {
            let mut rng = SecureRng::new();
            let key = SymmetricKey::generate(&mut rng);
            let envelope = AeadEnvelope::encrypt(&plaintext, &key, &mut rng).unwrap();
            let decrypted = envelope.decrypt(&key).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn aead_tamper_detect(nonce in any::<[u8;12]>(), _ct in any::<Vec<u8>>()) {
            let mut rng = SecureRng::new();
            let key = SymmetricKey::generate(&mut rng);
            let mut envelope = AeadEnvelope::encrypt(b"secret", &key, &mut rng).unwrap();
            // tamper with nonce
            envelope.nonce = nonce;
            prop_assert!(envelope.decrypt(&key).is_err());
        }
    }
}
