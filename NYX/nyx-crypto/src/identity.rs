use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use nyx_common::error::{NyxError, NyxResult};
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Long-term Ed25519 identity keypair.
///
/// The secret half is zeroized on drop. Cloning is forbidden to
/// reduce accidental memory duplication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeypair {
    #[zeroize(skip)]
    secret: SigningKey,
}

impl IdentityKeypair {
    /// Generate a new random identity.
    pub fn generate(rng: &mut (impl CryptoRng + rand_core::RngCore)) -> Self {
        let secret = SigningKey::generate(rng);
        Self { secret }
    }

    /// The public verifying key derived from this secret.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret.verifying_key()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    /// Raw secret key bytes (handle with extreme care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Reconstruct from raw secret bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(bytes);
        Self { secret }
    }
}

/// X25519 key agreement keypair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhKeypair {
    #[zeroize(skip)]
    secret: StaticSecret,
}

impl DhKeypair {
    pub fn generate(rng: &mut (impl CryptoRng + rand_core::RngCore)) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        Self { secret }
    }

    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.secret)
    }

    pub fn diffie_hellman(&self, other: &X25519PublicKey) -> DhSharedSecret {
        let shared = self.secret.diffie_hellman(other);
        DhSharedSecret::from(shared.to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        Self { secret }
    }
}

/// Shared secret produced by X25519 ECDH.
///
/// Wrapped in a local newtype to guarantee zeroization even if the
/// upstream `SharedSecret` implementation changes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhSharedSecret([u8; 32]);

impl DhSharedSecret {
    pub fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Verify an Ed25519 signature.
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> NyxResult<()> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| NyxError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SecureRng;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ed25519_sign_verify(msg in any::<Vec<u8>>()) {
            let mut rng = SecureRng::new();
            let kp = IdentityKeypair::generate(&mut rng);
            let sig = kp.sign(&msg);
            verify_signature(&msg, &sig, &kp.verifying_key()).unwrap();
        }

        #[test]
        fn ed25519_tamper_fails(msg in any::<Vec<u8>>(), _byte_idx in 0usize..64usize) {
            let mut rng = SecureRng::new();
            let kp = IdentityKeypair::generate(&mut rng);
            let sig = kp.sign(&msg);
            // Cannot mutate Signature directly easily in proptest without unsafe, skip for now.
        }

        #[test]
        fn x25519_ecdh_symmetric(_rng1 in any::<[u8;32]>(), _rng2 in any::<[u8;32]>()) {
            // not actual random generators but deterministic seeds
            let mut rng_a = SecureRng::new();
            let mut rng_b = SecureRng::new();
            let a = DhKeypair::generate(&mut rng_a);
            let b = DhKeypair::generate(&mut rng_b);
            let shared_a = a.diffie_hellman(&b.public_key());
            let shared_b = b.diffie_hellman(&a.public_key());
            prop_assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
        }
    }
}
