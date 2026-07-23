use argon2::{Argon2, Algorithm, Params, Version};
use hkdf::Hkdf;
use nyx_common::error::{NyxError, NyxResult};
use sha2::Sha256;

/// Derive a key from a passphrase using Argon2id (memory-hard).
///
/// Parameters (interactive) — 64 MiB, 3 iterations, 4 lanes.
/// These may be hardened per-profile in future phases.
pub fn derive_key_argon2id(passphrase: &[u8], salt: &[u8; 16]) -> NyxResult<[u8; 32]> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| NyxError::CryptoError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| NyxError::CryptoError(e.to_string()))?;
    Ok(out)
}

/// HKDF-SHA256: Extract-and-Expand key derivation.
///
/// Returns an `Hkdf` context that can be used to derive multiple sub-keys
/// with domain-separated `info` strings.
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(salt, ikm)
}

/// Expand a previously extracted HKDF context into output key material.
pub fn hkdf_expand(hkdf: &Hkdf<Sha256>, info: &[u8], okm: &mut [u8]) -> NyxResult<()> {
    hkdf.expand(info, okm)
        .map_err(|e| NyxError::CryptoError(e.to_string()))
}

/// One-shot HKDF-SHA256 extract-and-expand.
pub fn hkdf_derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> NyxResult<()> {
    let hk = hkdf_extract(salt, ikm);
    hkdf_expand(&hk, info, okm)
}

/// Domain-separated key derivation via BLAKE3.
///
/// BLAKE3's `derive_key` provides a built-in KDF that is faster
/// and simpler than HKDF-HMAC for many use-cases, but we keep
/// both primitives available as required by the specification.
pub fn kdf_blake3(ikm: &[u8], context: &str) -> [u8; 32] {
    blake3::derive_key(context, ikm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn argon2id_deterministic(pass in any::<Vec<u8>>(), salt in any::<[u8; 16]>()) {
            let a = derive_key_argon2id(&pass, &salt).unwrap();
            let b = derive_key_argon2id(&pass, &salt).unwrap();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn argon2id_different_salts(pass in any::<Vec<u8>>(), s1 in any::<[u8; 16]>(), s2 in any::<[u8; 16]>()) {
            let a = derive_key_argon2id(&pass, &s1).unwrap();
            let b = derive_key_argon2id(&pass, &s2).unwrap();
            prop_assert_ne!(a, b);
        }

        #[test]
        fn hkdf_expand_consistent(ikm in any::<Vec<u8>>(), salt in any::<Vec<u8>>(), info in any::< Vec<u8>>()) {
            let mut okm1 = [0u8; 32];
            let mut okm2 = [0u8; 32];
            hkdf_derive(Some(&salt), &ikm, &info, &mut okm1).unwrap();
            hkdf_derive(Some(&salt), &ikm, &info, &mut okm2).unwrap();
            prop_assert_eq!(okm1, okm2);
        }

        #[test]
        fn blake3_kdf_deterministic(ikm in any::<Vec<u8>>(), ctx in "[a-zA-Z0-9]{1,64}") {
            let a = kdf_blake3(&ikm, &ctx);
            let b = kdf_blake3(&ikm, &ctx);
            prop_assert_eq!(a, b);
        }
    }
}
