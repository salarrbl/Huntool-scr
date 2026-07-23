use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

/// Secure random number generator backed by the operating system CSPRNG.
///
/// All randomness in NYX (keys, nonces, salts) **must** flow through this
/// wrapper so that a single point of audit exists for RNG hygiene.
pub struct SecureRng(OsRng);

impl SecureRng {
    pub fn new() -> Self {
        Self(OsRng)
    }

    /// Fill `dest` with cryptographically secure random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    /// Generate a fixed-size random byte array.
    pub fn random_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.fill_bytes(&mut buf);
        buf
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn random_bytes_are_not_constant(size in 1usize..1024) {
            let mut rng = SecureRng::new();
            let mut a = vec![0u8; size];
            let mut b = vec![0u8; size];
            rng.fill_bytes(&mut a);
            rng.fill_bytes(&mut b);
            prop_assert_ne!(a, b);
        }
    }
}
