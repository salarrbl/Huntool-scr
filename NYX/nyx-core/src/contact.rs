use nyx_crypto::VerifyingKey;

/// A known remote contact.
pub struct Contact {
    pub display_name: String,
    pub verifying_key: VerifyingKey,
    pub onion_address: String,
}
