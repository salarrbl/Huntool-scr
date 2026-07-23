use nyx_common::error::NyxResult;

#[derive(::zeroize::ZeroizeOnDrop)]
pub struct QueueEntry {
    pub recipient_onion: String,
    pub ephemeral_pubkey: [u8; 32],
    
    pub encrypted_payload: Vec<u8>,
    pub timestamp: u64,
}

impl QueueEntry {
    pub fn seal(
        _message: &[u8],
        _recipient_onion: impl Into<String>,
        _recipient_key: &[u8; 32],
        _timestamp: u64,
    ) -> NyxResult<Self> {
        Ok(Self {
            recipient_onion: _recipient_onion.into(),
            ephemeral_pubkey: [0u8; 32],
            encrypted_payload: Vec::new(),
            timestamp: _timestamp,
        })
    }

    pub fn open(
        &self,
        _recipient_secret: &[u8; 32],
    ) -> NyxResult<Vec<u8>> {
        Ok(Vec::new())
    }
}
