use nyx_common::error::NyxResult;
use nyx_protocol::session::TransportSession;

pub struct Session {
    pub id: String,
    pub peer_onion: String,
    pub peer_identity_pub: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub transport: TransportSession,
}

impl Session {
    pub fn establish(
        _is_initiator: bool,
        _local_identity: Option<()>,
        peer_onion: impl Into<String>,
        peer_identity_pub: [u8; 32],
    ) -> NyxResult<Self> {
        Ok(Self {
            id: "session-0".into(),
            peer_onion: peer_onion.into(),
            peer_identity_pub,
            handshake_hash: [0u8; 32],
            transport: TransportSession,
        })
    }
    pub fn encrypt(&mut self, _: &[u8]) -> NyxResult<Vec<u8>> { Ok(Vec::new()) }
    pub fn decrypt(&mut self, _: &[u8]) -> NyxResult<Vec<u8>> { Ok(Vec::new()) }
}
