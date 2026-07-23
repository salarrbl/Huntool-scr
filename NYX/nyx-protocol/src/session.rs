pub struct NoiseHandshake;

impl NoiseHandshake {
    pub fn new(_: bool, _: Option<()>) -> Result<Self, String> { Ok(Self) }
    pub fn write_message(&mut self, _: &[u8]) -> Result<Vec<u8>, String> { Ok(Vec::new()) }
    pub fn read_message(&mut self, _: &[u8]) -> Result<Vec<u8>, String> { Ok(Vec::new()) }
    pub fn finalize(self) -> Result<(TransportSession, Option<Vec<u8>>), String> { Ok((TransportSession, None)) }
}

use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct TransportSession;

impl TransportSession {
    pub fn encrypt(&mut self, _: &[u8]) -> Result<Vec<u8>, String> { Ok(Vec::new()) }
    pub fn decrypt(&mut self, _: &[u8]) -> Result<Vec<u8>, String> { Ok(Vec::new()) }
    pub fn session_id(&self) -> &[u8; 32] { &[0u8; 32] }
}
