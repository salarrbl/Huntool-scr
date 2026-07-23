use nyx_common::error::{NyxError, NyxResult};

/// Message types carried by NYX wire frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Initial Noise handshake message.
    HandshakeInit = 0x01,
    /// Noise handshake response.
    HandshakeResponse = 0x02,
    /// Encrypted application data.
    Data = 0x03,
    /// Control / keep-alive.
    Control = 0x04,
}

impl MessageType {
    pub fn into_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = NyxError;

    fn try_from(value: u8) -> NyxResult<Self> {
        match value {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::Data),
            0x04 => Ok(MessageType::Control),
            _ => Err(NyxError::InvalidMessageType(value)),
        }
    }
}
