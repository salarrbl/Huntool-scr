use nyx_common::error::{NyxError, NyxResult};
use crate::{NYX_MAGIC, NYX_PROTOCOL_VERSION, NYX_HEADER_SIZE, NYX_MAX_FRAME_SIZE};
use crate::types::MessageType;

/// A parsed NYX wire frame.
///
/// The encrypted payload is stored as a `Vec<u8>` containing
/// ciphertext concatenated with the Poly1305 authentication tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub flags: u8,
    pub msg_type: MessageType,
    pub nonce: [u8; 12],
    pub payload: Vec<u8>,
}

impl Frame {
    /// Attempt to parse a frame from raw bytes.
    ///
    /// **Security:** performs strict length checks and rejects any
    /// frame exceeding `NYX_MAX_FRAME_SIZE` before allocation.
    pub fn parse(data: &[u8]) -> NyxResult<Self> {
        if data.len() < NYX_HEADER_SIZE {
            return Err(NyxError::InsufficientData);
        }
        if data[0..4] != NYX_MAGIC[..] {
            return Err(NyxError::ProtocolError("invalid magic bytes".into()));
        }
        let version = data[4];
        if version != NYX_PROTOCOL_VERSION {
            return Err(NyxError::VersionMismatch {
                expected: NYX_PROTOCOL_VERSION,
                got: version,
            });
        }
        let flags = data[5];
        let msg_type = MessageType::try_from(data[6])?;
        let _reserved = data[7];
        let payload_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

        if payload_len > NYX_MAX_FRAME_SIZE {
            return Err(NyxError::FrameTooLarge {
                size: payload_len,
                max: NYX_MAX_FRAME_SIZE,
            });
        }
        let total_len = NYX_HEADER_SIZE
            .checked_add(payload_len)
            .ok_or(NyxError::FrameTooLarge {
                size: payload_len,
                max: NYX_MAX_FRAME_SIZE,
            })?;

        if data.len() < total_len {
            return Err(NyxError::InsufficientData);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[12..24]);
        let payload = data[NYX_HEADER_SIZE..total_len].to_vec();

        Ok(Self {
            version,
            flags,
            msg_type,
            nonce,
            payload,
        })
    }

    /// Serialize the frame into a byte vector.
    pub fn serialize(&self) -> NyxResult<Vec<u8>> {
        if self.payload.len() > NYX_MAX_FRAME_SIZE {
            return Err(NyxError::FrameTooLarge {
                size: self.payload.len(),
                max: NYX_MAX_FRAME_SIZE,
            });
        }
        let mut buf = Vec::with_capacity(NYX_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&NYX_MAGIC);
        buf.push(self.version);
        buf.push(self.flags);
        buf.push(self.msg_type.into_u8());
        buf.push(0x00); // reserved
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a valid frame with given payload size.
    fn make_frame(payload_size: usize) -> Frame {
        Frame {
            version: NYX_PROTOCOL_VERSION,
            flags: 0,
            msg_type: MessageType::Data,
            nonce: [0xAB; 12],
            payload: vec![0xCD; payload_size],
        }
    }

    proptest! {
        #[test]
        fn frame_roundtrip(size in 0usize..NYX_MAX_FRAME_SIZE) {
            let f = make_frame(size);
            let bytes = f.serialize().unwrap();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(f, parsed);
        }

        #[test]
        fn reject_oversize(size in (NYX_MAX_FRAME_SIZE + 1)..=u32::MAX as usize) {
            let mut f = make_frame(0);
            f.payload = vec![0x00; size];
            prop_assert!(f.serialize().is_err());
        }

        #[test]
        fn reject_bad_magic(first_byte in any::<u8>()) {
            let mut bytes = make_frame(4).serialize().unwrap();
            bytes[0] = first_byte;
            // only fail if first_byte != NYX_MAGIC[0]
            if first_byte != NYX_MAGIC[0] {
                prop_assert!(Frame::parse(&bytes).is_err());
            }
        }

        #[test]
        fn reject_version_mismatch(v in any::<u8>()) {
            let mut bytes = make_frame(4).serialize().unwrap();
            bytes[4] = v;
            if v != NYX_PROTOCOL_VERSION {
                let err = Frame::parse(&bytes).unwrap_err();
                let is_mismatch = matches!(err, NyxError::VersionMismatch { .. });
                prop_assert!(is_mismatch);
            }
        }
    }
}
