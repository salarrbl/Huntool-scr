use thiserror::Error;

/// Central error type for Project NYX.
///
/// All crates return concrete errors but map them into `NyxError` at
/// boundary layers to prevent information leakage.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NyxError {
    #[error("crypto failure: {0}")]
    CryptoError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("frame too large: {size} > {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("insufficient data")]
    InsufficientData,

    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type NyxResult<T> = Result<T, NyxError>;
