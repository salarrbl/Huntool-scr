use nyx_common::error::{NyxError, NyxResult};

/// Trait for Onion v3 service lifecycle management.
///
/// Concrete implementations use the Tor Control Port to create,
/// persist, and destroy ephemeral onion services.
///
/// **Security:** The service must bind exclusively to `127.0.0.1`
/// inside the application. No clearnet listener should exist.
#[async_trait::async_trait]
pub trait OnionService {
    /// Create a new ephemeral Onion v3 service on the given local port.
    async fn create_service(&self, local_port: u16) -> NyxResult<String>;

    /// Destroy the service identified by its onion address.
    async fn destroy_service(&self, onion_address: &str) -> NyxResult<()>;

    /// List currently active services managed by this instance.
    async fn list_services(&self) -> NyxResult<Vec<String>>;
}

/// Placeholder implementation used when no Tor Control Port is available.
///
/// Always returns an error describing that Control Port integration
/// requires the `torut` crate (not available in offline builds).
pub struct UnavailableOnionService;

#[async_trait::async_trait]
impl OnionService for UnavailableOnionService {
    async fn create_service(&self, _local_port: u16) -> NyxResult<String> {
        Err(NyxError::ProtocolError(
            "Onion service creation requires torut and a running Tor daemon".into(),
        ))
    }

    async fn destroy_service(&self, _onion_address: &str) -> NyxResult<()> {
        Err(NyxError::ProtocolError(
            "Onion service management unavailable".into(),
        ))
    }

    async fn list_services(&self) -> NyxResult<Vec<String>> {
        Ok(vec![])
    }
}
