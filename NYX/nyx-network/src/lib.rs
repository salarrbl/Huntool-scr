//! Tor-only networking layer for Project NYX.
//!
//! Outbound TCP is routed through the Tor SOCKS5 proxy.
//! Inbound Onion v3 services are managed via the Tor Control Port
//! (implementation deferred until `torut` is available).

pub mod connection;
pub mod onion;
pub mod transport;

// Re-export common items
pub use connection::{ConnectionConfig, ConnectionPool, TorConnection};
pub use onion::{OnionService, UnavailableOnionService};
pub use transport::dial_tor;
