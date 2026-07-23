use nyx_common::error::{NyxError, NyxResult};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Hardcoded Tor SOCKS5 proxy endpoints.
///
/// We support both standard Tor (9050) and Tor Browser (9150).
/// No other proxy configuration is permitted to prevent clearnet fallback.
const TOR_PROXIES: &[(&str, u16)] = &[("127.0.0.1", 9050), ("127.0.0.1", 9150)];

/// Dial `target` (a `.onion` address or other TCP endpoint) through Tor.
///
/// Attempts connections in order: tries each proxy, returns the first
/// successful stream. Fails closed if no proxy is reachable.
pub async fn dial_tor(target: &str) -> NyxResult<TcpStream> {
    for &(host, port) in TOR_PROXIES {
        match Socks5Stream::connect((host, port), target).await {
            Ok(stream) => {
                // Socks5Stream derefs to TcpStream
                return Ok(stream.into_inner());
            }
            Err(e) => {
                eprintln!("[nyx-network] proxy {}:{} failed: {}", host, port, e);
            }
        }
    }
    Err(NyxError::ProtocolError(
        "no Tor proxy reachable on 9050 or 9150".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tor_proxy_unreachable() {
        // With no Tor running, all proxies should fail.
        // We test with a fake onion address.
        let result = dial_tor("nonexistent.onion:80").await;
        assert!(result.is_err());
    }
}
