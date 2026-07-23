use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use nyx_common::error::{NyxError, NyxResult};

use crate::transport::dial_tor;

#[allow(clippy::new_without_default)]
pub struct ConnectionConfig {
    pub target: String,
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            max_retries: 5,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
        }
    }
}

pub struct TorConnection {
    config: ConnectionConfig,
    attempt: AtomicU32,
}

impl TorConnection {
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            attempt: AtomicU32::new(0),
        }
    }

    pub async fn connect(&self) -> NyxResult<tokio::net::TcpStream> {
        let mut delay = self.config.base_delay_ms;
        loop {
            let current = self.attempt.fetch_add(1, Ordering::SeqCst);
            if current >= self.config.max_retries {
                return Err(NyxError::ProtocolError(format!(
                    "max retries ({}) exceeded for {}",
                    self.config.max_retries, self.config.target
                )));
            }
            match dial_tor(&self.config.target).await {
                Ok(stream) => {
                    self.attempt.store(0, Ordering::SeqCst);
                    return Ok(stream);
                }
                Err(e) => {
                    eprintln!(
                        "[nyx-network] connection attempt {} failed: {}",
                        current + 1,
                        e
                    );
                    if current + 1 >= self.config.max_retries {
                        return Err(e);
                    }
                    sleep(Duration::from_millis(delay)).await;
                    delay = (delay * 2).min(self.config.max_delay_ms);
                }
            }
        }
    }
}

pub struct ConnectionPool {
    peers: std::collections::HashMap<String, Arc<TorConnection>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, target: impl Into<String>) {
        let target = target.into();
        self.peers.insert(
            target.clone(),
            Arc::new(TorConnection::new(ConnectionConfig {
                target,
                ..Default::default()
            })),
        );
    }

    pub fn get(&self, target: &str) -> Option<Arc<TorConnection>> {
        self.peers.get(target).cloned()
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
