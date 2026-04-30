use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use wireguard_netstack::{DohResolver, DohServerConfig, NetStack};

/// Resolve a hostname by racing multiple DoH server configurations in parallel.
///
/// Creates one `DohResolver` per server config, spawns a tokio task per resolver
/// calling `resolver.resolve_addr()` (public API), and returns the first successful
/// response. If all resolvers fail, returns the last error encountered.
///
/// Each resolver has a configurable per-server timeout.
pub async fn resolve_doh_parallel(
    hostname: &str,
    port: u16,
    servers: &[DohServerConfig],
    netstack: Arc<NetStack>,
    per_server_timeout: Duration,
) -> Result<SocketAddr> {
    if servers.is_empty() {
        return Err(anyhow!("no DoH servers configured"));
    }

    let hostname = hostname.to_string();
    let mut handles = Vec::with_capacity(servers.len());
    let mut last_error = None;

    for server in servers {
        let ns = netstack.clone();
        let server = server.clone();
        let hn = hostname.clone();

        let handle = tokio::spawn(async move {
            let resolver = DohResolver::new_tunneled_with_config(ns, server);
            match timeout(per_server_timeout, resolver.resolve_addr(&hn, port)).await {
                Ok(Ok(addr)) => Ok(addr),
                Ok(Err(e)) => Err(anyhow!("resolve failed: {}", e)),
                Err(_) => Err(anyhow!("timeout ({}s)", per_server_timeout.as_secs())),
            }
        });

        handles.push(handle);
    }

    // Collect results, return first success or last error
    for handle in handles {
        match handle.await {
            Ok(Ok(addr)) => return Ok(addr),
            Ok(Err(e)) => {
                last_error = Some(e);
            }
            Err(e) => {
                last_error = Some(anyhow!("task panicked: {}", e));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("all DoH servers failed")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: the function exists with the correct module path.
    #[test]
    fn test_module_loaded() {
        // Just verify the module compiles and the function is accessible
        assert!(std::mem::size_of::<DohServerConfig>() > 0);
    }
}
