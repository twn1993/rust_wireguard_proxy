use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Mutex;
use wireguard_netstack::{DohResolver, DohServerConfig, ManagedTunnel, NetStack, TcpConnection};
use wireguard_netstack::wireguard::WireGuardConfig;

use crate::dns;

pub struct TunnelManager {
    tunnel: Arc<Mutex<Option<ManagedTunnel>>>,
    netstack: Arc<NetStack>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    dns_resolver: Arc<DohResolver>,
}

impl TunnelManager {
    pub async fn connect(config: WireGuardConfig) -> Result<Self> {
        Self::connect_with_dns(config, DohServerConfig::cloudflare()).await
    }

    pub async fn connect_with_dns(config: WireGuardConfig, dns_server: DohServerConfig) -> Result<Self> {
        let tunnel = ManagedTunnel::connect(config).await?;
        let netstack = tunnel.netstack().clone();
        let dns_resolver = Arc::new(DohResolver::new_tunneled_with_config(netstack.clone(), dns_server));
        Ok(Self {
            tunnel: Arc::new(Mutex::new(Some(tunnel))),
            netstack,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            dns_resolver,
        })
    }

    pub fn netstack(&self) -> Arc<NetStack> {
        self.netstack.clone()
    }

    pub fn dns_resolver(&self) -> Arc<DohResolver> {
        self.dns_resolver.clone()
    }

    pub async fn tcp_connect(&self, addr: &SocketAddr) -> Result<TcpConnection> {
        let conn = TcpConnection::connect(self.netstack.clone(), *addr).await?;
        Ok(conn)
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resolve a hostname by racing multiple DoH server configurations in parallel.
    /// Uses the existing tunnel netstack.
    pub async fn resolve_parallel(
        &self,
        hostname: &str,
        port: u16,
        servers: &[DohServerConfig],
        per_server_timeout: Duration,
    ) -> Result<SocketAddr> {
        dns::resolve_doh_parallel(hostname, port, servers, self.netstack.clone(), per_server_timeout).await
    }

    pub async fn shutdown(&self) {
        let mut guard = self.tunnel.lock().await;
        if let Some(tunnel) = guard.take() {
            tunnel.shutdown().await;
        }
        self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
