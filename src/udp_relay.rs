use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use wireguard_netstack::{DohResolver, NetStack};

use crate::util;
use crate::util::s;

const SOCKS5_UDP_HEADER_LEN: usize = 4;
const STALE_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

struct UdpAssociation {
    dest_addr: SocketAddr,
    last_active: Instant,
}

pub struct UdpRelay {
    netstack: Arc<NetStack>,
    associations: Arc<Mutex<HashMap<SocketAddr, UdpAssociation>>>,
    dns_resolver: Arc<DohResolver>,
}

impl UdpRelay {
    pub fn new(netstack: Arc<NetStack>, dns_resolver: Arc<DohResolver>) -> Self {
        Self {
            netstack,
            associations: Arc::new(Mutex::new(HashMap::new())),
            dns_resolver,
        }
    }

    pub async fn handle_associate(&self) -> Result<SocketAddr> {
        let local_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let relay_addr = local_socket.local_addr()?;

        info!("{} {}", s(util::RELAY), relay_addr);

        let associations_cleanup = self.associations.clone();
        tokio::spawn(async move {
            loop {
                sleep(CLEANUP_INTERVAL).await;
                let mut map = associations_cleanup.lock().await;
                let before = map.len();
                map.retain(|_, assoc| assoc.last_active.elapsed() < STALE_TIMEOUT);
                let removed = before - map.len();
                if removed > 0 {
                    debug!("cleanup: {} ({} left)", removed, map.len());
                }
            }
        });

        let netstack = self.netstack.clone();
        let associations = self.associations.clone();
        let dns_resolver = self.dns_resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::relay_loop(local_socket, netstack, associations, dns_resolver).await {
                error!("loop: {}", e);
            }
        });

        Ok(relay_addr)
    }

    pub async fn start_cleanup_task(self: &Arc<Self>) {
        let associations = self.associations.clone();
        tokio::spawn(async move {
            loop {
                sleep(CLEANUP_INTERVAL).await;
                let mut map = associations.lock().await;
                let before = map.len();
                map.retain(|_, assoc| assoc.last_active.elapsed() < STALE_TIMEOUT);
                let removed = before - map.len();
                if removed > 0 {
                    debug!("cleanup: {} ({} left)", removed, map.len());
                }
            }
        });
    }

    async fn relay_loop(
        local_socket: UdpSocket,
        _netstack: Arc<NetStack>,
        associations: Arc<Mutex<HashMap<SocketAddr, UdpAssociation>>>,
        dns_resolver: Arc<DohResolver>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65535].into_boxed_slice();

        loop {
            let (n, src_addr) = local_socket.recv_from(&mut buf).await?;

            if n < SOCKS5_UDP_HEADER_LEN + 1 {
                warn!("short from {}: {}b", src_addr, n);
                continue;
            }

            let frag = buf[2];
            if frag != 0 {
                warn!("frag={} from {}", frag, src_addr);
                continue;
            }

            let atyp = buf[3];
            let (dest_addr, data_offset) = match parse_udp_header(&buf[..n], atyp) {
                Ok(result) => result,
                Err(e) => {
                    warn!("bad header from {}: {}", src_addr, e);
                    continue;
                }
            };

            // Resolve domain names through the tunnel if they were not resolved by parse_udp_header
            let dest_addr = if atyp == 0x03 && dest_addr.ip().is_unspecified() {
                let name_len = buf[4] as usize;
                if 5 + name_len + 2 <= n {
                    let name = String::from_utf8_lossy(&buf[5..5 + name_len]);
                    match dns_resolver.resolve_addr(&name, dest_addr.port()).await {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!("DNS resolve through tunnel failed for '{}': {}", name, e);
                            continue;
                        }
                    }
                } else {
                    dest_addr
                }
            } else {
                dest_addr
            };

            let payload = &buf[data_offset..n];

            {
                let mut map = associations.lock().await;
                map.insert(src_addr, UdpAssociation {
                    dest_addr,
                    last_active: Instant::now(),
                });
            }

            debug!("{} {}->{} ({}b)", s(util::RELAY), src_addr, dest_addr, payload.len());
        }
    }
}

fn parse_udp_header(data: &[u8], atyp: u8) -> Result<(SocketAddr, usize)> {
    match atyp {
        0x01 => {
            if data.len() < 10 {
                return Err(anyhow::anyhow!("short IPv4"));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), 10))
        }
        0x03 => {
            let name_len = data[4] as usize;
            if data.len() < 5 + name_len + 2 {
                return Err(anyhow::anyhow!("short domain"));
            }
            let port = u16::from_be_bytes([data[5 + name_len], data[5 + name_len + 1]]);
            let offset = 5 + name_len + 2;
            let name = String::from_utf8_lossy(&data[5..5 + name_len]);
            if let Ok(ip) = name.parse::<Ipv4Addr>() {
                Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), offset))
            } else {
                warn!("unresolved: {}", name);
                Ok((SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)), offset))
            }
        }
        0x04 => {
            if data.len() < 22 {
                return Err(anyhow::anyhow!("short IPv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            Ok((SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)), 22))
        }
        _ => Err(anyhow::anyhow!("bad atyp: 0x{:02x}", atyp)),
    }
}
