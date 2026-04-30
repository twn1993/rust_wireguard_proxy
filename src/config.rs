use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, Result};
use base64::Engine as _;
use ipnet::Ipv4Net;
use serde::Deserialize;
use wireguard_netstack::DohServerConfig;

use crate::util;
use crate::util::s;

/// WireGuard configuration parsed from a standard .conf file.
#[derive(Debug, Deserialize)]
pub struct WgProxyConfig {
    #[serde(rename = "Interface")]
    pub interface: InterfaceConfig,
    #[serde(rename = "Peer")]
    pub peer: PeerConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceConfig {
    pub private_key: String,
    pub address: Option<String>,
    pub listen_port: Option<u16>,
    #[serde(alias = "DNS")]
    pub dns: Option<String>,
    #[serde(alias = "MTU")]
    pub mtu: Option<u16>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

impl WgProxyConfig {
    /// Parse a WireGuard .conf file from disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let reader = BufReader::new(file);
        let cfg: Self = serde_ini::from_read(reader)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Convert to the wireguard-netstack WireGuardConfig struct,
    /// optionally overriding the MTU with the given value.
    pub fn to_wireguard_config_with_mtu(&self, mtu_override: Option<u16>) -> Result<wireguard_netstack::wireguard::WireGuardConfig> {
        let mut cfg = self.to_wireguard_config()?;
        if let Some(mtu) = mtu_override {
            if mtu > 0 {
                cfg.mtu = Some(mtu);
            }
        }
        Ok(cfg)
    }

    /// Convert to the wireguard-netstack WireGuardConfig struct.
    pub fn to_wireguard_config(&self) -> Result<wireguard_netstack::wireguard::WireGuardConfig> {
        let private_key = decode_key(&self.interface.private_key)?;
        let peer_public_key = decode_key(&self.peer.public_key)?;

        let endpoint_str = self.peer.endpoint.as_ref()
            .ok_or_else(|| anyhow!("{} {}", s(util::CONFIG), "endpoint required"))?;
        let peer_endpoint: SocketAddr = endpoint_str.parse()?;

        let tunnel_ip = match &self.interface.address {
            Some(addr) => {
                let first = addr.split(',').next()
                    .ok_or_else(|| anyhow!("addr empty"))?
                    .trim();
                let net: Ipv4Net = first.parse()
                    .map_err(|e| anyhow!("bad addr '{}': {}", first, e))?;
                net.addr()
            }
            None => return Err(anyhow!("addr required")),
        };

        let preshared_key = match &self.peer.preshared_key {
            Some(pk) => Some(decode_key(pk)?),
            None => None,
        };

        Ok(wireguard_netstack::wireguard::WireGuardConfig {
            private_key,
            peer_public_key,
            peer_endpoint,
            tunnel_ip,
            preshared_key,
            keepalive_seconds: self.peer.persistent_keepalive,
            mtu: self.interface.mtu,
        })
    }

    /// Convert the config's DNS field to a DohServerConfig for tunnel-based DNS resolution.
    ///
    /// Maps well-known DNS server IPs to their DNS-over-HTTPS equivalents.
    /// Falls back to Cloudflare (1.1.1.1) when no DNS is configured or the IP is unknown.
    pub fn to_doh_server_config(&self) -> DohServerConfig {
        let dns_str = match &self.interface.dns {
            Some(dns) => dns,
            None => return DohServerConfig::cloudflare(),
        };

        // Take the first DNS server from a comma-separated list
        let first_dns = dns_str.split(',').next().map(|s| s.trim()).unwrap_or("");

        match first_dns {
            "1.1.1.1" | "1.0.0.1" => DohServerConfig::cloudflare(),
            "8.8.8.8" | "8.8.4.4" => DohServerConfig::google(),
            "9.9.9.9" | "149.112.112.112" => DohServerConfig::quad9(),
            "94.140.14.14" | "94.140.15.15" => DohServerConfig::adguard(),
            "194.242.2.2" | "194.242.2.3" => {
                DohServerConfig::new(
                    "dns.mullvad.net",
                    vec![
                        std::net::Ipv4Addr::new(194, 242, 2, 2),
                        std::net::Ipv4Addr::new(194, 242, 2, 3),
                    ],
                )
            }
            _ => {
                tracing::warn!(
                    "unknown DNS server '{}', falling back to Cloudflare DoH",
                    first_dns
                );
                DohServerConfig::cloudflare()
            }
        }
    }

    fn validate(&self) -> Result<()> {
        decode_key(&self.interface.private_key)
            .map_err(|e| anyhow!("bad key: {}", e))?;
        decode_key(&self.peer.public_key)
            .map_err(|e| anyhow!("bad key: {}", e))?;
        Ok(())
    }
}

fn decode_key(key_b64: &str) -> Result<[u8; 32]> {
    if key_b64.len() != 44 {
        return Err(anyhow!(
            "bad len: {} (need 44)", key_b64.len()
        ));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine
        .decode(key_b64)
        .map_err(|e| anyhow!("decode: {}", e))?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "bad decoded: {} (need 32)", decoded.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a proper 44-char base64-encoded 32-byte key for testing.
    fn test_key() -> String {
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(&[0u8; 32])
    }

    fn make_conf(private_key: &str, public_key: &str) -> String {
        format!(
            r#"
[Interface]
PrivateKey = {}
Address = 10.0.0.2/32
ListenPort = 51820
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = {}
PresharedKey = {}
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#,
            private_key,
            public_key,
            private_key, // reuse same key for preshared
        )
    }

    #[test]
    fn test_parse_valid() {
        let key = test_key();
        let conf = make_conf(&key, &key);
        let config: WgProxyConfig = serde_ini::from_str(&conf).unwrap();
        assert_eq!(config.interface.private_key.len(), 44);
        assert_eq!(config.interface.address.as_deref(), Some("10.0.0.2/32"));
        assert_eq!(config.peer.endpoint.as_deref(), Some("203.0.113.1:51820"));
        assert_eq!(config.peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn test_validate_valid() {
        let key = test_key();
        let conf = make_conf(&key, &key);
        let config: WgProxyConfig = serde_ini::from_str(&conf).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_to_wireguard_config() {
        let key = test_key();
        let conf = make_conf(&key, &key);
        let config: WgProxyConfig = serde_ini::from_str(&conf).unwrap();
        let wg = config.to_wireguard_config().unwrap();
        assert_eq!(wg.private_key.len(), 32);
        assert_eq!(wg.peer_public_key.len(), 32);
        assert_eq!(wg.tunnel_ip.to_string(), "10.0.0.2");
        assert!(wg.preshared_key.is_some());
        assert_eq!(wg.keepalive_seconds, Some(25));
        assert_eq!(wg.mtu, Some(1420));
    }

    #[test]
    fn test_missing_endpoint() {
        let key = test_key();
        let conf = make_conf(&key, &key);
        let conf = conf.replace("Endpoint = 203.0.113.1:51820\n", "");
        let config: WgProxyConfig = serde_ini::from_str(&conf).unwrap();
        assert!(config.to_wireguard_config().is_err());
    }

    #[test]
    fn test_missing_address() {
        let key = test_key();
        let conf = make_conf(&key, &key);
        let conf = conf.replace("Address = 10.0.0.2/32\n", "");
        let config: WgProxyConfig = serde_ini::from_str(&conf).unwrap();
        assert!(config.to_wireguard_config().is_err());
    }

    #[test]
    fn test_from_file_nonexistent() {
        let result = WgProxyConfig::from_file("/tmp/nonexistent-wg.conf");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_key_valid() {
        let engine = base64::engine::general_purpose::STANDARD;
        let key = engine.encode(&[0u8; 32]);
        assert_eq!(key.len(), 44);
        let decoded = decode_key(&key).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, [0u8; 32]);
    }

    #[test]
    fn test_decode_key_invalid_length() {
        assert!(decode_key("too-short").is_err());
    }
}
