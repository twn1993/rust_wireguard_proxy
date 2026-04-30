use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use wireguard_netstack::DohServerConfig;

/// Well-known DNS provider names that can be used in config's `dns.provider` field.
pub const KNOWN_PROVIDERS: &[&str] = &[
    "cloudflare", "google", "quad9", "adguard", "mullvad",
];

/// A single manual DoH endpoint override.
/// Maps a hostname + IPs to a custom DNS-over-HTTPS server.
#[derive(Debug, Clone, Deserialize)]
pub struct ManualDohEndpoint {
    pub hostname: String,
    pub ips: Vec<String>,
}

/// General proxy settings.
#[derive(Debug, Clone, Deserialize)]
pub struct GeneralConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

/// DNS resolution configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// Enable auto-mapping of well-known DNS server IPs to DoH endpoints.
    #[serde(default = "default_dns_auto_map")]
    pub auto_map: bool,
    /// DNS server IP strings for auto-mapping (e.g. "1.1.1.1", "8.8.8.8").
    #[serde(default)]
    pub servers: Vec<String>,
    /// Manual DoH endpoint overrides. If non-empty, the first entry is used.
    #[serde(default)]
    pub manual_endpoints: Vec<ManualDohEndpoint>,
    /// Named DNS provider: "cloudflare", "google", "quad9", "adguard", "mullvad".
    /// Only used when `servers` and `manual_endpoints` are both empty.
    /// CLI overrides file, file overrides default.
    #[serde(default)]
    pub provider: Option<String>,
}

fn default_dns_auto_map() -> bool {
    true
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            auto_map: true,
            servers: Vec::new(),
            manual_endpoints: Vec::new(),
            provider: None,
        }
    }
}

/// SOCKS5 proxy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Socks5Config {
    /// Bind address for the SOCKS5 listener.
    #[serde(default = "default_socks5_bind")]
    pub bind: String,
    /// Port for the SOCKS5 listener.
    #[serde(default = "default_socks5_port")]
    pub port: u16,
    /// SOCKS5 connection timeout in seconds.
    #[serde(default = "default_socks5_timeout")]
    pub timeout_secs: u64,
}

fn default_socks5_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_socks5_port() -> u16 {
    1080
}
fn default_socks5_timeout() -> u64 {
    30
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            bind: default_socks5_bind(),
            port: default_socks5_port(),
            timeout_secs: default_socks5_timeout(),
        }
    }
}

/// WireGuard tunnel configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel MTU (default 1500). Passed to WireGuardConfig.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Tunnel connection timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// HTTP test timeout in seconds (for --config-dir mode data-plane verification).
    #[serde(default = "default_http_test_timeout")]
    pub http_test_timeout_secs: u64,
}

fn default_mtu() -> u16 {
    1500
}
fn default_connect_timeout() -> u64 {
    12
}
fn default_http_test_timeout() -> u64 {
    10
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            connect_timeout_secs: default_connect_timeout(),
            http_test_timeout_secs: default_http_test_timeout(),
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// DNS cache TTL in seconds.
    #[serde(default = "default_dns_ttl")]
    pub dns_ttl_secs: u64,
}

fn default_dns_ttl() -> u64 {
    300
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            dns_ttl_secs: default_dns_ttl(),
        }
    }
}

/// Top-level proxy configuration parsed from a TOML file.
///
/// Merge precedence (highest to lowest):
/// 1. CLI overrides (explicitly provided on the command line)
/// 2. Config file values
/// 3. Hard-coded defaults
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub socks5: Socks5Config,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            socks5: Socks5Config::default(),
            tunnel: TunnelConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// Load a ProxyConfig from a TOML file path.
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("failed to read config file '{}': {}", path.as_ref().display(), e))?;
        let cfg: ProxyConfig = toml::from_str(&content)
            .map_err(|e| anyhow!("failed to parse config file '{}': {}", path.as_ref().display(), e))?;
        Ok(cfg)
    }

    /// Merge two configs with `self` (CLI) taking precedence over `file` (file config).
    ///
    /// For each field:
    /// - If the CLI value differs from its default → use CLI value
    /// - Else if the file value differs from its default → use file value
    /// - Else → use the default
    ///
    /// For Vec fields: CLI list replaces file list entirely if non-empty.
    pub fn merge(self, file: ProxyConfig) -> ProxyConfig {
        ProxyConfig {
            general: GeneralConfig {
                log_level: take_precedence(
                    &self.general.log_level,
                    &file.general.log_level,
                    &GeneralConfig::default().log_level,
                ),
            },
            dns: DnsConfig {
                auto_map: take_precedence(
                    &self.dns.auto_map,
                    &file.dns.auto_map,
                    &DnsConfig::default().auto_map,
                ),
                servers: if !self.dns.servers.is_empty() {
                    self.dns.servers
                } else if !file.dns.servers.is_empty() {
                    file.dns.servers
                } else {
                    DnsConfig::default().servers
                },
                manual_endpoints: if !self.dns.manual_endpoints.is_empty() {
                    self.dns.manual_endpoints
                } else if !file.dns.manual_endpoints.is_empty() {
                    file.dns.manual_endpoints
                } else {
                    DnsConfig::default().manual_endpoints
                },
                provider: if self.dns.provider.is_some() {
                    self.dns.provider.clone()
                } else if file.dns.provider.is_some() {
                    file.dns.provider.clone()
                } else {
                    None
                },
            },
            socks5: Socks5Config {
                bind: take_precedence(
                    &self.socks5.bind,
                    &file.socks5.bind,
                    &Socks5Config::default().bind,
                ),
                port: take_precedence(
                    &self.socks5.port,
                    &file.socks5.port,
                    &Socks5Config::default().port,
                ),
                timeout_secs: take_precedence(
                    &self.socks5.timeout_secs,
                    &file.socks5.timeout_secs,
                    &Socks5Config::default().timeout_secs,
                ),
            },
            tunnel: TunnelConfig {
                mtu: take_precedence(
                    &self.tunnel.mtu,
                    &file.tunnel.mtu,
                    &TunnelConfig::default().mtu,
                ),
                connect_timeout_secs: take_precedence(
                    &self.tunnel.connect_timeout_secs,
                    &file.tunnel.connect_timeout_secs,
                    &TunnelConfig::default().connect_timeout_secs,
                ),
                http_test_timeout_secs: take_precedence(
                    &self.tunnel.http_test_timeout_secs,
                    &file.tunnel.http_test_timeout_secs,
                    &TunnelConfig::default().http_test_timeout_secs,
                ),
            },
            cache: CacheConfig {
                dns_ttl_secs: take_precedence(
                    &self.cache.dns_ttl_secs,
                    &file.cache.dns_ttl_secs,
                    &CacheConfig::default().dns_ttl_secs,
                ),
            },
        }
    }

    /// Resolve the effective DoH server configuration from this proxy config.
    ///
    /// Priority:
    /// 1. If manual_endpoints is non-empty, use the first manual endpoint.
    /// 2. If servers is non-empty, try to auto-map the first server IP.
    /// 3. If provider is set, use the named provider.
    /// 4. Fall back to Cloudflare.
    pub fn resolve_doh_config(&self) -> DohServerConfig {
        // Manual endpoint takes highest priority
        if let Some(endpoint) = self.dns.manual_endpoints.first() {
            let ips: Vec<Ipv4Addr> = endpoint
                .ips
                .iter()
                .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
                .collect();
            if !ips.is_empty() {
                return DohServerConfig::new(endpoint.hostname.clone(), ips);
            }
        }

        // Try auto-mapping the first server IP
        if !self.dns.servers.is_empty() {
            if let Some(first) = self.dns.servers.first() {
                return auto_map_doh(first);
            }
        }

        // Named provider overrides default
        if let Some(ref name) = self.dns.provider {
            if let Some(doh) = resolve_provider(name) {
                return doh;
            }
            tracing::warn!("unknown DNS provider '{}', falling back to Cloudflare", name);
        }

        // Fallback to Cloudflare
        DohServerConfig::cloudflare()
    }

    /// Generate a default TOML configuration string with explanatory comments.
    pub fn generate_default_toml() -> String {
        let default = ProxyConfig::default();
        format!(
            r#"# wg-proxy configuration file
# Auto-generated. Edit this file to customize your proxy.

[general]
# Log level: trace, debug, info, warn, error
log_level = "{}"

[dns]
# DNS servers for tunnel-based resolution (TOML array of IP strings).
# Known IPs are auto-mapped to their DoH equivalents:
#   1.1.1.1, 1.0.0.1     → Cloudflare
#   8.8.8.8, 8.8.4.4     → Google
#   9.9.9.9              → Quad9
#   94.140.14.14         → AdGuard
#   194.242.2.2          → Mullvad
servers = []

# Named DNS provider (used when servers is empty).
# Accepted values: "cloudflare", "google", "quad9", "adguard", "mullvad"
# provider = "cloudflare"

# Manual DoH endpoint overrides (optional, highest priority).
# Uncomment and customize for a custom DNS-over-HTTPS server:
# [[dns.manual_endpoints]]
# hostname = "mydns.example.com"
# ips = ["10.0.0.1"]

[socks5]
bind = "{}"
port = {}
timeout_secs = {}

[tunnel]
mtu = {}
connect_timeout_secs = {}
http_test_timeout_secs = {}

[cache]
dns_ttl_secs = {}
"#,
            default.general.log_level,
            default.socks5.bind,
            default.socks5.port,
            default.socks5.timeout_secs,
            default.tunnel.mtu,
            default.tunnel.connect_timeout_secs,
            default.tunnel.http_test_timeout_secs,
            default.cache.dns_ttl_secs,
        )
    }
}

/// Auto-map a DNS server IP string to its known DoH configuration.
/// Falls back to Cloudflare for unknown IPs.
fn auto_map_doh(ip: &str) -> DohServerConfig {
    match ip.trim() {
        "1.1.1.1" | "1.0.0.1" => DohServerConfig::cloudflare(),
        "8.8.8.8" | "8.8.4.4" => DohServerConfig::google(),
        "9.9.9.9" | "149.112.112.112" => DohServerConfig::quad9(),
        "94.140.14.14" | "94.140.15.15" => DohServerConfig::adguard(),
        "194.242.2.2" | "194.242.2.3" => mullvad_doh(),
        _ => {
            tracing::warn!("unknown DNS server '{}', falling back to Cloudflare DoH", ip);
            DohServerConfig::cloudflare()
        }
    }
}

/// Resolve a named DNS provider to its DohServerConfig.
/// Returns None for unknown names.
fn resolve_provider(name: &str) -> Option<DohServerConfig> {
    match name.trim().to_lowercase().as_str() {
        "cloudflare" => Some(DohServerConfig::cloudflare()),
        "google" => Some(DohServerConfig::google()),
        "quad9" => Some(DohServerConfig::quad9()),
        "adguard" => Some(DohServerConfig::adguard()),
        "mullvad" => Some(mullvad_doh()),
        _ => None,
    }
}

/// Mullvad DNS-over-HTTPS (vanilla, no blocking).
/// Hostname: dns.mullvad.net
/// IPv4: 194.242.2.2, 194.242.2.3
fn mullvad_doh() -> DohServerConfig {
    DohServerConfig::new(
        "dns.mullvad.net",
        vec![
            Ipv4Addr::new(194, 242, 2, 2),
            Ipv4Addr::new(194, 242, 2, 3),
        ],
    )
}

/// Helper: return `cli_val` if it differs from the default, else `file_val` if it differs from the default,
/// else the default.
fn take_precedence<T: PartialEq>(cli_val: &T, file_val: &T, default_val: &T) -> T
where
    T: Clone,
{
    if cli_val != default_val {
        cli_val.clone()
    } else if file_val != default_val {
        file_val.clone()
    } else {
        default_val.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.general.log_level, "info");
        assert_eq!(cfg.socks5.port, 1080);
        assert_eq!(cfg.socks5.bind, "127.0.0.1");
        assert_eq!(cfg.socks5.timeout_secs, 30);
        assert_eq!(cfg.tunnel.mtu, 1500);
        assert_eq!(cfg.tunnel.connect_timeout_secs, 12);
        assert_eq!(cfg.tunnel.http_test_timeout_secs, 10);
        assert_eq!(cfg.cache.dns_ttl_secs, 300);
        assert!(cfg.dns.auto_map);
        assert!(cfg.dns.servers.is_empty());
        assert!(cfg.dns.manual_endpoints.is_empty());
    }

    #[test]
    fn test_from_file_nonexistent() {
        let result = ProxyConfig::from_file("/tmp/nonexistent-proxy.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_valid() {
        let toml_str = r#"
[general]
log_level = "debug"

[socks5]
port = 2080
timeout_secs = 60

[tunnel]
mtu = 1400
"#;
        let cfg: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.general.log_level, "debug");
        assert_eq!(cfg.socks5.port, 2080);
        assert_eq!(cfg.socks5.timeout_secs, 60);
        assert_eq!(cfg.tunnel.mtu, 1400);
        // defaults for unspecified fields
        assert_eq!(cfg.socks5.bind, "127.0.0.1");
        assert_eq!(cfg.cache.dns_ttl_secs, 300);
        assert!(cfg.dns.auto_map);
    }

    #[test]
    fn test_merge_cli_overrides_file() {
        let file_cfg = ProxyConfig {
            socks5: Socks5Config {
                port: 2080,
                ..Socks5Config::default()
            },
            tunnel: TunnelConfig {
                mtu: 1400,
                ..TunnelConfig::default()
            },
            ..ProxyConfig::default()
        };

        let cli_cfg = ProxyConfig {
            socks5: Socks5Config {
                port: 3080,
                ..Socks5Config::default()
            },
            ..ProxyConfig::default()
        };

        let merged = cli_cfg.merge(file_cfg);
        assert_eq!(merged.socks5.port, 3080); // CLI wins
        assert_eq!(merged.tunnel.mtu, 1400);  // File wins (CLI didn't set)
        assert_eq!(merged.socks5.timeout_secs, 30); // Default
        assert_eq!(merged.socks5.bind, "127.0.0.1"); // Default
    }

    #[test]
    fn test_merge_file_overrides_default() {
        let file_cfg = ProxyConfig {
            tunnel: TunnelConfig {
                mtu: 1400,
                ..TunnelConfig::default()
            },
            ..ProxyConfig::default()
        };

        let cli_cfg = ProxyConfig::default();
        let merged = cli_cfg.merge(file_cfg);
        assert_eq!(merged.tunnel.mtu, 1400);
        assert_eq!(merged.socks5.port, 1080); // default
    }

    #[test]
    fn test_merge_servers_replacement() {
        let file_cfg = ProxyConfig {
            dns: DnsConfig {
                servers: vec!["8.8.8.8".to_string()],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };

        let cli_cfg = ProxyConfig::default();
        let merged = cli_cfg.merge(file_cfg);
        assert_eq!(merged.dns.servers, vec!["8.8.8.8"]);

        // CLI non-empty replaces file (clone file_cfg since merge consumes)
        let file_cfg2 = ProxyConfig {
            dns: DnsConfig {
                servers: vec!["8.8.8.8".to_string()],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let cli_cfg2 = ProxyConfig {
            dns: DnsConfig {
                servers: vec!["1.1.1.1".to_string()],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged2 = cli_cfg2.merge(file_cfg2);
        assert_eq!(merged2.dns.servers, vec!["1.1.1.1"]);
    }

    #[test]
    fn test_resolve_doh_config_cloudflare_default() {
        let cfg = ProxyConfig::default();
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");
    }

    #[test]
    fn test_resolve_doh_config_auto_map_google() {
        let cfg = ProxyConfig {
            dns: DnsConfig {
                servers: vec!["8.8.8.8".to_string()],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "dns.google");
    }

    #[test]
    fn test_resolve_doh_config_manual_endpoint() {
        let cfg = ProxyConfig {
            dns: DnsConfig {
                manual_endpoints: vec![ManualDohEndpoint {
                    hostname: "mydns.example.com".to_string(),
                    ips: vec!["10.0.0.1".to_string()],
                }],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "mydns.example.com");
        assert_eq!(doh.ips, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn test_generate_default_toml() {
        let toml_str = ProxyConfig::generate_default_toml();
        // Should parse back to default config
        let cfg: ProxyConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.general.log_level, "info");
        assert_eq!(cfg.socks5.port, 1080);
        assert_eq!(cfg.tunnel.mtu, 1500);
        assert_eq!(cfg.cache.dns_ttl_secs, 300);
    }

    #[test]
    fn test_from_file_invalid_toml() {
        let dir = std::env::temp_dir();
        let path = dir.join("_test_invalid_proxy.toml");
        std::fs::write(&path, "this is not valid toml [[[").ok();
        let result = ProxyConfig::from_file(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_auto_map_doh_known() {
        let doh = auto_map_doh("1.1.1.1");
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");
        let doh = auto_map_doh("8.8.8.8");
        assert_eq!(doh.hostname, "dns.google");
        let doh = auto_map_doh("9.9.9.9");
        assert_eq!(doh.hostname, "dns.quad9.net");
        let doh = auto_map_doh("94.140.14.14");
        assert_eq!(doh.hostname, "dns.adguard-dns.com");
    }

    #[test]
    fn test_auto_map_doh_unknown_fallback() {
        let doh = auto_map_doh("192.168.1.1");
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");
    }

    #[test]
    fn test_auto_map_doh_mullvad() {
        let doh = auto_map_doh("194.242.2.2");
        assert_eq!(doh.hostname, "dns.mullvad.net");
        assert!(doh.ips.contains(&Ipv4Addr::new(194, 242, 2, 2)));
    }

    #[test]
    fn test_resolve_provider_known() {
        let doh = resolve_provider("cloudflare").unwrap();
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");

        let doh = resolve_provider("google").unwrap();
        assert_eq!(doh.hostname, "dns.google");

        let doh = resolve_provider("quad9").unwrap();
        assert_eq!(doh.hostname, "dns.quad9.net");

        let doh = resolve_provider("adguard").unwrap();
        assert_eq!(doh.hostname, "dns.adguard-dns.com");

        let doh = resolve_provider("mullvad").unwrap();
        assert_eq!(doh.hostname, "dns.mullvad.net");
    }

    #[test]
    fn test_resolve_provider_case_insensitive() {
        let doh = resolve_provider("Mullvad").unwrap();
        assert_eq!(doh.hostname, "dns.mullvad.net");
        let doh = resolve_provider("CLOUDFLARE").unwrap();
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");
    }

    #[test]
    fn test_resolve_provider_unknown() {
        assert!(resolve_provider("nonexistent").is_none());
    }

    #[test]
    fn test_resolve_doh_config_provider() {
        // Provider mullvad → Mullvad DoH
        let cfg = ProxyConfig {
            dns: DnsConfig {
                provider: Some("mullvad".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "dns.mullvad.net");

        // Provider cloudflare → Cloudflare DoH
        let cfg2 = ProxyConfig {
            dns: DnsConfig {
                provider: Some("cloudflare".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let doh2 = cfg2.resolve_doh_config();
        assert_eq!(doh2.hostname, "1dot1dot1dot1.cloudflare-dns.com");
    }

    #[test]
    fn test_resolve_doh_config_provider_over_default() {
        // Provider field overrides default Cloudflare fallback
        let cfg = ProxyConfig {
            dns: DnsConfig {
                provider: Some("quad9".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "dns.quad9.net");
    }

    #[test]
    fn test_merge_provider() {
        // File sets provider, CLI doesn't → file wins
        let file_cfg = ProxyConfig {
            dns: DnsConfig {
                provider: Some("google".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged = ProxyConfig::default().merge(file_cfg);
        assert_eq!(merged.dns.provider.as_deref(), Some("google"));

        // CLI sets provider → CLI wins
        let cli_cfg = ProxyConfig {
            dns: DnsConfig {
                provider: Some("mullvad".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let file_cfg2 = ProxyConfig {
            dns: DnsConfig {
                provider: Some("google".to_string()),
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged2 = cli_cfg.merge(file_cfg2);
        assert_eq!(merged2.dns.provider.as_deref(), Some("mullvad"));
    }

    #[test]
    fn test_backward_compatibility_no_config() {
        // Running with no config file should use all defaults and work correctly
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.socks5.port, 1080);
        assert_eq!(cfg.socks5.bind, "127.0.0.1");
        assert_eq!(cfg.general.log_level, "info");
        assert_eq!(cfg.tunnel.mtu, 1500);
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");
    }

    #[test]
    fn test_full_precedence_chain() {
        // Defaults
        assert_eq!(Socks5Config::default().port, 1080);

        // File overrides defaults (simulated via merge with default CLI)
        let file_cfg = ProxyConfig {
            socks5: Socks5Config {
                port: 2080,
                ..Socks5Config::default()
            },
            ..ProxyConfig::default()
        };
        let cli_default = ProxyConfig::default();
        let merged = cli_default.merge(file_cfg);
        assert_eq!(merged.socks5.port, 2080, "file value should override default");

        // CLI overrides file (new file_cfg since previous was consumed)
        let file_cfg2 = ProxyConfig {
            socks5: Socks5Config {
                port: 2080,
                ..Socks5Config::default()
            },
            ..ProxyConfig::default()
        };
        let cli_with_override = ProxyConfig {
            socks5: Socks5Config {
                port: 3080,
                ..Socks5Config::default()
            },
            ..ProxyConfig::default()
        };
        let merged2 = cli_with_override.merge(file_cfg2);
        assert_eq!(merged2.socks5.port, 3080, "CLI value should override file value");
    }

    #[test]
    fn test_mtu_default_and_override() {
        // Default MTU is 1500
        assert_eq!(TunnelConfig::default().mtu, 1500);

        // File config can override it
        let file_cfg = ProxyConfig {
            tunnel: TunnelConfig {
                mtu: 1400,
                ..TunnelConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged = ProxyConfig::default().merge(file_cfg);
        assert_eq!(merged.tunnel.mtu, 1400);

        // CLI can override file (new file_cfg since previous was consumed)
        let file_cfg2 = ProxyConfig {
            tunnel: TunnelConfig {
                mtu: 1400,
                ..TunnelConfig::default()
            },
            ..ProxyConfig::default()
        };
        let cli_cfg = ProxyConfig {
            tunnel: TunnelConfig {
                mtu: 1200,
                ..TunnelConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged2 = cli_cfg.merge(file_cfg2);
        assert_eq!(merged2.tunnel.mtu, 1200);
    }

    #[test]
    fn test_dns_servers_default_and_override() {
        // Default: empty servers → Cloudflare
        let cfg = ProxyConfig::default();
        let doh = cfg.resolve_doh_config();
        assert_eq!(doh.hostname, "1dot1dot1dot1.cloudflare-dns.com");

        // File with servers → auto-mapped
        let file_cfg = ProxyConfig {
            dns: DnsConfig {
                servers: vec!["8.8.8.8".to_string()],
                ..DnsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let merged = ProxyConfig::default().merge(file_cfg);
        assert_eq!(merged.resolve_doh_config().hostname, "dns.google");
    }

    #[test]
    fn test_config_file_roundtrip() {
        // Write a temp config, read it back, verify values
        let dir = std::env::temp_dir();
        let path = dir.join("_test_proxy_roundtrip.toml");
        let content = r#"
[general]
log_level = "debug"

[socks5]
port = 9999
bind = "0.0.0.0"

[tunnel]
mtu = 1300
"#;
        std::fs::write(&path, content).unwrap();
        let cfg = ProxyConfig::from_file(&path).unwrap();
        assert_eq!(cfg.general.log_level, "debug");
        assert_eq!(cfg.socks5.port, 9999);
        assert_eq!(cfg.socks5.bind, "0.0.0.0");
        assert_eq!(cfg.tunnel.mtu, 1300);
        // defaults for unspecified
        assert_eq!(cfg.socks5.timeout_secs, 30);
        assert_eq!(cfg.cache.dns_ttl_secs, 300);
        let _ = std::fs::remove_file(&path);
    }
}
