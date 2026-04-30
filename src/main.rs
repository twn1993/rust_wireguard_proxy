use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

mod config;
mod dns;
mod proxy_config;
mod scanner;
mod socks5_handler;
mod tunnel;
mod udp_relay;
mod util;

use util::s;

#[derive(Parser, Debug)]
#[command(name = "ncservice")]
#[command(about = "Network Communication Service")]
#[command(version)]
#[command(after_help = "\
EXAMPLES:
  ncservice -c wg.conf -p 1080
  ncservice --config-dir ./confs/ -p 1080
  ncservice --config wg.conf --socks5-port 2080 --verbose
  ncservice -f proxy.toml -c wg.conf
")]
pub struct CliArgs {
    #[arg(short = 'c', long = "config", required = false)]
    pub config: Option<String>,

    #[arg(short = 'd', long = "config-dir", required = false)]
    pub config_dir: Option<String>,

    #[arg(short = 'f', long = "config-file", required = false)]
    pub config_file: Option<String>,

    #[arg(short = 'p', long = "socks5-port", default_value = "1080")]
    pub socks5_port: u16,
    #[arg(short = 'b', long = "bind-addr", default_value = "127.0.0.1")]
    pub bind_addr: String,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::SetTrue)]
    pub verbose: bool,
}

fn main() {
    let args = CliArgs::parse();
    let rt = tokio::runtime::Runtime::new().expect("runtime init failed");
    if let Err(e) = rt.block_on(run(args)) {
        eprintln!("Fatal: {}", e);
        std::process::exit(1);
    }
}

async fn run(args: CliArgs) -> Result<()> {
    // ── Stage 1: Load proxy config (tracing not yet initialized) ──────────
    let proxy_config = if let Some(ref path) = args.config_file {
        match proxy_config::ProxyConfig::from_file(path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("warning: config file '{}' error: {}", path, e);
                proxy_config::ProxyConfig::default()
            }
        }
    } else {
        let default_path = "wg-proxy.toml";
        if Path::new(default_path).exists() {
            proxy_config::ProxyConfig::from_file(default_path)?
        } else {
            eprintln!("no config file found, generating default: {}", default_path);
            let default_content = proxy_config::ProxyConfig::generate_default_toml();
            std::fs::write(default_path, default_content)
                .map_err(|e| anyhow!("failed to create default config: {}", e))?;
            eprintln!("default config generated: {}", default_path);
            proxy_config::ProxyConfig::default()
        }
    };

    // ── Stage 2: Build CLI config and merge (CLI > file > defaults) ───────
    let cli_config = proxy_config::ProxyConfig {
        socks5: proxy_config::Socks5Config {
            port: args.socks5_port,
            bind: args.bind_addr.clone(),
            ..proxy_config::Socks5Config::default()
        },
        ..proxy_config::ProxyConfig::default()
    };
    let config = cli_config.merge(proxy_config);

    // ── Stage 3: Initialize tracing with merged config ───────────────────
    let log_level = if args.verbose {
        "debug"
    } else {
        &config.general.log_level
    };
    let filter = match log_level {
        "trace" => "ncservice=trace",
        "debug" => "ncservice=debug",
        "warn" => "ncservice=warn",
        "error" => "ncservice=error",
        _ => "ncservice=info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // ── Stage 4: Load WireGuard config and establish tunnel ──────────────
    let (tunnel, netstack, dns_resolver) = if let Some(dir) = &args.config_dir {
        let entries = scanner::scan_configs(dir)?;
        let tunnel = scanner::test_and_select(
            &entries,
            Duration::from_secs(config.tunnel.connect_timeout_secs),
            Duration::from_secs(config.tunnel.http_test_timeout_secs),
        )
        .await;
        let ns = tunnel.netstack();
        let dr = tunnel.dns_resolver();
        println!("Selected: {}\n", "tunnel");
        (tunnel, ns, dr)
    } else if let Some(wg_config_file) = &args.config {
        info!("{} {}", s(util::LOADING), wg_config_file);
        let wg_proxy_config = config::WgProxyConfig::from_file(wg_config_file)?;
        let dns_config = config.resolve_doh_config();
        let wg_cfg = wg_proxy_config.to_wireguard_config_with_mtu(Some(config.tunnel.mtu))?;
        info!("{} {}...", s(util::ESTABLISHED), s(util::TUNNEL));
        let tunnel = tunnel::TunnelManager::connect_with_dns(wg_cfg, dns_config).await?;
        let ns = tunnel.netstack();
        let dr = tunnel.dns_resolver();
        info!("{} {}", s(util::TUNNEL), s(util::ESTABLISHED));
        (tunnel, ns, dr)
    } else {
        return Err(anyhow!("use --config <FILE> or --config-dir <DIR>"));
    };

    let udp_relay = Arc::new(udp_relay::UdpRelay::new(netstack.clone(), dns_resolver.clone()));

    let bind_addr = format!("{}:{}", config.socks5.bind, config.socks5.port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow!("bind {}: {}", bind_addr, e))?;
    info!("{} {}", s(util::LISTENING_ON), bind_addr);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("signal init failed");
        info!("{}", s(util::SHUTDOWN_SIGNAL));
        let _ = shutdown_tx.send(()).await;
    });

    let socks5_timeout = Duration::from_secs(config.socks5.timeout_secs);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("accept: {}", e);
                        continue;
                    }
                };
                info!("{} {}", s(util::NEW_CONNECTION), peer_addr);
                let netstack = netstack.clone();
                let udp_relay = udp_relay.clone();
                let dns_resolver = dns_resolver.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_connection(stream, netstack, udp_relay, dns_resolver, socks5_timeout).await {
                        warn!("{}: {}", peer_addr, e);
                    }
                });
            }
            _ = shutdown_rx.recv() => {
                info!("{}", s(util::STOPPING));
                break;
            }
        }
    }

    info!("{} {}...", s(util::SHUTTING_DOWN), s(util::TUNNEL));
    tunnel.shutdown().await;
    info!("{}", s(util::GOODBYE));
    Ok(())
}

async fn handle_socks5_connection(
    mut stream: tokio::net::TcpStream,
    netstack: Arc<wireguard_netstack::NetStack>,
    udp_relay: Arc<udp_relay::UdpRelay>,
    dns_resolver: Arc<wireguard_netstack::DohResolver>,
    socks5_timeout: Duration,
) -> Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(anyhow!("bad version: {}", header[0]));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        stream.read_exact(&mut methods).await?;
    }
    stream.write_all(&[5u8, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(anyhow!("bad req version: {}", req[0]));
    }
    let cmd = req[1];
    let atyp = req[3];

    let (addr_str, port) = read_socks5_addr(&mut stream, atyp).await?;

    match cmd {
        0x01 => {
            // Try to parse as IP first; otherwise resolve the domain through the tunnel via DoH
            let addr = if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                SocketAddr::new(IpAddr::V4(ip), port)
            } else if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                SocketAddr::new(IpAddr::V6(ip), port)
            } else {
                dns_resolver
                    .resolve_addr(&addr_str, port)
                    .await
                    .map_err(|e| anyhow!("DNS resolve through tunnel failed: {}", e))?
            };
            socks5_handler::handle_tcp_connect(stream, addr, netstack.clone(), socks5_timeout).await?;
            Ok(())
        }
        0x03 => {
            let relay_addr = udp_relay.handle_associate().await?;
            let reply = build_socks5_reply(0x00, &relay_addr.ip().to_string(), relay_addr.port());
            stream.write_all(&reply).await?;
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
            info!("{}", s(util::RELAY));
            Ok(())
        }
        _ => {
            let reply = build_socks5_reply(0x07, "0.0.0.0", 0);
            stream.write_all(&reply).await?;
            Err(anyhow!("unsupported cmd: 0x{:02x}", cmd))
        }
    }
}

async fn read_socks5_addr(
    stream: &mut tokio::net::TcpStream,
    atyp: u8,
) -> Result<(String, u16)> {
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            Ok((ip.to_string(), u16::from_be_bytes(port)))
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let name_len = len_byte[0] as usize;
            let mut name = vec![0u8; name_len];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let hostname = String::from_utf8_lossy(&name).to_string();
            Ok((hostname, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv6Addr::from(addr);
            Ok((ip.to_string(), u16::from_be_bytes(port)))
        }
        _ => Err(anyhow!("bad atyp: 0x{:02x}", atyp)),
    }
}

fn build_socks5_reply(reply_code: u8, bind_addr: &str, bind_port: u16) -> Vec<u8> {
    let mut reply = vec![5u8, reply_code, 0u8, 1u8];
    if let Ok(ip) = bind_addr.parse::<std::net::Ipv4Addr>() {
        reply.extend_from_slice(&ip.octets());
    } else {
        reply.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]);
    }
    reply.extend_from_slice(&bind_port.to_be_bytes());
    reply
}
