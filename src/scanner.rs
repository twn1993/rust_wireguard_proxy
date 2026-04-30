use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use tracing::warn;

use crate::config;
use crate::tunnel::TunnelManager;
use crate::util;
use crate::util::s;


pub struct ConfigEntry {
    pub path: PathBuf,
    pub name: String,
}

/// Scan a directory for .conf files.
pub fn scan_configs<P: AsRef<Path>>(dir: P) -> Result<Vec<ConfigEntry>> {
    let dir = dir.as_ref();
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow!("cannot read dir '{}': {}", dir.display(), e))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("conf") {
            let name = path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            entries.push(ConfigEntry { path, name });
        }
    }
    if entries.is_empty() {
        return Err(anyhow!("no .conf files found in '{}'", dir.display()));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Test result for display.
pub struct TestResult {
    pub name: String,
    pub ok: bool,
    pub error: String,
}

/// Test all configs in parallel and return the selected tunnel manager.
/// Working tunnels are kept alive; unselected ones are dropped (clean shutdown).
pub async fn test_and_select(
    entries: &[ConfigEntry],
    connect_timeout: Duration,
    http_test_timeout: Duration,
) -> TunnelManager {
    println!("\nTesting {} config(s) with {}s timeout...", entries.len(), connect_timeout.as_secs());

    let mut handles = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let path = entry.path.clone();
        let name = entry.name.clone();
        handles.push(tokio::spawn(async move {
            match try_connect(&path, connect_timeout, http_test_timeout).await {
                Ok(mgr) => (i, name, true, String::new(), Some(mgr)),
                Err(e) => (i, name, false, e.to_string(), None),
            }
        }));
    }

    let mut results: Vec<TestResult> = Vec::new();
    let mut tunnels: HashMap<usize, TunnelManager> = HashMap::new();

    for handle in handles {
        match handle.await {
            Ok((i, name, _ok, _err, Some(mgr))) => {
                tunnels.insert(i, mgr);
                results.push(TestResult { name, ok: true, error: String::new() });
            }
            Ok((_i, name, ok, err, None)) => {
                results.push(TestResult { name, ok, error: err });
            }
            Err(e) => warn!("test task failed: {}", e),
        }
    }

    // Print results
    for r in &results {
        if r.ok {
            println!("  [OK] {}", r.name);
        } else {
            println!("  [{}] {}: {}", s(util::FAILED), r.name, r.error);
        }
    }

    // Interactive selection
    let selected_idx = select_index(&results);
    let selected = tunnels.remove(&selected_idx).expect("selected tunnel not found");

    // Drop remaining tunnels (clean shutdown via Drop → ManagedTunnel::shutdown)
    for (_, mgr) in tunnels {
        mgr.shutdown().await;
    }

    selected
}

/// Try connecting: parse config and establish tunnel + handshake.
/// Returns TunnelManager on success.
async fn try_connect(path: &Path, connect_timeout: Duration, http_test_timeout: Duration) -> Result<TunnelManager> {
    let proxy_cfg = config::WgProxyConfig::from_file(path)
        .map_err(|e| anyhow!("parse failed: {}", e))?;
    let dns_config = proxy_cfg.to_doh_server_config();
    let wg_cfg = proxy_cfg.to_wireguard_config()
        .map_err(|e| anyhow!("convert failed: {}", e))?;

    let mgr = match timeout(connect_timeout, TunnelManager::connect_with_dns(wg_cfg, dns_config)).await {
        Ok(Ok(mgr)) => mgr,
        Ok(Err(e)) => return Err(anyhow!("{}: {}", s(util::FAILED), e)),
        Err(_) => return Err(anyhow!("timeout ({}s)", connect_timeout.as_secs())),
    };

    // Verify data plane: send a real HTTP GET through the tunnel and check for HTML response.
    // This proves the WireGuard server has IP forwarding + NAT properly configured.
    let netstack = mgr.netstack();
    let test_ok = test_http_through_tunnel(netstack, connect_timeout, http_test_timeout).await;

    if !test_ok {
        mgr.shutdown().await;
        return Err(anyhow!("HTTP test failed"));
    }

    Ok(mgr)
}

/// Full HTTP test: connect through tunnel, send GET, verify HTML response.
async fn test_http_through_tunnel(
    netstack: std::sync::Arc<wireguard_netstack::NetStack>,
    connect_timeout: Duration,
    http_test_timeout: Duration,
) -> bool {
    // Resolve hostname using system DNS (gets an IP independent of the tunnel)
    let addr = match tokio::net::lookup_host("example.com:80").await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                warn!("HTTP test: DNS resolution returned no addresses");
                return false;
            }
        },
        Err(e) => {
            warn!("HTTP test: DNS resolution failed: {}", e);
            return false;
        }
    };

    // Step 1: TCP connect through tunnel
    let conn = match timeout(connect_timeout, wireguard_netstack::TcpConnection::connect(netstack, addr)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            warn!("HTTP test: TCP connect through tunnel failed: {}", e);
            return false;
        }
        Err(_) => {
            warn!("HTTP test: TCP connect through tunnel timed out");
            return false;
        }
    };

    // Step 2: Send HTTP GET request
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    if conn.write_all(request).await.is_err() {
        warn!("HTTP test: write request failed");
        return false;
    }

    // Step 3: Read response
    let mut buf = [0u8; 4096];
    let n = match timeout(http_test_timeout, conn.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("HTTP test: read response failed: {}", e);
            return false;
        }
        Err(_) => {
            warn!("HTTP test: read response timed out");
            return false;
        }
    };

    if n == 0 {
        warn!("HTTP test: connection closed without response");
        return false;
    }

    // Step 4: Check for valid HTML response
    let response = String::from_utf8_lossy(&buf[..n]);
    let has_html = response.contains("DOCTYPE html")
        || response.contains("<!DOCTYPE HTML")
        || response.contains("<html")
        || response.contains("HTTP/1.1 200")
        || response.contains("HTTP/1.0 200");

    if has_html {
        println!("  HTTP test passed: received valid HTTP response ({} bytes)", n);
    } else {
        warn!("HTTP test: response did not contain HTML: {:?}", &response[..response.len().min(200)]);
    }

    has_html
}

/// Interactive selection. Returns the index into the original entries slice.
fn select_index(results: &[TestResult]) -> usize {
    let working: Vec<&TestResult> = results.iter().filter(|r| r.ok).collect();
    let indices: Vec<usize> = results.iter().enumerate().filter(|(_, r)| r.ok).map(|(i, _)| i).collect();

    if working.is_empty() {
        eprintln!("\nNo working configs found. Check server or network.");
        std::process::exit(1);
    }

    if working.len() == 1 {
        println!("\nOnly one working config: {}", working[0].name);
        return indices[0];
    }

    println!("\n=== Available configs ===");
    for (j, r) in working.iter().enumerate() {
        println!("  {}. {}", j + 1, r.name);
    }
    println!("  q. quit");

    loop {
        print!("\nSelect config (1-{}): ", working.len());
        io::stdout().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        let input = input.trim();
        if input == "q" || input == "quit" {
            std::process::exit(0);
        }
        if let Ok(n) = input.parse::<usize>() {
            if n >= 1 && n <= working.len() {
                return indices[n - 1];
            }
        }
    }
}
