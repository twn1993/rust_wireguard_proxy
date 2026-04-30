use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, error, warn};
use wireguard_netstack::{NetStack, TcpConnection};

use crate::util;
use crate::util::s;

pub async fn handle_tcp_connect(
    mut client_stream: TcpStream,
    target_addr: SocketAddr,
    netstack: Arc<NetStack>,
    timeout_duration: Duration,
) -> Result<()> {
    info!("{} {}", s(util::CONNECTION), target_addr);

    let tunnel_conn = match timeout(timeout_duration, TcpConnection::connect(netstack, target_addr)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            error!("{} {}: {}", s(util::FAILED), target_addr, e);
            send_reply(&mut client_stream, 0x04).await.ok();
            return Err(anyhow!("connect failed: {}", e));
        }
        Err(_) => {
            warn!("timeout ({}s)", timeout_duration.as_secs());
            send_reply(&mut client_stream, 0x04).await.ok();
            return Err(anyhow!("timeout"));
        }
    };

    send_reply(&mut client_stream, 0x00).await?;
    info!("{} {}", s(util::CONNECTION), target_addr);

    let mut buf_c2t = vec![0u8; 65535];
    let mut buf_t2c = vec![0u8; 65535];
    let mut done = false;

    while !done {
        tokio::select! {
            r = client_stream.read(&mut buf_c2t) => {
                match r {
                    Ok(0) => { tunnel_conn.shutdown(); done = true; }
                    Ok(n) => {
                        if let Err(e) = tunnel_conn.write_all(&buf_c2t[..n]).await {
                            warn!("write: {}", e); done = true;
                        }
                    }
                    Err(e) => { warn!("read: {}", e); done = true; }
                }
            }
            r = tunnel_conn.read(&mut buf_t2c) => {
                match r {
                    Ok(0) => { let _ = client_stream.shutdown().await; done = true; }
                    Ok(n) => {
                        if let Err(e) = client_stream.write_all(&buf_t2c[..n]).await {
                            warn!("write: {}", e); done = true;
                        }
                    }
                    Err(e) => { warn!("read: {}", e); done = true; }
                }
            }
        }
    }

    Ok(())
}

async fn send_reply(stream: &mut TcpStream, reply_code: u8) -> Result<()> {
    let reply = [5u8, reply_code, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
    stream.write_all(&reply).await?;
    Ok(())
}
