//! Connect to local/remote targets for forwarded sessions.

use anno_common::{Host, TargetAddress};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

/// Cap on how many resolved addresses we try per DNS lookup before
/// giving up. Real-world A/AAAA fans-outs are tiny (≤ 8); the cap
/// just prevents a pathological resolver answer from spinning forever.
const DNS_FALLBACK_MAX_ATTEMPTS: usize = 8;

/// Resolve `host:port` and return up to [`DNS_FALLBACK_MAX_ATTEMPTS`]
/// addresses. Returns `NotFound` if the resolver yields nothing.
async fn resolve_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let it = tokio::net::lookup_host((host, port)).await?;
    let addrs: Vec<SocketAddr> = it.take(DNS_FALLBACK_MAX_ATTEMPTS).collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "dns empty"));
    }
    Ok(addrs)
}

pub async fn tcp_connect(target: &TargetAddress) -> io::Result<TcpStream> {
    match &target.host {
        Host::V4(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), target.port)).await,
        Host::V6(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), target.port)).await,
        Host::Domain(name) => {
            // Try every resolved address in order before giving up so
            // a host that returns both IPv6 and IPv4 still works
            // when one family is unreachable (the previous code
            // failed permanently if the *first* address was bad).
            let addrs = resolve_addrs(name, target.port).await?;
            let mut last_err = io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses tried for {name}"),
            );
            for addr in addrs {
                match TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        tracing::debug!(target = %name, %addr, "tcp connect failed: {e}");
                        last_err = e;
                    }
                }
            }
            Err(last_err)
        }
    }
}

pub async fn udp_connect(target: &TargetAddress) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    match &target.host {
        Host::V4(ip) => {
            sock.connect(SocketAddr::new((*ip).into(), target.port))
                .await?;
        }
        Host::V6(ip) => {
            sock.connect(SocketAddr::new((*ip).into(), target.port))
                .await?;
        }
        Host::Domain(name) => {
            let addrs = resolve_addrs(name, target.port).await?;
            let mut last_err = io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses tried for {name}"),
            );
            let mut connected = false;
            for addr in addrs {
                match sock.connect(addr).await {
                    Ok(()) => {
                        connected = true;
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(target = %name, %addr, "udp connect failed: {e}");
                        last_err = e;
                    }
                }
            }
            if !connected {
                return Err(last_err);
            }
        }
    }
    Ok(sock)
}
