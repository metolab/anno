//! Connect to local/remote targets for forwarded sessions.

use anno_common::{Host, TargetAddress};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

pub async fn tcp_connect(target: &TargetAddress) -> io::Result<TcpStream> {
    match &target.host {
        Host::V4(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), target.port)).await,
        Host::V6(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), target.port)).await,
        Host::Domain(name) => {
            let mut it = tokio::net::lookup_host((name.as_str(), target.port)).await?;
            let addr = it
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dns empty"))?;
            TcpStream::connect(addr).await
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
            let mut it = tokio::net::lookup_host((name.as_str(), target.port)).await?;
            let addr = it
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dns empty"))?;
            sock.connect(addr).await?;
        }
    }
    Ok(sock)
}
