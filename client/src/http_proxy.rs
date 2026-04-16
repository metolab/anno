//! Minimal local HTTP proxy (HTTP CONNECT + absolute-form HTTP/1.x GET).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn run_http_proxy(
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", listen_port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("local HTTP proxy listening on {}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_conn(stream).await {
                tracing::warn!("proxy session {} error: {}", peer, e);
            }
        });
    }
}

async fn handle_proxy_conn(
    mut client: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut filled = 0usize;
    loop {
        let n = client.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(());
        }
        filled += n;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(&buf[..filled])?;
        if status.is_partial() {
            if filled >= buf.len() {
                client
                    .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Ok(());
            }
            continue;
        }
        return dispatch(client, &buf[..filled], req).await;
    }
}

async fn dispatch(
    mut client: TcpStream,
    buf: &[u8],
    req: httparse::Request<'_, '_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let method = req.method.ok_or("no method")?;
    if method.eq_ignore_ascii_case("CONNECT") {
        let target = req.path.ok_or("no path")?;
        let mut parts = target.split(':');
        let host = parts.next().ok_or("bad connect target")?;
        let port: u16 = parts.next().unwrap_or("443").parse().unwrap_or(443);
        let mut remote = TcpStream::connect(format!("{}:{}", host, port)).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        return Ok(());
    }

    let path = req.path.ok_or("no path")?;
    if !path.starts_with("http://") {
        client
            .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let without = &path["http://".len()..];
    let slash = without.find('/').unwrap_or(without.len());
    let hostport = &without[..slash];
    let rest = if slash < without.len() {
        &without[slash..]
    } else {
        "/"
    };
    let (host, port) = parse_host_port(hostport, 80)?;
    let mut remote = TcpStream::connect(format!("{}:{}", host, port)).await?;

    let first_line_end = buf.windows(2).position(|w| w == b"\r\n").ok_or("no crlf")?;
    let mut new_first = Vec::new();
    new_first.extend_from_slice(method.as_bytes());
    new_first.push(b' ');
    new_first.extend_from_slice(rest.as_bytes());
    new_first.extend_from_slice(b" HTTP/1.1\r\n");
    remote.write_all(&new_first).await?;
    let body_start = first_line_end + 2;
    remote.write_all(&buf[body_start..]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

fn parse_host_port(
    s: &str,
    default_port: u16,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    if let Some((h, p)) = s.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return Ok((h.to_string(), p.parse()?));
        }
    }
    Ok((s.to_string(), default_port))
}
