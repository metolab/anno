//! Minimal local HTTP proxy (HTTP CONNECT + absolute-form HTTP/1.x GET).

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Initial read buffer size (most request heads fit comfortably here).
const HTTP_INITIAL_CAPACITY: usize = 16 * 1024;
/// How much to grow the buffer each time the request head is still partial.
const HTTP_GROW_CHUNK: usize = 8 * 1024;
/// Absolute cap on the size of a request head we're willing to parse.
///
/// Headers larger than this are very likely abusive; reject with 413 so
/// a malformed client cannot force unbounded buffering on the proxy.
const HTTP_HEADER_MAX: usize = 128 * 1024;

/// Bind the local HTTP proxy listener up-front so the caller observes the
/// real port before registering with the server. Returning `(listener,
/// actual_port)` lets us support `--http-proxy 0` (ephemeral port) while
/// still advertising the correct port in the `Register` frame.
pub async fn bind_http_proxy(listen_port: u16) -> std::io::Result<(TcpListener, u16)> {
    let addr = format!("127.0.0.1:{}", listen_port);
    let listener = TcpListener::bind(&addr).await?;
    let actual = listener.local_addr()?.port();
    Ok((listener, actual))
}

/// Run the accept loop on an already-bound listener.
pub async fn serve_http_proxy(
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        "local HTTP proxy listening on {}",
        listener.local_addr()?
    );
    // Exponential backoff on accept errors so a transient file-descriptor
    // exhaustion does not spin the CPU.
    let mut backoff_ms: u64 = 1;
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                backoff_ms = 1;
                tokio::spawn(async move {
                    if let Err(e) = handle_proxy_conn(stream).await {
                        tracing::warn!("proxy session {} error: {}", peer, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("http proxy accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(1000);
            }
        }
    }
}

async fn handle_proxy_conn(
    mut client: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Start with a reasonable buffer and grow on demand up to HTTP_HEADER_MAX.
    // Using BytesMut avoids the fixed 16 KB ceiling that previously rejected
    // otherwise legitimate requests whose headers exceeded that limit.
    let mut buf = BytesMut::with_capacity(HTTP_INITIAL_CAPACITY);
    buf.resize(HTTP_INITIAL_CAPACITY, 0);
    let mut filled = 0usize;
    loop {
        if filled == buf.len() {
            if buf.len() >= HTTP_HEADER_MAX {
                client
                    .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Ok(());
            }
            let new_len = (buf.len() + HTTP_GROW_CHUNK).min(HTTP_HEADER_MAX);
            buf.resize(new_len, 0);
        }
        let n = client.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(());
        }
        filled += n;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(&buf[..filled])?;
        if status.is_partial() {
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

    // Locate the end of the request head (`\r\n\r\n`). Anything after it
    // is the request body / pipelined content — we pass it through as-is.
    let headers_end = find_headers_end(buf).ok_or("no end-of-headers")?;
    let first_line_end = buf.windows(2).position(|w| w == b"\r\n").ok_or("no crlf")?;

    let mut out = Vec::with_capacity(headers_end);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(rest.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // Compute the set of hop-by-hop headers (RFC 7230 §6.1) that must not be
    // forwarded. This includes the fixed set plus any header names listed
    // inside an incoming `Connection:` field. Without this, proxy-specific
    // headers (notably `Proxy-Connection`, `Proxy-Authorization`) bleed
    // through to the origin server and can cause misbehaviour.
    let mut hop_by_hop: Vec<String> = HOP_BY_HOP
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("connection") {
            if let Ok(v) = std::str::from_utf8(h.value) {
                for tok in v.split(',') {
                    let t = tok.trim().to_ascii_lowercase();
                    if !t.is_empty() {
                        hop_by_hop.push(t);
                    }
                }
            }
        }
    }

    for h in req.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        let lower = h.name.to_ascii_lowercase();
        if hop_by_hop.iter().any(|s| s == &lower) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    remote.write_all(&out).await?;

    // Forward any bytes belonging to the request body that arrived together
    // with the headers. `body_start` is the offset past the final `\r\n\r\n`.
    let body_start = headers_end;
    if body_start < buf.len() {
        remote.write_all(&buf[body_start..]).await?;
    }
    // Prevent the unused-variable warning (`first_line_end` used to be the
    // cut point for buf pass-through; we now rebuild the head from the
    // parsed request).
    let _ = first_line_end;

    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

/// RFC 7230 §6.1: connection-control headers that are strictly hop-by-hop
/// and MUST NOT be forwarded by proxies.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Find the byte offset just past the end-of-headers delimiter (`\r\n\r\n`).
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
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
