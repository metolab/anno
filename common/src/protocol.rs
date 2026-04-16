//! Fixed 16-byte header + payload frames (big-endian).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

pub const FRAME_HEADER_SIZE: usize = 16;
pub const MAGIC: u16 = 0x4E54;
pub const VERSION: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Ping = 0x00,
    Pong = 0x01,
    Register = 0x02,
    RegisterAck = 0x03,
    ConfigPush = 0x04,
    ConfigAck = 0x05,
    NewConn = 0x20,
    ConnReady = 0x21,
    ConnClose = 0x22,
    DataTcp = 0x40,
    DataUdp = 0x41,
    /// Server/client fault notification (`0xF0`).
    Fault = 0xF0,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Ping),
            0x01 => Ok(Self::Pong),
            0x02 => Ok(Self::Register),
            0x03 => Ok(Self::RegisterAck),
            0x04 => Ok(Self::ConfigPush),
            0x05 => Ok(Self::ConfigAck),
            0x20 => Ok(Self::NewConn),
            0x21 => Ok(Self::ConnReady),
            0x22 => Ok(Self::ConnClose),
            0x40 => Ok(Self::DataTcp),
            0x41 => Ok(Self::DataUdp),
            0xF0 => Ok(Self::Fault),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0x00,
    Udp = 0x01,
    Both = 0x02,
}

impl TryFrom<u8> for Protocol {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Tcp),
            0x01 => Ok(Self::Udp),
            0x02 => Ok(Self::Both),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    Ipv4 = 0x01,
    Ipv6 = 0x02,
    Domain = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddress {
    pub host: Host,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl TargetAddress {
    pub fn socket_addr(&self) -> std::io::Result<SocketAddr> {
        match &self.host {
            Host::V4(ip) => Ok(SocketAddr::new((*ip).into(), self.port)),
            Host::V6(ip) => Ok(SocketAddr::new((*ip).into(), self.port)),
            Host::Domain(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "domain must be resolved by async resolver",
            )),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        match &self.host {
            Host::V4(ip) => {
                buf.put_u8(AddressType::Ipv4 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(self.port);
            }
            Host::V6(ip) => {
                buf.put_u8(AddressType::Ipv6 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(self.port);
            }
            Host::Domain(s) => {
                let b = s.as_bytes();
                assert!(b.len() <= 255, "domain too long");
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(b.len() as u8);
                buf.put_slice(b);
                buf.put_u16(self.port);
            }
        }
    }

    pub fn decode(mut src: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::Truncated);
        }
        let kind = src[0];
        let mut consumed = 1usize;
        src = &src[1..];
        match kind {
            x if x == AddressType::Ipv4 as u8 => {
                if src.len() < 6 {
                    return Err(ProtocolError::Truncated);
                }
                let ip = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
                let port = u16::from_be_bytes([src[4], src[5]]);
                consumed += 6;
                Ok((
                    TargetAddress {
                        host: Host::V4(ip),
                        port,
                    },
                    consumed,
                ))
            }
            x if x == AddressType::Ipv6 as u8 => {
                if src.len() < 18 {
                    return Err(ProtocolError::Truncated);
                }
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&src[..16]);
                let ip = Ipv6Addr::from(oct);
                let port = u16::from_be_bytes([src[16], src[17]]);
                consumed += 18;
                Ok((
                    TargetAddress {
                        host: Host::V6(ip),
                        port,
                    },
                    consumed,
                ))
            }
            x if x == AddressType::Domain as u8 => {
                if src.is_empty() {
                    return Err(ProtocolError::Truncated);
                }
                let len = src[0] as usize;
                if src.len() < 1 + len + 2 {
                    return Err(ProtocolError::Truncated);
                }
                let name = std::str::from_utf8(&src[1..1 + len])
                    .map_err(|_| ProtocolError::InvalidUtf8)?
                    .to_string();
                let port = u16::from_be_bytes([src[1 + len], src[1 + len + 1]]);
                consumed += 1 + len + 2;
                Ok((
                    TargetAddress {
                        host: Host::Domain(name),
                        port,
                    },
                    consumed,
                ))
            }
            _ => Err(ProtocolError::BadAddressType(kind)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub msg_type: MessageType,
    pub flags: u8,
    pub conn_id: u64,
    pub payload: Bytes,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("truncated frame")]
    Truncated,
    #[error("bad magic {0:#x}")]
    BadMagic(u16),
    #[error("unsupported version {0}")]
    BadVersion(u8),
    #[error("unknown message type {0}")]
    BadMessageType(u8),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("invalid utf8")]
    InvalidUtf8,
    #[error("bad address type {0}")]
    BadAddressType(u8),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn encode_frame(f: &Frame) -> BytesMut {
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + f.payload.len());
    buf.put_u16(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(f.msg_type as u8);
    buf.put_u8(f.flags);
    buf.put_u8(0);
    buf.put_u16(f.payload.len() as u16);
    buf.put_u64(f.conn_id);
    buf.extend_from_slice(&f.payload);
    buf
}

/// Try to decode one frame from the front of `src`. On success, advances `src`.
pub fn decode_frame(src: &mut BytesMut) -> Result<Option<Frame>, ProtocolError> {
    if src.len() < FRAME_HEADER_SIZE {
        return Ok(None);
    }
    let magic = u16::from_be_bytes([src[0], src[1]]);
    if magic != MAGIC {
        return Err(ProtocolError::BadMagic(magic));
    }
    let version = src[2];
    if version != VERSION {
        return Err(ProtocolError::BadVersion(version));
    }
    let msg_type = src[3];
    let msg_type =
        MessageType::try_from(msg_type).map_err(|_| ProtocolError::BadMessageType(msg_type))?;
    let flags = src[4];
    let _reserved = src[5];
    let len = u16::from_be_bytes([src[6], src[7]]) as usize;
    let conn_id = u64::from_be_bytes([
        src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15],
    ]);
    if src.len() < FRAME_HEADER_SIZE + len {
        return Ok(None);
    }
    let mut chunk = src.split_to(FRAME_HEADER_SIZE + len);
    chunk.advance(FRAME_HEADER_SIZE);
    let payload = chunk.freeze();
    Ok(Some(Frame {
        msg_type,
        flags,
        conn_id,
        payload,
    }))
}

pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_frame(src).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&encode_frame(&item));
        Ok(())
    }
}

// --- Payload helpers ---

pub fn build_register(name: &str, key: Option<&str>, http_proxy_port: Option<u16>) -> Frame {
    let mut p = BytesMut::new();
    let b = name.as_bytes();
    p.put_u16(b.len() as u16);
    p.extend_from_slice(b);
    let hp = http_proxy_port.filter(|p| *p > 0).unwrap_or(0);
    p.put_u16(hp);
    let key_bytes = key.unwrap_or("").as_bytes();
    p.put_u16(key_bytes.len() as u16);
    p.extend_from_slice(key_bytes);
    Frame {
        msg_type: MessageType::Register,
        flags: 0,
        conn_id: 0,
        payload: p.freeze(),
    }
}

/// Returns client name, optional local HTTP proxy port, and optional key.
pub fn parse_register(
    payload: &[u8],
) -> Result<(String, Option<u16>, Option<String>), ProtocolError> {
    if payload.len() < 2 {
        return Err(ProtocolError::Truncated);
    }
    let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + n {
        return Err(ProtocolError::Truncated);
    }
    let name = std::str::from_utf8(&payload[2..2 + n])
        .map_err(|_| ProtocolError::InvalidUtf8)?
        .to_string();
    let mut offset = 2 + n;
    let mut http_proxy = None;
    if payload.len() >= offset + 2 {
        let hp = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;
        if hp != 0 {
            http_proxy = Some(hp);
        }
    }
    let mut key = None;
    if payload.len() >= offset + 2 {
        let key_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if payload.len() >= offset + key_len && key_len > 0 {
            let s = std::str::from_utf8(&payload[offset..offset + key_len])
                .map_err(|_| ProtocolError::InvalidUtf8)?
                .to_string();
            key = Some(s);
        }
    }
    Ok((name, http_proxy, key))
}

pub fn build_register_ack(client_id: u64) -> Frame {
    let mut p = BytesMut::with_capacity(8);
    p.put_u64(client_id);
    Frame {
        msg_type: MessageType::RegisterAck,
        flags: 0,
        conn_id: 0,
        payload: p.freeze(),
    }
}

pub fn parse_register_ack(payload: &[u8]) -> Result<u64, ProtocolError> {
    if payload.len() < 8 {
        return Err(ProtocolError::Truncated);
    }
    Ok(u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub server_port: u16,
    pub protocol: Protocol,
    pub target: TargetAddress,
}

pub fn build_config_push(mappings: &[PortMapping]) -> Frame {
    let mut p = BytesMut::new();
    p.put_u16(mappings.len() as u16);
    for m in mappings {
        p.put_u8(m.protocol as u8);
        p.put_u16(m.server_port);
        m.target.encode(&mut p);
    }
    Frame {
        msg_type: MessageType::ConfigPush,
        flags: 0,
        conn_id: 0,
        payload: p.freeze(),
    }
}

pub fn parse_config_push(payload: &[u8]) -> Result<Vec<PortMapping>, ProtocolError> {
    if payload.len() < 2 {
        return Err(ProtocolError::Truncated);
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut out = Vec::with_capacity(count);
    let mut i = 2usize;
    for _ in 0..count {
        if i >= payload.len() {
            return Err(ProtocolError::Truncated);
        }
        let proto = Protocol::try_from(payload[i])
            .map_err(|_| ProtocolError::BadMessageType(payload[i]))?;
        i += 1;
        if i + 2 > payload.len() {
            return Err(ProtocolError::Truncated);
        }
        let server_port = u16::from_be_bytes([payload[i], payload[i + 1]]);
        i += 2;
        let rest = &payload[i..];
        let (target, c) = TargetAddress::decode(rest)?;
        i += c;
        out.push(PortMapping {
            server_port,
            protocol: proto,
            target,
        });
    }
    Ok(out)
}

pub fn build_new_conn(
    conn_id: u64,
    server_port: u16,
    protocol: Protocol,
    target: &TargetAddress,
) -> Frame {
    let mut p = BytesMut::new();
    p.put_u16(server_port);
    p.put_u8(protocol as u8);
    target.encode(&mut p);
    Frame {
        msg_type: MessageType::NewConn,
        flags: 0,
        conn_id,
        payload: p.freeze(),
    }
}

pub fn parse_new_conn(payload: &[u8]) -> Result<(u16, Protocol, TargetAddress), ProtocolError> {
    if payload.len() < 2 + 1 {
        return Err(ProtocolError::Truncated);
    }
    let server_port = u16::from_be_bytes([payload[0], payload[1]]);
    let proto =
        Protocol::try_from(payload[2]).map_err(|_| ProtocolError::BadMessageType(payload[2]))?;
    let (target, _) = TargetAddress::decode(&payload[3..])?;
    Ok((server_port, proto, target))
}

pub fn build_conn_ready(conn_id: u64) -> Frame {
    Frame {
        msg_type: MessageType::ConnReady,
        flags: 0,
        conn_id,
        payload: Bytes::new(),
    }
}

pub fn build_conn_close(conn_id: u64) -> Frame {
    Frame {
        msg_type: MessageType::ConnClose,
        flags: 0,
        conn_id,
        payload: Bytes::new(),
    }
}

pub fn build_ping() -> Frame {
    Frame {
        msg_type: MessageType::Ping,
        flags: 0,
        conn_id: 0,
        payload: Bytes::new(),
    }
}

pub fn build_pong() -> Frame {
    Frame {
        msg_type: MessageType::Pong,
        flags: 0,
        conn_id: 0,
        payload: Bytes::new(),
    }
}

pub fn build_config_ack() -> Frame {
    Frame {
        msg_type: MessageType::ConfigAck,
        flags: 0,
        conn_id: 0,
        payload: Bytes::new(),
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ErrorCode {
    UnknownClient = 0x01,
    PortUnavailable = 0x02,
    ConnectionRefused = 0x03,
    Timeout = 0x04,
    ProtocolError = 0x05,
}

pub fn build_error(code: ErrorCode, msg: &str) -> Frame {
    let mut p = BytesMut::new();
    p.put_u16(code as u16);
    let b = msg.as_bytes();
    p.put_u16(b.len() as u16);
    p.extend_from_slice(b);
    Frame {
        msg_type: MessageType::Fault,
        flags: 0,
        conn_id: 0,
        payload: p.freeze(),
    }
}

pub fn build_data_tcp(conn_id: u64, data: Bytes) -> Frame {
    Frame {
        msg_type: MessageType::DataTcp,
        flags: 0,
        conn_id,
        payload: data,
    }
}

pub fn build_data_udp(conn_id: u64, data: Bytes) -> Frame {
    Frame {
        msg_type: MessageType::DataUdp,
        flags: 0,
        conn_id,
        payload: data,
    }
}

/// Parse error/fault message payload.
pub fn parse_error(payload: &[u8]) -> Result<(u16, String), ProtocolError> {
    if payload.len() < 4 {
        return Err(ProtocolError::Truncated);
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if payload.len() < 4 + msg_len {
        return Err(ProtocolError::Truncated);
    }
    let message = std::str::from_utf8(&payload[4..4 + msg_len])
        .map_err(|_| ProtocolError::InvalidUtf8)?
        .to_string();
    Ok((code, message))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let frame = Frame {
            msg_type: MessageType::Ping,
            flags: 0,
            conn_id: 42,
            payload: Bytes::new(),
        };
        let encoded = encode_frame(&frame);
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.msg_type, frame.msg_type);
        assert_eq!(decoded.conn_id, frame.conn_id);
        assert_eq!(decoded.flags, frame.flags);
    }

    #[test]
    fn test_frame_with_payload() {
        let payload = Bytes::from_static(b"hello world");
        let frame = Frame {
            msg_type: MessageType::DataTcp,
            flags: 1,
            conn_id: 12345,
            payload: payload.clone(),
        };
        let encoded = encode_frame(&frame);
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.conn_id, 12345);
        assert_eq!(decoded.flags, 1);
    }

    #[test]
    fn test_frame_codec_partial() {
        let frame = Frame {
            msg_type: MessageType::Pong,
            flags: 0,
            conn_id: 1,
            payload: Bytes::from_static(b"test"),
        };
        let encoded = encode_frame(&frame);

        // Partial header
        let mut partial = BytesMut::from(&encoded[..8]);
        assert!(decode_frame(&mut partial).unwrap().is_none());

        // Partial payload
        let mut partial = BytesMut::from(&encoded[..FRAME_HEADER_SIZE + 2]);
        assert!(decode_frame(&mut partial).unwrap().is_none());

        // Complete
        let mut complete = BytesMut::from(&encoded[..]);
        assert!(decode_frame(&mut complete).unwrap().is_some());
    }

    #[test]
    fn test_bad_magic() {
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ][..],
        );
        let result = decode_frame(&mut buf);
        assert!(matches!(result, Err(ProtocolError::BadMagic(_))));
    }

    #[test]
    fn test_bad_version() {
        let mut buf = BytesMut::from(
            &[
                0x4E, 0x54, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ][..],
        );
        let result = decode_frame(&mut buf);
        assert!(matches!(result, Err(ProtocolError::BadVersion(0x99))));
    }

    #[test]
    fn test_bad_message_type() {
        let mut buf = BytesMut::from(
            &[
                0x4E, 0x54, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ][..],
        );
        let result = decode_frame(&mut buf);
        assert!(matches!(result, Err(ProtocolError::BadMessageType(0xFF))));
    }

    #[test]
    fn test_target_address_ipv4() {
        let addr = TargetAddress {
            host: Host::V4(Ipv4Addr::new(192, 168, 1, 100)),
            port: 8080,
        };
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        let (decoded, consumed) = TargetAddress::decode(&buf).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 7); // 1 type + 4 ipv4 + 2 port
    }

    #[test]
    fn test_target_address_ipv6() {
        let addr = TargetAddress {
            host: Host::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: 443,
        };
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        let (decoded, consumed) = TargetAddress::decode(&buf).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 19); // 1 type + 16 ipv6 + 2 port
    }

    #[test]
    fn test_target_address_domain() {
        let addr = TargetAddress {
            host: Host::Domain("example.com".to_string()),
            port: 80,
        };
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        let (decoded, consumed) = TargetAddress::decode(&buf).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 1 + 1 + 11 + 2); // type + len + domain + port
    }

    #[test]
    fn test_target_address_socket_addr() {
        let addr = TargetAddress {
            host: Host::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 3000,
        };
        let sock = addr.socket_addr().unwrap();
        assert_eq!(sock.port(), 3000);

        let domain_addr = TargetAddress {
            host: Host::Domain("localhost".to_string()),
            port: 80,
        };
        assert!(domain_addr.socket_addr().is_err());
    }

    #[test]
    fn test_register_roundtrip() {
        let frame = build_register("test-client", Some("mykey"), Some(8080));
        let (name, proxy, key) = parse_register(&frame.payload).unwrap();
        assert_eq!(name, "test-client");
        assert_eq!(proxy, Some(8080));
        assert_eq!(key, Some("mykey".to_string()));
    }

    #[test]
    fn test_register_no_proxy() {
        let frame = build_register("client", None, None);
        let (name, proxy, key) = parse_register(&frame.payload).unwrap();
        assert_eq!(name, "client");
        assert_eq!(proxy, None);
        assert_eq!(key, None);
    }

    #[test]
    fn test_register_ack_roundtrip() {
        let frame = build_register_ack(12345678);
        let client_id = parse_register_ack(&frame.payload).unwrap();
        assert_eq!(client_id, 12345678);
    }

    #[test]
    fn test_config_push_roundtrip() {
        let mappings = vec![
            PortMapping {
                server_port: 8080,
                protocol: Protocol::Tcp,
                target: TargetAddress {
                    host: Host::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 80,
                },
            },
            PortMapping {
                server_port: 5353,
                protocol: Protocol::Udp,
                target: TargetAddress {
                    host: Host::Domain("dns.local".to_string()),
                    port: 53,
                },
            },
        ];
        let frame = build_config_push(&mappings);
        let decoded = parse_config_push(&frame.payload).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].server_port, 8080);
        assert_eq!(decoded[0].protocol, Protocol::Tcp);
        assert_eq!(decoded[1].server_port, 5353);
        assert_eq!(decoded[1].protocol, Protocol::Udp);
    }

    #[test]
    fn test_config_push_empty() {
        let frame = build_config_push(&[]);
        let decoded = parse_config_push(&frame.payload).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_new_conn_roundtrip() {
        let target = TargetAddress {
            host: Host::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 22,
        };
        let frame = build_new_conn(999, 2222, Protocol::Tcp, &target);
        let (port, proto, decoded_target) = parse_new_conn(&frame.payload).unwrap();
        assert_eq!(port, 2222);
        assert_eq!(proto, Protocol::Tcp);
        assert_eq!(decoded_target, target);
    }

    #[test]
    fn test_error_roundtrip() {
        let frame = build_error(ErrorCode::ConnectionRefused, "connection refused");
        let (code, msg) = parse_error(&frame.payload).unwrap();
        assert_eq!(code, ErrorCode::ConnectionRefused as u16);
        assert_eq!(msg, "connection refused");
    }

    #[test]
    fn test_data_tcp() {
        let data = Bytes::from_static(b"hello tcp");
        let frame = build_data_tcp(123, data.clone());
        assert_eq!(frame.msg_type, MessageType::DataTcp);
        assert_eq!(frame.conn_id, 123);
        assert_eq!(frame.payload, data);
    }

    #[test]
    fn test_data_udp() {
        let data = Bytes::from_static(b"hello udp");
        let frame = build_data_udp(456, data.clone());
        assert_eq!(frame.msg_type, MessageType::DataUdp);
        assert_eq!(frame.conn_id, 456);
        assert_eq!(frame.payload, data);
    }

    #[test]
    fn test_ping_pong() {
        let ping = build_ping();
        assert_eq!(ping.msg_type, MessageType::Ping);
        assert!(ping.payload.is_empty());

        let pong = build_pong();
        assert_eq!(pong.msg_type, MessageType::Pong);
        assert!(pong.payload.is_empty());
    }

    #[test]
    fn test_conn_ready_close() {
        let ready = build_conn_ready(100);
        assert_eq!(ready.msg_type, MessageType::ConnReady);
        assert_eq!(ready.conn_id, 100);

        let close = build_conn_close(100);
        assert_eq!(close.msg_type, MessageType::ConnClose);
        assert_eq!(close.conn_id, 100);
    }

    #[test]
    fn test_protocol_conversion() {
        assert_eq!(Protocol::try_from(0x00), Ok(Protocol::Tcp));
        assert_eq!(Protocol::try_from(0x01), Ok(Protocol::Udp));
        assert_eq!(Protocol::try_from(0x02), Ok(Protocol::Both));
        assert!(Protocol::try_from(0x99).is_err());
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(0x00), Ok(MessageType::Ping));
        assert_eq!(MessageType::try_from(0x40), Ok(MessageType::DataTcp));
        assert_eq!(MessageType::try_from(0xF0), Ok(MessageType::Fault));
        assert!(MessageType::try_from(0x99).is_err());
    }

    #[test]
    fn test_frame_codec_encoder_decoder() {
        use tokio_util::codec::{Decoder, Encoder};

        let mut codec = FrameCodec;
        let frame = Frame {
            msg_type: MessageType::DataTcp,
            flags: 0,
            conn_id: 777,
            payload: Bytes::from_static(b"test data"),
        };

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.msg_type, frame.msg_type);
        assert_eq!(decoded.conn_id, frame.conn_id);
        assert_eq!(decoded.payload, frame.payload);
    }
}
