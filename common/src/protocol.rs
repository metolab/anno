//! Fixed 16-byte header + payload frames (big-endian).
//!
//! This module only defines the low-level wire format:
//! - Frame header / magic / version / message type codes
//! - Enumerations shared with the high-level `message` module
//! - Binary encoding of addresses (used by several message types)
//!
//! All payload-level helpers live in the [`crate::message`] module and are
//! built around the `Message` trait.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

pub const FRAME_HEADER_SIZE: usize = 16;
pub const MAGIC: u16 = 0x4E54;
pub const VERSION: u8 = 0x02;

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

/// Protocol selector for port mappings (config layer).
///
/// `Both` means "listen on TCP AND UDP for this server port"; it is only
/// meaningful inside [`PortMapping`] / `ConfigPush`. Per-connection frames
/// (e.g. `NewConn`) use [`ConnProtocol`] which is strictly `Tcp` or `Udp`.
///
/// `HttpProxy` is a TCP listener whose per-connection target is resolved
/// server-side to `127.0.0.1:<client's registered http_proxy_port>`, so
/// a client that restarts with a different random proxy port keeps
/// working transparently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0x00,
    Udp = 0x01,
    Both = 0x02,
    HttpProxy = 0x03,
}

impl TryFrom<u8> for Protocol {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Tcp),
            0x01 => Ok(Self::Udp),
            0x02 => Ok(Self::Both),
            0x03 => Ok(Self::HttpProxy),
            _ => Err(()),
        }
    }
}

/// Connection-level protocol (no `Both`) used on the wire for `NewConn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnProtocol {
    Tcp = 0x00,
    Udp = 0x01,
}

impl TryFrom<u8> for ConnProtocol {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Tcp),
            0x01 => Ok(Self::Udp),
            // Explicitly reject 0x02 (Both) — it is not a valid per-connection
            // protocol; accepting it would lead to silent warn-and-drop on the
            // client side.
            _ => Err(()),
        }
    }
}

impl From<ConnProtocol> for Protocol {
    fn from(p: ConnProtocol) -> Self {
        match p {
            ConnProtocol::Tcp => Protocol::Tcp,
            ConnProtocol::Udp => Protocol::Udp,
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
                // Domain is length-prefixed by a single byte: truncate on the
                // wire rather than panic. Callers (e.g. the HTTP API layer)
                // should validate the length before it ever reaches here.
                debug_assert!(b.len() <= 255, "domain too long: {} bytes", b.len());
                debug_assert!(!b.is_empty(), "domain must not be empty");
                let len = b.len().min(255);
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(len as u8);
                buf.put_slice(&b[..len]);
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
                if len == 0 {
                    // Reject empty domains at the protocol boundary so we
                    // never hand an empty string to DNS downstream.
                    return Err(ProtocolError::EmptyDomain);
                }
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
    #[error("invalid register payload")]
    InvalidRegisterPayload,
    #[error("bad address type {0}")]
    BadAddressType(u8),
    #[error("empty domain name")]
    EmptyDomain,
    #[error("bad connection protocol {0}")]
    BadConnProtocol(u8),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn encode_frame(f: &Frame) -> BytesMut {
    // The wire format uses a 2-byte payload length. Callers must cap their
    // reads/payloads to <= 65535. This guard catches regressions in debug;
    // in release we clamp to u16::MAX so we never silently wrap to 0 and
    // corrupt the stream for the peer.
    debug_assert!(
        f.payload.len() <= u16::MAX as usize,
        "frame payload too large: {} bytes",
        f.payload.len()
    );
    let payload_len = f.payload.len().min(u16::MAX as usize);
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);
    buf.put_u16(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(f.msg_type as u8);
    buf.put_u8(f.flags);
    buf.put_u8(0);
    buf.put_u16(payload_len as u16);
    buf.put_u64(f.conn_id);
    buf.extend_from_slice(&f.payload[..payload_len]);
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

/// Port mapping definition (config layer): which server port forwards to
/// which target over which protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub server_port: u16,
    pub protocol: Protocol,
    pub target: TargetAddress,
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

        let mut partial = BytesMut::from(&encoded[..8]);
        assert!(decode_frame(&mut partial).unwrap().is_none());

        let mut partial = BytesMut::from(&encoded[..FRAME_HEADER_SIZE + 2]);
        assert!(decode_frame(&mut partial).unwrap().is_none());

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
                0x4E, 0x54, VERSION, 0xFF, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
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
        assert_eq!(consumed, 7);
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
        assert_eq!(consumed, 19);
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
        assert_eq!(consumed, 1 + 1 + 11 + 2);
    }

    #[test]
    fn test_target_address_empty_domain_rejected() {
        // Manually craft a Domain TargetAddress with length=0.
        let buf: &[u8] = &[AddressType::Domain as u8, 0x00, 0x00, 0x50];
        let err = TargetAddress::decode(buf).unwrap_err();
        assert!(matches!(err, ProtocolError::EmptyDomain));
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
    fn test_protocol_conversion() {
        assert_eq!(Protocol::try_from(0x00), Ok(Protocol::Tcp));
        assert_eq!(Protocol::try_from(0x01), Ok(Protocol::Udp));
        assert_eq!(Protocol::try_from(0x02), Ok(Protocol::Both));
        assert_eq!(Protocol::try_from(0x03), Ok(Protocol::HttpProxy));
        assert!(Protocol::try_from(0x99).is_err());
    }

    #[test]
    fn test_conn_protocol_rejects_both() {
        assert_eq!(ConnProtocol::try_from(0x00), Ok(ConnProtocol::Tcp));
        assert_eq!(ConnProtocol::try_from(0x01), Ok(ConnProtocol::Udp));
        assert!(ConnProtocol::try_from(0x02).is_err());
        assert!(ConnProtocol::try_from(0x99).is_err());
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
