//! Strongly-typed message definitions with automatic serialization.
//!
//! Each protocol message is represented as a Rust struct implementing the `Message` trait,
//! providing type-safe encoding/decoding and better ergonomics than raw payload manipulation.

use crate::protocol::{Frame, MessageType, PortMapping, Protocol, ProtocolError, TargetAddress};
use bytes::{BufMut, Bytes, BytesMut};

/// Trait for protocol messages that can be encoded/decoded from frames.
pub trait Message: Sized + Send + Sync {
    /// The message type identifier.
    const MSG_TYPE: MessageType;

    /// Encode the message payload into bytes.
    fn encode_payload(&self) -> Bytes;

    /// Decode the message from a payload slice.
    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError>;

    /// Build a complete frame from this message.
    fn to_frame(&self, conn_id: u64) -> Frame {
        Frame {
            msg_type: Self::MSG_TYPE,
            flags: 0,
            conn_id,
            payload: self.encode_payload(),
        }
    }

    /// Try to extract this message type from a frame.
    fn from_frame(frame: &Frame) -> Result<Self, ProtocolError> {
        if frame.msg_type != Self::MSG_TYPE {
            return Err(ProtocolError::BadMessageType(frame.msg_type as u8));
        }
        Self::decode_payload(&frame.payload)
    }
}

// ============================================================================
// Control Messages
// ============================================================================

/// Client registration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub name: String,
    pub key: Option<String>,
    pub http_proxy_port: Option<u16>,
}

impl Message for Register {
    const MSG_TYPE: MessageType = MessageType::Register;

    fn encode_payload(&self) -> Bytes {
        let name_bytes = self.name.as_bytes();
        let key_bytes = self.key.as_deref().unwrap_or("").as_bytes();
        let mut buf = BytesMut::with_capacity(2 + name_bytes.len() + 2 + key_bytes.len() + 2);
        buf.put_u16(name_bytes.len() as u16);
        buf.extend_from_slice(name_bytes);
        buf.put_u16(self.http_proxy_port.unwrap_or(0));
        buf.put_u16(key_bytes.len() as u16);
        buf.extend_from_slice(key_bytes);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 2 {
            return Err(ProtocolError::Truncated);
        }
        let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + name_len {
            return Err(ProtocolError::Truncated);
        }
        let name = std::str::from_utf8(&payload[2..2 + name_len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_string();

        let mut offset = 2 + name_len;

        let http_proxy_port = if payload.len() >= offset + 2 {
            let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            offset += 2;
            if port != 0 {
                Some(port)
            } else {
                None
            }
        } else {
            None
        };

        let key = if payload.len() >= offset + 2 {
            let key_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            if payload.len() >= offset + key_len && key_len > 0 {
                let s = std::str::from_utf8(&payload[offset..offset + key_len])
                    .map_err(|_| ProtocolError::InvalidUtf8)?
                    .to_string();
                Some(s)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            name,
            key,
            http_proxy_port,
        })
    }
}

/// Server acknowledgment of registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterAck {
    pub client_id: u64,
}

impl Message for RegisterAck {
    const MSG_TYPE: MessageType = MessageType::RegisterAck;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u64(self.client_id);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 8 {
            return Err(ProtocolError::Truncated);
        }
        Ok(Self {
            client_id: u64::from_be_bytes(payload[..8].try_into().unwrap()),
        })
    }
}

/// Configuration push from server to client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPush {
    pub mappings: Vec<PortMapping>,
}

impl Message for ConfigPush {
    const MSG_TYPE: MessageType = MessageType::ConfigPush;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.mappings.len() as u16);
        for m in &self.mappings {
            buf.put_u8(m.protocol as u8);
            buf.put_u16(m.server_port);
            m.target.encode(&mut buf);
        }
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 2 {
            return Err(ProtocolError::Truncated);
        }
        let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let mut mappings = Vec::with_capacity(count);
        let mut offset = 2usize;

        for _ in 0..count {
            if offset >= payload.len() {
                return Err(ProtocolError::Truncated);
            }
            let proto = Protocol::try_from(payload[offset])
                .map_err(|_| ProtocolError::BadMessageType(payload[offset]))?;
            offset += 1;

            if offset + 2 > payload.len() {
                return Err(ProtocolError::Truncated);
            }
            let server_port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            offset += 2;

            let (target, consumed) = TargetAddress::decode(&payload[offset..])?;
            offset += consumed;

            mappings.push(PortMapping {
                server_port,
                protocol: proto,
                target,
            });
        }

        Ok(Self { mappings })
    }
}

/// Client acknowledgment of configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigAck;

impl Message for ConfigAck {
    const MSG_TYPE: MessageType = MessageType::ConfigAck;

    fn encode_payload(&self) -> Bytes {
        Bytes::new()
    }

    fn decode_payload(_payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

/// Heartbeat ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ping;

impl Message for Ping {
    const MSG_TYPE: MessageType = MessageType::Ping;

    fn encode_payload(&self) -> Bytes {
        Bytes::new()
    }

    fn decode_payload(_payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

/// Heartbeat pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pong;

impl Message for Pong {
    const MSG_TYPE: MessageType = MessageType::Pong;

    fn encode_payload(&self) -> Bytes {
        Bytes::new()
    }

    fn decode_payload(_payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

// ============================================================================
// Connection Messages
// ============================================================================

/// Request to establish a new forwarding connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConn {
    pub server_port: u16,
    pub protocol: Protocol,
    pub target: TargetAddress,
}

impl Message for NewConn {
    const MSG_TYPE: MessageType = MessageType::NewConn;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.server_port);
        buf.put_u8(self.protocol as u8);
        self.target.encode(&mut buf);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 3 {
            return Err(ProtocolError::Truncated);
        }
        let server_port = u16::from_be_bytes([payload[0], payload[1]]);
        let protocol = Protocol::try_from(payload[2])
            .map_err(|_| ProtocolError::BadMessageType(payload[2]))?;
        let (target, _) = TargetAddress::decode(&payload[3..])?;
        Ok(Self {
            server_port,
            protocol,
            target,
        })
    }
}

/// Acknowledgment that connection is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnReady;

impl Message for ConnReady {
    const MSG_TYPE: MessageType = MessageType::ConnReady;

    fn encode_payload(&self) -> Bytes {
        Bytes::new()
    }

    fn decode_payload(_payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

/// Request to close a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnClose;

impl Message for ConnClose {
    const MSG_TYPE: MessageType = MessageType::ConnClose;

    fn encode_payload(&self) -> Bytes {
        Bytes::new()
    }

    fn decode_payload(_payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

// ============================================================================
// Data Messages
// ============================================================================

/// TCP data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTcp {
    pub data: Bytes,
}

impl Message for DataTcp {
    const MSG_TYPE: MessageType = MessageType::DataTcp;

    fn encode_payload(&self) -> Bytes {
        self.data.clone()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            data: Bytes::copy_from_slice(payload),
        })
    }
}

/// UDP data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUdp {
    pub data: Bytes,
}

impl Message for DataUdp {
    const MSG_TYPE: MessageType = MessageType::DataUdp;

    fn encode_payload(&self) -> Bytes {
        self.data.clone()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            data: Bytes::copy_from_slice(payload),
        })
    }
}

// ============================================================================
// Error Messages
// ============================================================================

/// Error codes for fault messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    UnknownClient = 0x01,
    PortUnavailable = 0x02,
    ConnectionRefused = 0x03,
    Timeout = 0x04,
    ProtocolError = 0x05,
    InternalError = 0x06,
}

impl TryFrom<u16> for ErrorCode {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::UnknownClient),
            0x02 => Ok(Self::PortUnavailable),
            0x03 => Ok(Self::ConnectionRefused),
            0x04 => Ok(Self::Timeout),
            0x05 => Ok(Self::ProtocolError),
            0x06 => Ok(Self::InternalError),
            _ => Err(()),
        }
    }
}

/// Fault/error notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub code: ErrorCode,
    pub message: String,
}

impl Message for Fault {
    const MSG_TYPE: MessageType = MessageType::Fault;

    fn encode_payload(&self) -> Bytes {
        let msg_bytes = self.message.as_bytes();
        let mut buf = BytesMut::with_capacity(4 + msg_bytes.len());
        buf.put_u16(self.code as u16);
        buf.put_u16(msg_bytes.len() as u16);
        buf.extend_from_slice(msg_bytes);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let code_raw = u16::from_be_bytes([payload[0], payload[1]]);
        let code = ErrorCode::try_from(code_raw).unwrap_or(ErrorCode::InternalError);
        let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;

        if payload.len() < 4 + msg_len {
            return Err(ProtocolError::Truncated);
        }
        let message = std::str::from_utf8(&payload[4..4 + msg_len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_string();

        Ok(Self { code, message })
    }
}

// ============================================================================
// Frame Builder (ergonomic API)
// ============================================================================

/// Builder for constructing frames with a fluent API.
#[derive(Debug, Clone)]
pub struct FrameBuilder {
    msg_type: MessageType,
    flags: u8,
    conn_id: u64,
    payload: Bytes,
}

impl FrameBuilder {
    /// Create a new frame builder for a message.
    pub fn new<M: Message>(msg: &M) -> Self {
        Self {
            msg_type: M::MSG_TYPE,
            flags: 0,
            conn_id: 0,
            payload: msg.encode_payload(),
        }
    }

    /// Set the connection ID.
    pub fn conn_id(mut self, id: u64) -> Self {
        self.conn_id = id;
        self
    }

    /// Set custom flags.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Build the final frame.
    pub fn build(self) -> Frame {
        Frame {
            msg_type: self.msg_type,
            flags: self.flags,
            conn_id: self.conn_id,
            payload: self.payload,
        }
    }
}

// ============================================================================
// Convenience constructors (backwards compatibility)
// ============================================================================

impl Register {
    pub fn new(name: impl Into<String>, key: Option<String>, http_proxy_port: Option<u16>) -> Self {
        Self {
            name: name.into(),
            key,
            http_proxy_port,
        }
    }
}

impl RegisterAck {
    pub fn new(client_id: u64) -> Self {
        Self { client_id }
    }
}

impl ConfigPush {
    pub fn new(mappings: Vec<PortMapping>) -> Self {
        Self { mappings }
    }
}

impl NewConn {
    pub fn new(server_port: u16, protocol: Protocol, target: TargetAddress) -> Self {
        Self {
            server_port,
            protocol,
            target,
        }
    }
}

impl DataTcp {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl DataUdp {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl Fault {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Host;
    use std::net::Ipv4Addr;

    #[test]
    fn test_register_roundtrip() {
        let msg = Register::new("test-client", Some("k1".to_string()), Some(8080));
        let payload = msg.encode_payload();
        let decoded = Register::decode_payload(&payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_register_no_proxy() {
        let msg = Register::new("client", None, None);
        let payload = msg.encode_payload();
        let decoded = Register::decode_payload(&payload).unwrap();
        assert_eq!(decoded.http_proxy_port, None);
    }

    #[test]
    fn test_register_ack_roundtrip() {
        let msg = RegisterAck::new(12345);
        let payload = msg.encode_payload();
        let decoded = RegisterAck::decode_payload(&payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_config_push_roundtrip() {
        let msg = ConfigPush::new(vec![
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
                    host: Host::Domain("localhost".to_string()),
                    port: 53,
                },
            },
        ]);
        let payload = msg.encode_payload();
        let decoded = ConfigPush::decode_payload(&payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_config_push_empty() {
        let msg = ConfigPush::new(vec![]);
        let payload = msg.encode_payload();
        let decoded = ConfigPush::decode_payload(&payload).unwrap();
        assert_eq!(decoded.mappings.len(), 0);
    }

    #[test]
    fn test_new_conn_roundtrip() {
        let msg = NewConn::new(
            8080,
            Protocol::Tcp,
            TargetAddress {
                host: Host::V4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 80,
            },
        );
        let payload = msg.encode_payload();
        let decoded = NewConn::decode_payload(&payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fault_roundtrip() {
        let msg = Fault::new(ErrorCode::ConnectionRefused, "connection refused by peer");
        let payload = msg.encode_payload();
        let decoded = Fault::decode_payload(&payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_frame_builder() {
        let msg = Ping;
        let frame = FrameBuilder::new(&msg).conn_id(42).flags(1).build();
        assert_eq!(frame.msg_type, MessageType::Ping);
        assert_eq!(frame.conn_id, 42);
        assert_eq!(frame.flags, 1);
    }

    #[test]
    fn test_message_to_frame() {
        let msg = RegisterAck::new(999);
        let frame = msg.to_frame(0);
        assert_eq!(frame.msg_type, MessageType::RegisterAck);
        let decoded = RegisterAck::from_frame(&frame).unwrap();
        assert_eq!(decoded.client_id, 999);
    }
}
