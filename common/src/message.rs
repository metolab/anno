//! Strongly-typed protocol messages with automatic frame encoding/decoding.
//!
//! Every protocol message has a dedicated struct implementing [`Message`].
//! Use `msg.to_frame(conn_id)` to build a wire frame and `Msg::from_frame(&f)`
//! to parse one. This is the only public encoding/decoding API — the
//! low-level [`crate::protocol`] module is only used for the frame header
//! itself plus shared enums/types.

use crate::protocol::{
    ConnProtocol, Frame, MessageType, PortMapping, Protocol, ProtocolError, TargetAddress,
};
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

/// Default number of physical TCP lanes per client mux session.
pub const DEFAULT_LANES: u8 = 4;
/// Hard cap on the number of physical TCP lanes the protocol supports.
/// Picked so a malicious peer cannot exhaust file descriptors via a single
/// `Register`. Server may still grant fewer.
pub const MAX_LANES: u8 = 16;
/// Default maximum frame size (per shard) negotiated for new sessions.
/// 16 KiB matches HTTP/2 default `SETTINGS_MAX_FRAME_SIZE` and gives a
/// good fairness/syscall trade-off.
pub const DEFAULT_MAX_FRAME_SIZE: u16 = 16 * 1024;
/// Hard floor — frames smaller than this are rejected during negotiation
/// so that a degenerate value cannot make every TCP read into a frame.
pub const MIN_MAX_FRAME_SIZE: u16 = 1024;
/// Default per-stream credit window (bytes). Receiver acks every
/// `initial_window/2` bytes via `WindowUpdate`.
pub const DEFAULT_INITIAL_WINDOW: u32 = 256 * 1024;

/// Client registration request.
///
/// Wire layout (v3):
///   u16 http_proxy_port (0 means none)
///   u16 key_len
///   [key_len] bytes of key
///   u8  requested_lanes (0 means "use server default")
///   u16 max_frame_size  (0 means "use server default")
///   u32 initial_window  (0 means "use server default")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub key: String,
    pub http_proxy_port: Option<u16>,
    /// Number of physical TCP lanes the client wants for this session.
    /// 0 asks the server to pick its default. Server enforces an upper
    /// bound and echoes the granted count in `RegisterAck::granted_lanes`.
    pub requested_lanes: u8,
    /// Largest single shard the client is willing to send/accept on the
    /// wire. 0 asks for the server default. Negotiated value is the
    /// `min` of both peers, clamped to `MIN_MAX_FRAME_SIZE`.
    pub max_frame_size: u16,
    /// Initial per-stream credit window (bytes). 0 means default.
    pub initial_window: u32,
}

impl Message for Register {
    const MSG_TYPE: MessageType = MessageType::Register;

    fn encode_payload(&self) -> Bytes {
        let hp = self.http_proxy_port.filter(|p| *p > 0).unwrap_or(0);
        let key_bytes = self.key.as_bytes();
        // Key is length-prefixed by u16: truncate to fit rather than silently
        // wrap. Real keys are UUIDs (~36 bytes) so this only defends against
        // misuse.
        let key_len = key_bytes.len().min(u16::MAX as usize);
        let mut buf = BytesMut::with_capacity(2 + 2 + key_len + 1 + 2 + 4);
        buf.put_u16(hp);
        buf.put_u16(key_len as u16);
        buf.extend_from_slice(&key_bytes[..key_len]);
        buf.put_u8(self.requested_lanes);
        buf.put_u16(self.max_frame_size);
        buf.put_u32(self.initial_window);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let hp = u16::from_be_bytes([payload[0], payload[1]]);
        let http_proxy_port = if hp != 0 { Some(hp) } else { None };
        let key_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if key_len == 0 {
            return Err(ProtocolError::InvalidRegisterPayload);
        }
        if payload.len() < 4 + key_len {
            return Err(ProtocolError::Truncated);
        }
        let key = std::str::from_utf8(&payload[4..4 + key_len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_string();
        let mut off = 4 + key_len;
        // The mux negotiation tail is optional so a v3 server can accept a
        // future "minimal" client (or a test fixture) that omits it; missing
        // bytes mean "use defaults".
        let requested_lanes = if payload.len() > off {
            let v = payload[off];
            off += 1;
            v
        } else {
            0
        };
        let max_frame_size = if payload.len() >= off + 2 {
            let v = u16::from_be_bytes([payload[off], payload[off + 1]]);
            off += 2;
            v
        } else {
            0
        };
        let initial_window = if payload.len() >= off + 4 {
            u32::from_be_bytes([
                payload[off],
                payload[off + 1],
                payload[off + 2],
                payload[off + 3],
            ])
        } else {
            0
        };
        Ok(Self {
            key,
            http_proxy_port,
            requested_lanes,
            max_frame_size,
            initial_window,
        })
    }
}

/// Server acknowledgment of registration.
///
/// Wire layout (v3):
///   u64 client_id
///   u64 session_token (echoed back via `LaneHello` for the 2..N lanes)
///   u8  granted_lanes
///   u16 max_frame_size
///   u32 initial_window
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterAck {
    pub client_id: u64,
    /// Opaque token the server assigns to this mux session. Bigger lanes
    /// (i.e. lane 1..N) attach by quoting it back in [`LaneHello`].
    pub session_token: u64,
    pub granted_lanes: u8,
    pub max_frame_size: u16,
    pub initial_window: u32,
}

impl Message for RegisterAck {
    const MSG_TYPE: MessageType = MessageType::RegisterAck;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8 + 8 + 1 + 2 + 4);
        buf.put_u64(self.client_id);
        buf.put_u64(self.session_token);
        buf.put_u8(self.granted_lanes);
        buf.put_u16(self.max_frame_size);
        buf.put_u32(self.initial_window);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 8 {
            return Err(ProtocolError::Truncated);
        }
        let client_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
        // Tail is optional so a v3 server that hasn't yet been upgraded to
        // emit the mux negotiation block still parses cleanly with
        // defaults.
        let session_token = if payload.len() >= 16 {
            u64::from_be_bytes(payload[8..16].try_into().unwrap())
        } else {
            0
        };
        let granted_lanes = if payload.len() >= 17 { payload[16] } else { 1 };
        let max_frame_size = if payload.len() >= 19 {
            u16::from_be_bytes([payload[17], payload[18]])
        } else {
            DEFAULT_MAX_FRAME_SIZE
        };
        let initial_window = if payload.len() >= 23 {
            u32::from_be_bytes([payload[19], payload[20], payload[21], payload[22]])
        } else {
            DEFAULT_INITIAL_WINDOW
        };
        Ok(Self {
            client_id,
            session_token,
            granted_lanes,
            max_frame_size,
            initial_window,
        })
    }
}

/// Per-stream credit-based flow control update.
///
/// `frame.conn_id` selects the target stream. The receiver of `DataTcp`
/// emits `WindowUpdate(increment)` once it has consumed `increment` bytes
/// out of the previously-advertised window. The sender adds `increment`
/// to its `send_credit` and resumes if previously parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowUpdate {
    pub increment: u32,
}

impl Message for WindowUpdate {
    const MSG_TYPE: MessageType = MessageType::WindowUpdate;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u32(self.increment);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        Ok(Self { increment })
    }
}

impl WindowUpdate {
    pub fn new(increment: u32) -> Self {
        Self { increment }
    }
}

/// Graceful-shutdown notification.
///
/// Sent by either peer to indicate that no new streams beyond
/// `last_accepted_conn_id` will be honoured; in-flight streams may
/// drain. After a grace period the connection is closed.
///
/// Wire layout:
///   u64 last_accepted_conn_id
///   u16 code (mirrors `ErrorCode` numeric space)
///   u16 reason_len
///   [reason_len] bytes utf-8 reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub last_accepted_conn_id: u64,
    pub code: ErrorCode,
    pub reason: String,
}

impl Message for GoAway {
    const MSG_TYPE: MessageType = MessageType::GoAway;

    fn encode_payload(&self) -> Bytes {
        let bytes = self.reason.as_bytes();
        let len = bytes.len().min(u16::MAX as usize);
        let mut buf = BytesMut::with_capacity(8 + 2 + 2 + len);
        buf.put_u64(self.last_accepted_conn_id);
        buf.put_u16(u16::from(self.code));
        buf.put_u16(len as u16);
        buf.extend_from_slice(&bytes[..len]);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 12 {
            return Err(ProtocolError::Truncated);
        }
        let last_accepted_conn_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
        let code = ErrorCode::from(u16::from_be_bytes([payload[8], payload[9]]));
        let len = u16::from_be_bytes([payload[10], payload[11]]) as usize;
        if payload.len() < 12 + len {
            return Err(ProtocolError::Truncated);
        }
        let reason = std::str::from_utf8(&payload[12..12 + len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_string();
        Ok(Self {
            last_accepted_conn_id,
            code,
            reason,
        })
    }
}

impl GoAway {
    pub fn new(last_accepted_conn_id: u64, code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            last_accepted_conn_id,
            code,
            reason: reason.into(),
        }
    }
}

/// Bind a freshly-opened TCP connection to an existing mux session.
///
/// After the first lane completes the regular `Register`/`RegisterAck`
/// handshake the client opens additional TCP connections (lanes
/// `1..granted_lanes`) and sends `LaneHello` as the first frame. The
/// server matches `session_token` to the in-memory mux entry and
/// attaches the new lane.
///
/// Wire layout:
///   u64 session_token
///   u8  lane_idx
///   u8  lane_total
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneHello {
    pub session_token: u64,
    pub lane_idx: u8,
    pub lane_total: u8,
}

impl Message for LaneHello {
    const MSG_TYPE: MessageType = MessageType::LaneHello;

    fn encode_payload(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8 + 1 + 1);
        buf.put_u64(self.session_token);
        buf.put_u8(self.lane_idx);
        buf.put_u8(self.lane_total);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 10 {
            return Err(ProtocolError::Truncated);
        }
        let session_token = u64::from_be_bytes(payload[..8].try_into().unwrap());
        let lane_idx = payload[8];
        let lane_total = payload[9];
        Ok(Self {
            session_token,
            lane_idx,
            lane_total,
        })
    }
}

impl LaneHello {
    pub fn new(session_token: u64, lane_idx: u8, lane_total: u8) -> Self {
        Self {
            session_token,
            lane_idx,
            lane_total,
        }
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
        // Count is length-prefixed by u16 on the wire; saturate at
        // u16::MAX and serialise only that many mappings so an oversized
        // list does not silently truncate via an `as` cast that would
        // wrap around and desynchronise the decoder.
        let count = self.mappings.len().min(u16::MAX as usize);
        buf.put_u16(count as u16);
        for m in self.mappings.iter().take(count) {
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
///
/// Per-connection protocol is strictly TCP or UDP (no `Both`), enforced
/// by the [`ConnProtocol`] type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConn {
    pub server_port: u16,
    pub protocol: ConnProtocol,
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
        let protocol = ConnProtocol::try_from(payload[2])
            .map_err(|_| ProtocolError::BadConnProtocol(payload[2]))?;
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
///
/// The `Unknown(u16)` variant preserves unrecognized codes verbatim so the
/// decoder never loses information (previously an unknown value was mapped
/// to `InternalError`, which was lossy and confusing in logs). The wire
/// format is unchanged: the raw `u16` is what's serialised in both
/// directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownClient,
    PortUnavailable,
    ConnectionRefused,
    Timeout,
    ProtocolError,
    InternalError,
    /// Authentication failed (bad client key, deleted entry, etc).
    /// Distinct from [`ConnectionRefused`] so the client can stop
    /// retrying instead of looping with backoff against a server
    /// that will never accept it.
    AuthFailed,
    Unknown(u16),
}

impl From<u16> for ErrorCode {
    fn from(v: u16) -> Self {
        match v {
            0x01 => Self::UnknownClient,
            0x02 => Self::PortUnavailable,
            0x03 => Self::ConnectionRefused,
            0x04 => Self::Timeout,
            0x05 => Self::ProtocolError,
            0x06 => Self::InternalError,
            0x07 => Self::AuthFailed,
            other => Self::Unknown(other),
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(c: ErrorCode) -> u16 {
        match c {
            ErrorCode::UnknownClient => 0x01,
            ErrorCode::PortUnavailable => 0x02,
            ErrorCode::ConnectionRefused => 0x03,
            ErrorCode::Timeout => 0x04,
            ErrorCode::ProtocolError => 0x05,
            ErrorCode::InternalError => 0x06,
            ErrorCode::AuthFailed => 0x07,
            ErrorCode::Unknown(v) => v,
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
        // Message is length-prefixed by u16 on the wire. Truncate to the
        // largest value that still fits in the length field so the frame
        // never carries a wrapped-around length that would desync the
        // decoder on the peer.
        let len = msg_bytes.len().min(u16::MAX as usize);
        let mut buf = BytesMut::with_capacity(4 + len);
        buf.put_u16(u16::from(self.code));
        buf.put_u16(len as u16);
        buf.extend_from_slice(&msg_bytes[..len]);
        buf.freeze()
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let code_raw = u16::from_be_bytes([payload[0], payload[1]]);
        let code = ErrorCode::from(code_raw);
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
    pub fn new<M: Message>(msg: &M) -> Self {
        Self {
            msg_type: M::MSG_TYPE,
            flags: 0,
            conn_id: 0,
            payload: msg.encode_payload(),
        }
    }

    pub fn conn_id(mut self, id: u64) -> Self {
        self.conn_id = id;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

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
// Convenience constructors
// ============================================================================

impl Register {
    /// Build a `Register` with the protocol defaults for the mux
    /// negotiation block (lanes / max_frame_size / initial_window).
    /// Use the struct literal directly to override.
    pub fn new(key: impl Into<String>, http_proxy_port: Option<u16>) -> Self {
        Self {
            key: key.into(),
            http_proxy_port,
            requested_lanes: DEFAULT_LANES,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            initial_window: DEFAULT_INITIAL_WINDOW,
        }
    }
}

impl RegisterAck {
    pub fn new(client_id: u64) -> Self {
        Self {
            client_id,
            session_token: 0,
            granted_lanes: 1,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            initial_window: DEFAULT_INITIAL_WINDOW,
        }
    }
}

impl ConfigPush {
    pub fn new(mappings: Vec<PortMapping>) -> Self {
        Self { mappings }
    }
}

impl NewConn {
    pub fn new(server_port: u16, protocol: ConnProtocol, target: TargetAddress) -> Self {
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
    use crate::protocol::{AddressType, Host};
    use std::net::Ipv4Addr;

    #[test]
    fn test_register_roundtrip() {
        let msg = Register::new("k1", Some(8080));
        let frame = msg.to_frame(0);
        let decoded = Register::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_register_no_proxy() {
        let msg = Register::new("client-key", None);
        let frame = msg.to_frame(0);
        let decoded = Register::from_frame(&frame).unwrap();
        assert_eq!(decoded.http_proxy_port, None);
        assert_eq!(decoded.key, "client-key");
        assert_eq!(decoded.requested_lanes, DEFAULT_LANES);
        assert_eq!(decoded.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(decoded.initial_window, DEFAULT_INITIAL_WINDOW);
    }

    #[test]
    fn test_register_custom_negotiation() {
        let msg = Register {
            key: "abc".into(),
            http_proxy_port: None,
            requested_lanes: 8,
            max_frame_size: 4096,
            initial_window: 64 * 1024,
        };
        let frame = msg.to_frame(0);
        let decoded = Register::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_register_legacy_minimal_payload_uses_defaults() {
        // Old-style payload without the v3 negotiation tail. The decoder
        // should treat missing bytes as "use default" rather than
        // erroring, so test fixtures can keep handcrafting minimal
        // payloads.
        let mut p = BytesMut::new();
        p.put_u16(0u16);
        p.put_u16(3u16);
        p.extend_from_slice(b"key");
        let decoded = Register::decode_payload(&p).unwrap();
        assert_eq!(decoded.key, "key");
        assert_eq!(decoded.requested_lanes, 0);
        assert_eq!(decoded.max_frame_size, 0);
        assert_eq!(decoded.initial_window, 0);
    }

    #[test]
    fn test_register_rejects_zero_key_len() {
        let mut p = BytesMut::new();
        p.put_u16(0u16);
        p.put_u16(0u16);
        let err = Register::decode_payload(&p).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidRegisterPayload));
    }

    #[test]
    fn test_register_ack_roundtrip() {
        let msg = RegisterAck {
            client_id: 12345,
            session_token: 9876,
            granted_lanes: 4,
            max_frame_size: 8192,
            initial_window: 128 * 1024,
        };
        let frame = msg.to_frame(0);
        let decoded = RegisterAck::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_register_ack_legacy_minimal_payload_uses_defaults() {
        let mut p = BytesMut::new();
        p.put_u64(7);
        let decoded = RegisterAck::decode_payload(&p).unwrap();
        assert_eq!(decoded.client_id, 7);
        assert_eq!(decoded.session_token, 0);
        assert_eq!(decoded.granted_lanes, 1);
        assert_eq!(decoded.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(decoded.initial_window, DEFAULT_INITIAL_WINDOW);
    }

    #[test]
    fn test_window_update_roundtrip() {
        let msg = WindowUpdate::new(65536);
        let frame = msg.to_frame(42);
        assert_eq!(frame.conn_id, 42);
        let decoded = WindowUpdate::from_frame(&frame).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_window_update_truncated() {
        let p = [0u8, 0, 0]; // need 4 bytes
        let err = WindowUpdate::decode_payload(&p).unwrap_err();
        assert!(matches!(err, ProtocolError::Truncated));
    }

    #[test]
    fn test_goaway_roundtrip() {
        let msg = GoAway::new(99, ErrorCode::ProtocolError, "bye");
        let frame = msg.to_frame(0);
        let decoded = GoAway::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_lane_hello_roundtrip() {
        let msg = LaneHello::new(0xdead_beef_cafe, 2, 4);
        let frame = msg.to_frame(0);
        let decoded = LaneHello::from_frame(&frame).unwrap();
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
        let frame = msg.to_frame(0);
        let decoded = ConfigPush::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_config_push_empty() {
        let msg = ConfigPush::new(vec![]);
        let frame = msg.to_frame(0);
        let decoded = ConfigPush::from_frame(&frame).unwrap();
        assert_eq!(decoded.mappings.len(), 0);
    }

    #[test]
    fn test_new_conn_roundtrip() {
        let msg = NewConn::new(
            8080,
            ConnProtocol::Tcp,
            TargetAddress {
                host: Host::V4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 80,
            },
        );
        let frame = msg.to_frame(42);
        let decoded = NewConn::from_frame(&frame).unwrap();
        assert_eq!(msg, decoded);
        assert_eq!(frame.conn_id, 42);
    }

    #[test]
    fn test_new_conn_rejects_both_on_wire() {
        // server_port (2B) + proto(1B = 0x02 Both) + ipv4 target
        let payload: &[u8] = &[
            0x1F, 0x90, // port 8080
            0x02, // Both — must be rejected
            AddressType::Ipv4 as u8,
            127, 0, 0, 1, 0, 80,
        ];
        let err = NewConn::decode_payload(payload).unwrap_err();
        assert!(matches!(err, ProtocolError::BadConnProtocol(0x02)));
    }

    #[test]
    fn test_fault_roundtrip() {
        let msg = Fault::new(ErrorCode::ConnectionRefused, "connection refused by peer");
        let frame = msg.to_frame(0);
        let decoded = Fault::from_frame(&frame).unwrap();
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
    fn test_data_tcp_udp() {
        let data = Bytes::from_static(b"hello");
        let tcp = DataTcp::new(data.clone()).to_frame(1);
        assert_eq!(tcp.msg_type, MessageType::DataTcp);
        let udp = DataUdp::new(data.clone()).to_frame(2);
        assert_eq!(udp.msg_type, MessageType::DataUdp);
        let back_tcp = DataTcp::from_frame(&tcp).unwrap();
        assert_eq!(back_tcp.data, data);
    }

    #[test]
    fn test_from_frame_wrong_type() {
        let ping = Ping.to_frame(0);
        let err = Pong::from_frame(&ping).unwrap_err();
        assert!(matches!(err, ProtocolError::BadMessageType(_)));
    }
}
