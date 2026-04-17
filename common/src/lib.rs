//! Binary framing protocol for NAT traversal control and data multiplexing.
//!
//! Public API:
//! - Low-level frame layer ([`Frame`], [`FrameCodec`], [`encode_frame`], [`decode_frame`]) and
//!   shared enums / structs ([`MessageType`], [`Protocol`], [`ConnProtocol`],
//!   [`AddressType`], [`Host`], [`TargetAddress`], [`PortMapping`]).
//! - Strongly-typed messages implementing the [`Message`] trait — use
//!   `msg.to_frame(conn_id)` to build a frame and `Msg::from_frame(&f)` to
//!   parse one.

pub mod message;
pub mod protocol;

pub use protocol::{
    decode_frame, encode_frame, AddressType, ConnProtocol, Frame, FrameCodec, Host, MessageType,
    PortMapping, Protocol, ProtocolError, TargetAddress, FRAME_HEADER_SIZE, MAGIC, VERSION,
};

pub use message::{
    ConfigAck, ConfigPush, ConnClose, ConnReady, DataTcp, DataUdp, ErrorCode, Fault, FrameBuilder,
    Message, NewConn, Ping, Pong, Register, RegisterAck,
};
