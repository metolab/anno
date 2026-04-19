//! Binary framing protocol for NAT traversal control and data multiplexing.
//!
//! Public API:
//! - Low-level frame layer ([`Frame`], [`FrameCodec`], [`encode_frame`], [`decode_frame`]) and
//!   shared enums / structs ([`MessageType`], [`Protocol`], [`ConnProtocol`],
//!   [`AddressType`], [`Host`], [`TargetAddress`], [`PortMapping`]).
//! - Strongly-typed messages implementing the [`Message`] trait — use
//!   `msg.to_frame(conn_id)` to build a frame and `Msg::from_frame(&f)` to
//!   parse one.
//! - The [`mux`] module bundles the cross-cutting machinery shared by
//!   client and server: payload sharding ([`mux::FrameShard`]),
//!   reassembly ([`mux::Reassembler`]), and the weighted fair-share
//!   scheduler ([`mux::Scheduler`]).

pub mod message;
pub mod mux;
pub mod protocol;

pub use protocol::{
    decode_frame, encode_frame, flags, AddressType, ConnProtocol, Frame, FrameCodec, Host,
    MessageType, PortMapping, Protocol, ProtocolError, TargetAddress, FRAME_HEADER_SIZE, MAGIC,
    VERSION,
};

pub use message::{
    ConfigAck, ConfigPush, ConnClose, ConnReady, DataTcp, DataUdp, ErrorCode, Fault, FrameBuilder,
    GoAway, LaneHello, Message, NewConn, Ping, Pong, Register, RegisterAck, WindowUpdate,
    DEFAULT_INITIAL_WINDOW, DEFAULT_LANES, DEFAULT_MAX_FRAME_SIZE, MAX_LANES,
    MIN_MAX_FRAME_SIZE,
};

pub use mux::{ReassemblyBudget, ReassemblyOutcome, Reassembler};
