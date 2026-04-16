//! Binary framing protocol for NAT traversal control and data multiplexing.
//!
//! This crate provides two APIs for working with the protocol:
//!
//! 1. **Low-level API** (`protocol` module): Direct frame encoding/decoding with `build_*` and
//!    `parse_*` functions. Use this for maximum control and backwards compatibility.
//!
//! 2. **High-level API** (`message` module): Strongly-typed message structs implementing the
//!    `Message` trait. Use this for type safety and better ergonomics.

pub mod message;
pub mod protocol;

// Re-export low-level API (backwards compatible)
pub use protocol::{
    build_config_ack, build_config_push, build_conn_close, build_conn_ready, build_data_tcp,
    build_data_udp, build_error, build_new_conn, build_ping, build_pong, build_register,
    build_register_ack, decode_frame, encode_frame, parse_config_push, parse_error, parse_new_conn,
    parse_register, parse_register_ack, AddressType, ErrorCode, Frame, FrameCodec, Host,
    MessageType, PortMapping, Protocol, ProtocolError, TargetAddress, FRAME_HEADER_SIZE, MAGIC,
    VERSION,
};

// Re-export high-level message API
pub use message::ErrorCode as MsgErrorCode;
pub use message::{
    ConfigAck, ConfigPush, ConnClose, ConnReady, DataTcp, DataUdp, Fault, FrameBuilder, Message,
    NewConn, Ping, Pong, Register, RegisterAck,
};
