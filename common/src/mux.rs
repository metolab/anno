//! Cross-cutting machinery shared by the client and server multiplexer:
//!
//! - [`FrameShard`] turns a (potentially large) payload into a sequence of
//!   wire-sized frames, marking every shard except the last with
//!   `flags::MORE` so the receiver can rebuild the original payload.
//! - [`Reassembler`] is the receiver-side counterpart: it accumulates
//!   `MORE`-flagged shards keyed by `conn_id` until a non-`MORE` shard
//!   arrives, then yields the concatenated payload. It enforces a
//!   per-stream byte cap and a wall-clock deadline so a malicious peer
//!   cannot pin server memory by trickling shards forever.
//! - [`Scheduler`] is a deterministic weighted round-robin queue used by
//!   the per-lane writer task. Control frames (Ping/Pong/Window/GoAway/
//!   Register*) bypass per-stream queues via a high-priority lane so a
//!   single fat data stream can never starve heartbeats.
//!
//! These primitives are deliberately runtime-agnostic — they operate on
//! [`Frame`] values and plain Rust collections so they're trivial to
//! exercise from `cargo test` without any tokio plumbing.

use crate::message::{Message, WindowUpdate, MAX_LANES, MIN_MAX_FRAME_SIZE};
use crate::protocol::{flags, Frame, MessageType};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

/// Negotiated mux session parameters, agreed during the
/// `Register`/`RegisterAck` handshake.
#[derive(Debug, Clone, Copy)]
pub struct MuxParams {
    pub lanes: u8,
    pub max_frame_size: u16,
    pub initial_window: u32,
}

impl MuxParams {
    /// Negotiate by taking the most conservative value of each side.
    /// `0` on either side means "use my default", so we substitute the
    /// `default_*` arguments before clamping. Lanes can never exceed
    /// [`MAX_LANES`]; frame size is floored at [`MIN_MAX_FRAME_SIZE`] so
    /// it's always large enough for the handshake messages themselves.
    pub fn negotiate(
        client_lanes: u8,
        client_frame: u16,
        client_window: u32,
        default_lanes: u8,
        default_frame: u16,
        default_window: u32,
    ) -> Self {
        let req_lanes = if client_lanes == 0 {
            default_lanes
        } else {
            client_lanes
        };
        let req_frame = if client_frame == 0 {
            default_frame
        } else {
            client_frame
        };
        let req_window = if client_window == 0 {
            default_window
        } else {
            client_window
        };
        let lanes = req_lanes.min(default_lanes).clamp(1, MAX_LANES);
        let max_frame_size = req_frame.min(default_frame).max(MIN_MAX_FRAME_SIZE);
        // We never want a 0 window (would deadlock immediately) so floor
        // at one frame's worth.
        let initial_window = req_window.min(default_window).max(max_frame_size as u32);
        Self {
            lanes,
            max_frame_size,
            initial_window,
        }
    }
}

// ---------------------------------------------------------------------------
// Sharding (sender side)
// ---------------------------------------------------------------------------

/// Iterator that splits a payload into wire-sized frames carrying
/// [`flags::MORE`] on every shard except the last.
///
/// Empty payloads still produce exactly one frame so the receiver always
/// gets a "this is the end of the message" signal.
pub struct FrameShard {
    msg_type: MessageType,
    conn_id: u64,
    /// Extra flags ORed into every emitted shard (e.g. `flags::FIN` on
    /// the last user-level write). The MORE bit is managed internally.
    extra_flags: u8,
    bytes: Bytes,
    total: usize,
    max_frame_size: usize,
    offset: usize,
    emitted_first: bool,
}

impl FrameShard {
    /// Build a sharder for `payload`.
    pub fn new(
        msg_type: MessageType,
        conn_id: u64,
        payload: Bytes,
        max_frame_size: usize,
    ) -> Self {
        let total = payload.len();
        Self {
            msg_type,
            conn_id,
            extra_flags: 0,
            bytes: payload,
            total,
            max_frame_size: max_frame_size.max(1),
            offset: 0,
            emitted_first: false,
        }
    }

    /// OR the supplied flag bits into every emitted shard. The
    /// fragmentation-control [`flags::MORE`] bit is still managed by the
    /// sharder regardless.
    pub fn with_extra_flags(mut self, flags: u8) -> Self {
        self.extra_flags = flags;
        self
    }
}

impl Iterator for FrameShard {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        if self.offset >= self.total {
            // Empty payload special case: emit exactly one zero-byte
            // frame so the receiver still observes a "logical message"
            // boundary.
            if !self.emitted_first {
                self.emitted_first = true;
                return Some(Frame {
                    msg_type: self.msg_type,
                    flags: self.extra_flags & !flags::MORE,
                    conn_id: self.conn_id,
                    payload: Bytes::new(),
                });
            }
            return None;
        }
        let take = self.max_frame_size.min(self.total - self.offset);
        let end = self.offset + take;
        let chunk = self.bytes.slice(self.offset..end);
        let is_last = end == self.total;
        let mut flag_bits = self.extra_flags;
        if !is_last {
            flag_bits |= flags::MORE;
        } else {
            flag_bits &= !flags::MORE;
        }
        self.offset = end;
        self.emitted_first = true;
        Some(Frame {
            msg_type: self.msg_type,
            flags: flag_bits,
            conn_id: self.conn_id,
            payload: chunk,
        })
    }
}

// ---------------------------------------------------------------------------
// Reassembly (receiver side)
// ---------------------------------------------------------------------------

/// Outcome of feeding a shard into the [`Reassembler`].
#[derive(Debug)]
pub enum ReassemblyOutcome {
    /// More shards expected; nothing to deliver yet.
    Pending,
    /// Complete payload reconstituted (may be a single frame whose
    /// `MORE` bit was already clear on arrival).
    Complete(Bytes),
    /// Shard rejected because the in-flight buffer would exceed
    /// `max_inflight_bytes` for this conn_id. Caller should reset the
    /// stream.
    Overflow,
}

struct Pending {
    chunks: Vec<Bytes>,
    bytes: usize,
    deadline: Instant,
}

/// Process-wide reservation for reassembly buffers. Several
/// [`Reassembler`] instances share one budget so a misbehaving client
/// can't push the server past a global memory ceiling by spreading
/// MORE-fragmented streams across many sessions / lanes. The budget
/// is intentionally lock-free: contention here would directly
/// translate to control-plane jitter.
#[derive(Debug)]
pub struct ReassemblyBudget {
    used: std::sync::atomic::AtomicUsize,
    cap: usize,
}

impl ReassemblyBudget {
    /// `cap == 0` means "unlimited" (only per-stream caps apply).
    pub fn new(cap: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            used: std::sync::atomic::AtomicUsize::new(0),
            cap,
        })
    }

    /// Try to reserve `n` bytes. Returns `false` and reserves
    /// nothing if the global cap would be exceeded.
    fn try_reserve(&self, n: usize) -> bool {
        if self.cap == 0 {
            self.used
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        let mut cur = self.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let next = cur.saturating_add(n);
            if next > self.cap {
                return false;
            }
            match self.used.compare_exchange_weak(
                cur,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        // `saturating_sub` semantics via fetch + clamp: under-flow
        // would indicate a double-release bug — clamp to keep going.
        let mut cur = self.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            match self.used.compare_exchange_weak(
                cur,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Currently reserved bytes across every reassembler attached to
    /// this budget. Useful for a `mux_reassembly_bytes_inflight_global`
    /// gauge.
    pub fn used(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn cap(&self) -> usize {
        self.cap
    }
}

/// Per-stream reassembly buffer for `MORE`-fragmented payloads.
///
/// Limits are enforced per stream so a single connection can't blow
/// past the cap regardless of how many other streams are active. An
/// optional [`ReassemblyBudget`] additionally caps the total across
/// every attached reassembler, protecting the process from many
/// small-but-bursty sessions adding up to a large heap footprint.
pub struct Reassembler {
    map: HashMap<u64, Pending>,
    max_inflight_bytes: usize,
    max_age: Duration,
    budget: Option<std::sync::Arc<ReassemblyBudget>>,
}

impl Reassembler {
    pub fn new(max_inflight_bytes: usize, max_age: Duration) -> Self {
        Self {
            map: HashMap::new(),
            max_inflight_bytes,
            max_age,
            budget: None,
        }
    }

    /// Build a reassembler that participates in a process-wide
    /// memory budget.
    pub fn with_budget(
        max_inflight_bytes: usize,
        max_age: Duration,
        budget: std::sync::Arc<ReassemblyBudget>,
    ) -> Self {
        Self {
            map: HashMap::new(),
            max_inflight_bytes,
            max_age,
            budget: Some(budget),
        }
    }

    /// Feed a shard into the reassembler.
    ///
    /// Behaviour:
    /// - `MORE`-flagged: append to the per-conn buffer; return Pending.
    /// - last shard: concatenate buffered + this; return Complete.
    /// - oversize: drop the buffered bytes and return Overflow so the
    ///   caller can issue a `ConnClose`/`Fault`.
    pub fn feed(&mut self, frame: Frame) -> ReassemblyOutcome {
        let has_more = (frame.flags & flags::MORE) != 0;
        let conn_id = frame.conn_id;
        let payload = frame.payload;

        if !has_more {
            if let Some(pending) = self.map.remove(&conn_id) {
                self.release_budget(pending.bytes);
                let total = pending.bytes + payload.len();
                if total > self.max_inflight_bytes {
                    return ReassemblyOutcome::Overflow;
                }
                let mut buf = bytes::BytesMut::with_capacity(total);
                for c in pending.chunks {
                    buf.extend_from_slice(&c);
                }
                buf.extend_from_slice(&payload);
                return ReassemblyOutcome::Complete(buf.freeze());
            }
            return ReassemblyOutcome::Complete(payload);
        }

        // Per-stream cap first — cheap and avoids touching the shared
        // budget atomic for streams that would have failed anyway.
        let already = self.map.get(&conn_id).map(|p| p.bytes).unwrap_or(0);
        if already + payload.len() > self.max_inflight_bytes {
            if let Some(pending) = self.map.remove(&conn_id) {
                self.release_budget(pending.bytes);
            }
            return ReassemblyOutcome::Overflow;
        }
        // Reserve from the global budget. If the cap is hit we drop
        // any partial state for this conn_id so the per-stream cap
        // and global cap can't disagree about how much memory is in
        // flight.
        if !self.try_reserve_budget(payload.len()) {
            if let Some(pending) = self.map.remove(&conn_id) {
                self.release_budget(pending.bytes);
            }
            return ReassemblyOutcome::Overflow;
        }
        let entry = self.map.entry(conn_id).or_insert_with(|| Pending {
            chunks: Vec::new(),
            bytes: 0,
            deadline: Instant::now() + self.max_age,
        });
        entry.bytes += payload.len();
        entry.chunks.push(payload);
        ReassemblyOutcome::Pending
    }

    /// Forget any in-flight buffer for this stream (e.g. on `ConnClose`).
    pub fn discard(&mut self, conn_id: u64) {
        if let Some(pending) = self.map.remove(&conn_id) {
            self.release_budget(pending.bytes);
        }
    }

    /// Drop every in-flight reassembly. Used when an entire mux session
    /// is being torn down (replace_online / clear_online_if_owner) so
    /// the previous session does not pin memory after its tasks exit.
    pub fn drain_all(&mut self) {
        let total: usize = self.map.values().map(|p| p.bytes).sum();
        self.map.clear();
        self.release_budget(total);
    }

    /// Drop reassemblies whose deadline has passed. Returns the list of
    /// timed-out conn_ids so the caller can `ConnClose` them.
    pub fn sweep_expired(&mut self, now: Instant) -> Vec<u64> {
        let expired: Vec<u64> = self
            .map
            .iter()
            .filter_map(|(k, v)| if v.deadline <= now { Some(*k) } else { None })
            .collect();
        for k in &expired {
            if let Some(pending) = self.map.remove(k) {
                self.release_budget(pending.bytes);
            }
        }
        expired
    }

    fn try_reserve_budget(&self, n: usize) -> bool {
        match &self.budget {
            Some(b) => b.try_reserve(n),
            None => true,
        }
    }

    fn release_budget(&self, n: usize) {
        if let Some(b) = &self.budget {
            b.release(n);
        }
    }

    /// Total buffered bytes across all in-flight reassemblies. Useful
    /// for the `mux_reassembly_bytes_inflight` gauge.
    pub fn inflight_bytes(&self) -> usize {
        self.map.values().map(|v| v.bytes).sum()
    }

    /// Number of streams currently in mid-reassembly.
    pub fn inflight_streams(&self) -> usize {
        self.map.len()
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        // Belt-and-braces: even if a caller forgets `drain_all`, we
        // still release the global budget when the reassembler goes
        // away. Per-stream `Pending` allocations are freed by the
        // standard `HashMap` drop.
        if self.budget.is_some() {
            let total: usize = self.map.values().map(|p| p.bytes).sum();
            self.release_budget(total);
        }
    }
}

// ---------------------------------------------------------------------------
// Weighted fair-share scheduler
// ---------------------------------------------------------------------------

/// Frame slot used by the [`Scheduler`]. Distinguishes "this frame must
/// jump the queue" from "this frame belongs to stream `conn_id`".
#[derive(Debug)]
pub enum SchedFrame {
    /// Control / housekeeping frames (Ping, Pong, WindowUpdate, GoAway,
    /// Register, RegisterAck, ConfigPush, ConfigAck, ConnReady, ConnClose,
    /// Fault, LaneHello). They jump the round-robin so they cannot be
    /// starved by data streams.
    HighPriority(Frame),
    /// Data frames (DataTcp/DataUdp). They are queued per `conn_id` and
    /// served in deficit-round-robin order.
    Stream { conn_id: u64, frame: Frame },
}

/// Decide whether a frame should bypass round-robin. Mirrors the
/// classification used by both the client and server writer.
pub fn classify(frame: Frame) -> SchedFrame {
    match frame.msg_type {
        MessageType::DataTcp | MessageType::DataUdp => SchedFrame::Stream {
            conn_id: frame.conn_id,
            frame,
        },
        _ => SchedFrame::HighPriority(frame),
    }
}

/// Deterministic weighted round-robin scheduler.
///
/// Each stream maintains its own FIFO queue. The scheduler walks the
/// active streams in insertion order and pops one frame at a time so a
/// single fat stream cannot monopolise a lane. High-priority frames
/// always drain first.
///
/// The scheduler is intentionally synchronous; the caller is responsible
/// for the async wakeup story (e.g. a [`tokio::sync::Notify`] paired
/// with a parking lot of awaiting writers).
pub struct Scheduler {
    high: VecDeque<Frame>,
    streams: HashMap<u64, VecDeque<Frame>>,
    /// Round-robin order over streams. Front is "next to serve".
    order: VecDeque<u64>,
    total_bytes: usize,
    total_frames: usize,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            high: VecDeque::new(),
            streams: HashMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            total_frames: 0,
        }
    }

    /// Enqueue a frame. The classifier decides which queue it lands in.
    pub fn push(&mut self, frame: Frame) {
        match classify(frame) {
            SchedFrame::HighPriority(f) => {
                self.total_bytes += f.payload.len();
                self.total_frames += 1;
                self.high.push_back(f);
            }
            SchedFrame::Stream { conn_id, frame } => {
                self.total_bytes += frame.payload.len();
                self.total_frames += 1;
                let q = self.streams.entry(conn_id).or_default();
                if q.is_empty() {
                    // Just-activated stream — append to the round-robin.
                    self.order.push_back(conn_id);
                }
                q.push_back(frame);
            }
        }
    }

    /// Pop the next frame in fair-share order, or `None` if empty.
    pub fn pop(&mut self) -> Option<Frame> {
        if let Some(f) = self.high.pop_front() {
            self.total_bytes = self.total_bytes.saturating_sub(f.payload.len());
            self.total_frames = self.total_frames.saturating_sub(1);
            return Some(f);
        }
        for _ in 0..self.order.len() {
            let conn_id = self.order.pop_front()?;
            let q_empty;
            let frame_opt = match self.streams.get_mut(&conn_id) {
                Some(q) => {
                    let f = q.pop_front();
                    q_empty = q.is_empty();
                    f
                }
                None => {
                    q_empty = true;
                    None
                }
            };
            match frame_opt {
                Some(f) => {
                    if !q_empty {
                        // Still has work; re-enqueue at the back.
                        self.order.push_back(conn_id);
                    } else {
                        self.streams.remove(&conn_id);
                    }
                    self.total_bytes = self.total_bytes.saturating_sub(f.payload.len());
                    self.total_frames = self.total_frames.saturating_sub(1);
                    return Some(f);
                }
                None => {
                    // Empty stream — drop it and continue searching.
                    self.streams.remove(&conn_id);
                }
            }
        }
        None
    }

    /// Drop everything queued for a given stream. Used when the stream
    /// is closed mid-flight (e.g. the receiver hit Overflow).
    pub fn drop_stream(&mut self, conn_id: u64) {
        if let Some(q) = self.streams.remove(&conn_id) {
            let bytes: usize = q.iter().map(|f| f.payload.len()).sum();
            self.total_bytes = self.total_bytes.saturating_sub(bytes);
            self.total_frames = self.total_frames.saturating_sub(q.len());
        }
        self.order.retain(|id| *id != conn_id);
    }

    pub fn is_empty(&self) -> bool {
        self.total_frames == 0
    }

    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    pub fn queued_bytes(&self) -> usize {
        self.total_bytes
    }
}

// ---------------------------------------------------------------------------
// Convenience builders for the new control frames
// ---------------------------------------------------------------------------

/// Build a `WindowUpdate` frame for the given stream.
pub fn window_update_frame(conn_id: u64, increment: u32) -> Frame {
    WindowUpdate::new(increment).to_frame(conn_id)
}

// ---------------------------------------------------------------------------
// Per-stream credit-based flow control
// ---------------------------------------------------------------------------

/// Reason the sender side abandoned a credit acquire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditError {
    /// The stream was closed (peer ConnClose, local cancel, etc.).
    /// Caller should give up and not emit any further frames.
    Closed,
}

/// Per-stream credit window.
///
/// The send side maintains a [`Semaphore`] whose permits represent the
/// number of bytes the local end is allowed to put on the wire before
/// the peer must replenish credit via a [`WindowUpdate`]. The receive
/// side counts bytes delivered upstream and emits a [`WindowUpdate`]
/// once the unacked total crosses [`StreamCredit::update_threshold`].
///
/// Both halves are independent and lock-free in the fast path.
pub struct StreamCredit {
    sem: Semaphore,
    recv_unacked: AtomicU32,
    update_threshold: u32,
}

impl StreamCredit {
    pub fn new(initial_window: u32) -> Self {
        // 0 would deadlock immediately; otherwise honour the caller's
        // sizing so unit tests can drive small windows on purpose.
        let initial = initial_window.max(1);
        // Replenish at half-window so we don't ping the peer with
        // tiny WindowUpdates but also don't let the sender stall.
        let update_threshold = (initial / 2).max(1);
        Self {
            sem: Semaphore::new(initial as usize),
            recv_unacked: AtomicU32::new(0),
            update_threshold,
        }
    }

    /// Block until at least `n` bytes of credit are available, then
    /// consume them. Returns [`CreditError::Closed`] if the stream was
    /// shut down while we were waiting.
    pub async fn acquire_send(&self, n: usize) -> Result<(), CreditError> {
        if n == 0 {
            return Ok(());
        }
        match self.sem.acquire_many(n as u32).await {
            Ok(p) => {
                p.forget();
                Ok(())
            }
            Err(_) => Err(CreditError::Closed),
        }
    }

    /// Replenish send-side credit (in response to an inbound
    /// `WindowUpdate`). Wakes any waiters.
    pub fn add_send_credit(&self, inc: u32) {
        if inc > 0 {
            self.sem.add_permits(inc as usize);
        }
    }

    /// Record that `n` bytes were delivered upstream by the receiver.
    /// Returns `Some(inc)` when the accumulated unacked total has
    /// crossed the update threshold and a `WindowUpdate(inc)` should
    /// be emitted; the internal counter is reset atomically in the
    /// same operation.
    pub fn record_received(&self, n: usize) -> Option<u32> {
        if n == 0 {
            return None;
        }
        let n32 = u32::try_from(n).unwrap_or(u32::MAX);
        let prev = self.recv_unacked.fetch_add(n32, Ordering::AcqRel);
        let cur = prev.saturating_add(n32);
        if cur >= self.update_threshold {
            // Snapshot whatever's accumulated so far. A racing producer
            // that lost the swap simply rolls its own bytes into the
            // *next* threshold crossing — at worst a slightly delayed
            // WindowUpdate.
            let inc = self.recv_unacked.swap(0, Ordering::AcqRel);
            if inc > 0 {
                return Some(inc);
            }
        }
        None
    }

    /// Close the credit. Any pending and future `acquire_send` calls
    /// return [`CreditError::Closed`]. Used on `ConnClose`/`Fault` so
    /// senders parked on credit don't dangle forever.
    pub fn close(&self) {
        self.sem.close();
    }

    pub fn available_send_credit(&self) -> usize {
        self.sem.available_permits()
    }

    pub fn pending_recv_unacked(&self) -> u32 {
        self.recv_unacked.load(Ordering::Acquire)
    }

    pub fn update_threshold(&self) -> u32 {
        self.update_threshold
    }
}

/// Per-control-connection map of [`StreamCredit`] keyed by `conn_id`.
///
/// The map is intentionally `tokio::sync::Mutex` free — concurrency is
/// achieved via `DashMap`-like semantics over `std::sync::Mutex`. The
/// hot path (acquire/release credit) holds neither.
pub struct CreditMap {
    inner: std::sync::Mutex<HashMap<u64, Arc<StreamCredit>>>,
    initial_window: AtomicU32,
}

impl CreditMap {
    pub fn new(initial_window: u32) -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
            initial_window: AtomicU32::new(initial_window.max(1)),
        }
    }

    /// Update the per-stream initial credit. Only affects streams
    /// created after this call (existing streams keep their windows).
    /// Used after `RegisterAck` to apply the negotiated value.
    pub fn set_initial_window(&self, w: u32) {
        self.initial_window.store(w.max(1), Ordering::Release);
    }

    /// Lookup-or-create. The first caller to touch a stream sizes its
    /// credit by the negotiated `initial_window`.
    pub fn get_or_create(&self, conn_id: u64) -> Arc<StreamCredit> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            g.entry(conn_id)
                .or_insert_with(|| Arc::new(StreamCredit::new(self.initial_window.load(Ordering::Acquire)))),
        )
    }

    /// Lookup without creating. Returns `None` if the stream isn't
    /// tracked yet (e.g. WindowUpdate arrived before any data flowed).
    pub fn get(&self, conn_id: u64) -> Option<Arc<StreamCredit>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&conn_id)
            .cloned()
    }

    /// Drop the credit for a stream and wake any senders blocked on
    /// it with [`CreditError::Closed`].
    pub fn remove(&self, conn_id: u64) {
        let removed = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.remove(&conn_id)
        };
        if let Some(c) = removed {
            c.close();
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Close every per-stream credit semaphore and drop the entries.
    /// Used during session teardown so any task parked on
    /// `acquire_send` wakes up with [`CreditError::Closed`] immediately
    /// instead of waiting for the next replenishment that will never
    /// arrive.
    pub fn close_all(&self) {
        let creds: Vec<Arc<StreamCredit>> = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.drain().map(|(_, v)| v).collect()
        };
        for c in creds {
            c.close();
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-lane sender abstraction
// ---------------------------------------------------------------------------

use tokio::sync::{mpsc, RwLock};

/// A handle that fans `Frame`s out across N physical TCP lanes.
///
/// Lane selection rules:
/// - Data frames (`DataTcp` / `DataUdp`) use sticky `conn_id % expected`
///   so a single logical stream's frames always land on the same lane
///   and thus stay in order.
/// - Control frames (everything else) always go to lane 0 so heartbeats
///   and registration acks travel on a known lane.
///
/// Slots are pre-allocated to the expected lane count and start as
/// `None`. Lanes are filled in via [`Self::set_lane`] as `LaneHello`
/// frames arrive. While a target slot is still empty (or its sender has
/// already closed) routing falls back to lane 0 — this keeps frames
/// flowing during the brief lane-attach window without ever silently
/// dropping into a dead channel.
#[derive(Clone)]
pub struct MuxSender {
    inner: Arc<RwLock<Vec<Option<mpsc::Sender<Frame>>>>>,
}

impl MuxSender {
    /// Build a single-lane sender. Equivalent to
    /// `with_capacity(lane0, 1)`.
    pub fn new(lane0: mpsc::Sender<Frame>) -> Self {
        Self::with_capacity(lane0, 1)
    }

    /// Pre-allocate `expected` lane slots, with lane 0 already
    /// attached. Slots `1..expected` start empty and are filled in by
    /// [`Self::set_lane`].
    pub fn with_capacity(lane0: mpsc::Sender<Frame>, expected: usize) -> Self {
        let n = expected.max(1);
        let mut v: Vec<Option<mpsc::Sender<Frame>>> = (0..n).map(|_| None).collect();
        v[0] = Some(lane0);
        Self {
            inner: Arc::new(RwLock::new(v)),
        }
    }

    /// Number of lane slots (attached or pending).
    pub async fn lane_count(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Number of slots whose sender has been attached.
    pub async fn attached_count(&self) -> usize {
        self.inner.read().await.iter().filter(|s| s.is_some()).count()
    }

    /// Append an additional lane slot. Returns the new lane's index.
    /// Useful when the expected lane count grows after construction
    /// (e.g. server side appending a lane discovered via `LaneHello`
    /// without `with_capacity` having been called).
    pub async fn push_lane(&self, tx: mpsc::Sender<Frame>) -> usize {
        let mut g = self.inner.write().await;
        g.push(Some(tx));
        g.len() - 1
    }

    /// Attach `tx` at slot `idx`, growing the vector with empty slots
    /// if needed. Replaces any existing sender at that slot.
    pub async fn set_lane(&self, idx: usize, tx: mpsc::Sender<Frame>) {
        let mut g = self.inner.write().await;
        while g.len() <= idx {
            g.push(None);
        }
        g[idx] = Some(tx);
    }

    /// Mark slot `idx` as unattached so subsequent routing falls back
    /// to lane 0. Idempotent and safe to call from a lane reader's
    /// shutdown path. No-op if `idx` is past the end.
    pub async fn clear_lane(&self, idx: usize) {
        let mut g = self.inner.write().await;
        if let Some(slot) = g.get_mut(idx) {
            *slot = None;
        }
    }

    /// Send `frame` to its routed lane. Awaits backpressure. Returns
    /// `Err` only if every viable target lane (including lane 0
    /// fallback) is closed.
    pub async fn send(&self, frame: Frame) -> Result<(), mpsc::error::SendError<Frame>> {
        let lane = self.pick(&frame).await?;
        lane.send(frame).await
    }

    /// True if every attached lane is closed.
    pub async fn is_closed(&self) -> bool {
        let g = self.inner.read().await;
        g.iter().all(|s| match s {
            Some(tx) => tx.is_closed(),
            None => true,
        })
    }

    /// Resolve the target lane for `frame`. Falls back to lane 0 if the
    /// preferred lane is unattached or closed. Returns `Err` carrying
    /// the original frame when no lane can take it.
    async fn pick(&self, frame: &Frame) -> Result<mpsc::Sender<Frame>, mpsc::error::SendError<Frame>> {
        let g = self.inner.read().await;
        let n = g.len();
        let preferred = Self::lane_for(frame, n);
        if let Some(tx) = g.get(preferred).and_then(|s| s.as_ref()) {
            if !tx.is_closed() {
                return Ok(tx.clone());
            }
        }
        // Fallback: lane 0 (always exists, may also be closed in
        // which case we surface SendError so the caller can react).
        if let Some(tx) = g.first().and_then(|s| s.as_ref()) {
            if !tx.is_closed() {
                return Ok(tx.clone());
            }
        }
        // No usable lane — the entire mux is gone. We have to fabricate
        // a SendError; we can't move `frame` here so use a placeholder
        // empty payload. Callers only inspect the variant, not the
        // contents.
        Err(mpsc::error::SendError(Frame {
            msg_type: frame.msg_type,
            flags: frame.flags,
            conn_id: frame.conn_id,
            payload: Bytes::new(),
        }))
    }

    fn lane_for(frame: &Frame, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        match frame.msg_type {
            MessageType::DataTcp | MessageType::DataUdp => (frame.conn_id as usize) % n,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Tokio-side helpers for the per-lane writer task
// ---------------------------------------------------------------------------

/// Greedily drain everything currently waiting on `rx` into the
/// scheduler. Used by the writer task right before popping so a single
/// fat stream cannot keep its frames at the front of the mpsc and
/// starve a recently-activated peer.
///
/// Returns the number of frames moved into the scheduler.
pub fn drain_into_scheduler(sched: &mut Scheduler, rx: &mut mpsc::Receiver<Frame>) -> usize {
    let mut n = 0;
    while let Ok(frame) = rx.try_recv() {
        sched.push(frame);
        n += 1;
    }
    n
}

/// Cooperative `next_frame` helper for the writer task.
///
/// Pops the next frame in fair-share order, blocking on `rx` only when
/// the scheduler is empty so we don't starve while data is sitting in
/// the channel. Returns `None` when the producer side is closed.
pub async fn next_scheduled_frame(
    sched: &mut Scheduler,
    rx: &mut mpsc::Receiver<Frame>,
) -> Option<Frame> {
    drain_into_scheduler(sched, rx);
    if let Some(f) = sched.pop() {
        return Some(f);
    }
    let first = rx.recv().await?;
    sched.push(first);
    drain_into_scheduler(sched, rx);
    sched.pop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::DataTcp;

    fn data_frame(conn_id: u64, n: usize) -> Frame {
        let buf = vec![0xABu8; n];
        DataTcp::new(Bytes::from(buf)).to_frame(conn_id)
    }

    #[test]
    fn frame_shard_marks_more_until_last() {
        let payload = Bytes::from(vec![0xAAu8; 5_000]);
        let shards: Vec<Frame> = FrameShard::new(MessageType::DataTcp, 1, payload, 1024).collect();
        assert_eq!(shards.len(), 5); // 1024*4 + 904
        for (i, s) in shards.iter().enumerate() {
            assert_eq!(s.msg_type, MessageType::DataTcp);
            if i == shards.len() - 1 {
                assert_eq!(s.flags & flags::MORE, 0);
            } else {
                assert_ne!(s.flags & flags::MORE, 0);
            }
        }
        let total: usize = shards.iter().map(|s| s.payload.len()).sum();
        assert_eq!(total, 5_000);
    }

    #[test]
    fn frame_shard_empty_payload_emits_one_frame() {
        let shards: Vec<Frame> =
            FrameShard::new(MessageType::DataTcp, 7, Bytes::new(), 1024).collect();
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0].payload.len(), 0);
        assert_eq!(shards[0].flags & flags::MORE, 0);
    }

    #[test]
    fn frame_shard_extra_flags_combined_with_more() {
        let shards: Vec<Frame> =
            FrameShard::new(MessageType::DataTcp, 1, Bytes::from(vec![0u8; 3000]), 1024)
                .with_extra_flags(flags::FIN)
                .collect();
        // Last shard should carry FIN AND not MORE.
        let last = shards.last().unwrap();
        assert_ne!(last.flags & flags::FIN, 0);
        assert_eq!(last.flags & flags::MORE, 0);
        // Intermediate shards should carry FIN AND MORE.
        for s in &shards[..shards.len() - 1] {
            assert_ne!(s.flags & flags::FIN, 0);
            assert_ne!(s.flags & flags::MORE, 0);
        }
    }

    #[test]
    fn reassembler_concatenates_in_order() {
        let mut r = Reassembler::new(1 << 20, Duration::from_secs(5));
        let payload = Bytes::from(vec![0x55u8; 4_000]);
        let shards: Vec<Frame> = FrameShard::new(MessageType::DataTcp, 9, payload.clone(), 1000)
            .collect();
        for (i, s) in shards.iter().enumerate() {
            match r.feed(s.clone()) {
                ReassemblyOutcome::Pending => assert!(i < shards.len() - 1),
                ReassemblyOutcome::Complete(b) => {
                    assert_eq!(i, shards.len() - 1);
                    assert_eq!(b, payload);
                }
                ReassemblyOutcome::Overflow => panic!("unexpected overflow"),
            }
        }
        assert_eq!(r.inflight_streams(), 0);
        assert_eq!(r.inflight_bytes(), 0);
    }

    #[test]
    fn reassembler_overflow_resets_stream() {
        let mut r = Reassembler::new(2_000, Duration::from_secs(5));
        let payload = Bytes::from(vec![0u8; 4_000]);
        let shards: Vec<Frame> = FrameShard::new(MessageType::DataTcp, 3, payload, 1500).collect();
        let mut hit_overflow = false;
        for s in shards {
            if let ReassemblyOutcome::Overflow = r.feed(s) {
                hit_overflow = true;
                break;
            }
        }
        assert!(hit_overflow);
        assert_eq!(r.inflight_streams(), 0);
    }

    #[test]
    fn reassembly_budget_blocks_when_exceeded_and_releases_on_complete() {
        let budget = ReassemblyBudget::new(8);
        let mut r = Reassembler::with_budget(1024, Duration::from_secs(60), budget.clone());
        let mk = |conn: u64, payload: &'static [u8], more: bool| Frame {
            msg_type: MessageType::DataTcp,
            flags: if more { flags::MORE } else { 0 },
            conn_id: conn,
            payload: Bytes::from_static(payload),
        };

        // 5 bytes consumed of the 8-byte global cap.
        assert!(matches!(r.feed(mk(1, b"hello", true)), ReassemblyOutcome::Pending));
        assert_eq!(budget.used(), 5);

        // Another 4-byte MORE shard (on a different conn) would push
        // us to 9 and must be rejected.
        assert!(matches!(r.feed(mk(2, b"abcd", true)), ReassemblyOutcome::Overflow));
        assert_eq!(budget.used(), 5, "rejected reservation must not stick");

        // Completing conn 1 releases its 5-byte reservation.
        assert!(matches!(r.feed(mk(1, b"!", false)), ReassemblyOutcome::Complete(_)));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembly_budget_released_on_drain_and_drop() {
        let budget = ReassemblyBudget::new(0); // unlimited cap, but still tracks usage
        {
            let mut r = Reassembler::with_budget(1024, Duration::from_secs(60), budget.clone());
            let f = Frame {
                msg_type: MessageType::DataTcp,
                flags: flags::MORE,
                conn_id: 7,
                payload: Bytes::from_static(b"chunk"),
            };
            let _ = r.feed(f);
            assert_eq!(budget.used(), 5);
            r.drain_all();
            assert_eq!(budget.used(), 0);
        }
        // Drop alone must not double-release.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembler_sweep_expired_drops_stale_buffers() {
        let mut r = Reassembler::new(1 << 20, Duration::from_millis(10));
        let f = Frame {
            msg_type: MessageType::DataTcp,
            flags: flags::MORE,
            conn_id: 5,
            payload: Bytes::from_static(b"abc"),
        };
        let _ = r.feed(f);
        std::thread::sleep(Duration::from_millis(20));
        let expired = r.sweep_expired(Instant::now());
        assert_eq!(expired, vec![5]);
        assert_eq!(r.inflight_streams(), 0);
    }

    #[test]
    fn scheduler_high_priority_wins() {
        let mut s = Scheduler::new();
        s.push(data_frame(1, 100));
        s.push(window_update_frame(1, 1024));
        s.push(data_frame(2, 100));
        let first = s.pop().unwrap();
        assert_eq!(first.msg_type, MessageType::WindowUpdate);
    }

    #[test]
    fn scheduler_round_robin_two_streams() {
        let mut s = Scheduler::new();
        for _ in 0..3 {
            s.push(data_frame(1, 10));
        }
        for _ in 0..3 {
            s.push(data_frame(2, 10));
        }
        let order: Vec<u64> = std::iter::from_fn(|| s.pop().map(|f| f.conn_id))
            .take(6)
            .collect();
        assert_eq!(order, vec![1, 2, 1, 2, 1, 2]);
    }

    #[test]
    fn scheduler_drop_stream_removes_pending() {
        let mut s = Scheduler::new();
        s.push(data_frame(1, 100));
        s.push(data_frame(1, 100));
        s.push(data_frame(2, 100));
        s.drop_stream(1);
        let order: Vec<u64> = std::iter::from_fn(|| s.pop().map(|f| f.conn_id)).collect();
        assert_eq!(order, vec![2]);
    }

    #[test]
    fn negotiate_uses_min_with_floor() {
        let p = MuxParams::negotiate(8, 32 * 1024, 1 << 20, 4, 16 * 1024, 256 * 1024);
        assert_eq!(p.lanes, 4);
        assert_eq!(p.max_frame_size, 16 * 1024);
        assert_eq!(p.initial_window, 256 * 1024);
    }

    #[test]
    fn negotiate_floors_below_min_frame_size() {
        let p = MuxParams::negotiate(2, 256, 4096, 4, 16 * 1024, 256 * 1024);
        assert_eq!(p.max_frame_size, MIN_MAX_FRAME_SIZE);
    }

    #[tokio::test]
    async fn next_scheduled_frame_prefers_control_then_round_robins() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame>(64);
        for _ in 0..3 {
            tx.send(data_frame(1, 10)).await.unwrap();
        }
        for _ in 0..3 {
            tx.send(data_frame(2, 10)).await.unwrap();
        }
        // Inject a high-priority frame after several stream frames are
        // already queued. It must come out first regardless.
        tx.send(window_update_frame(1, 4096)).await.unwrap();

        let mut sched = Scheduler::new();
        let first = next_scheduled_frame(&mut sched, &mut rx).await.unwrap();
        assert_eq!(first.msg_type, MessageType::WindowUpdate);

        // Remaining 6 data frames should alternate streams via RR.
        let mut order = Vec::new();
        for _ in 0..6 {
            let f = next_scheduled_frame(&mut sched, &mut rx).await.unwrap();
            order.push(f.conn_id);
        }
        assert_eq!(order, vec![1, 2, 1, 2, 1, 2]);
    }

    #[tokio::test]
    async fn stream_credit_acquire_blocks_until_replenished() {
        let credit = Arc::new(StreamCredit::new(8));
        // Drain the initial window.
        credit.acquire_send(8).await.unwrap();
        let c2 = Arc::clone(&credit);
        let waiter = tokio::spawn(async move { c2.acquire_send(4).await });
        // Should not have completed yet.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        credit.add_send_credit(4);
        let res = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("waiter wakes after credit replenished")
            .expect("join ok");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn stream_credit_close_wakes_blocked_sender() {
        let credit = Arc::new(StreamCredit::new(4));
        credit.acquire_send(4).await.unwrap();
        let c2 = Arc::clone(&credit);
        let waiter = tokio::spawn(async move { c2.acquire_send(8).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        credit.close();
        let res = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("waiter unblocks after close")
            .expect("join ok");
        assert_eq!(res, Err(CreditError::Closed));
    }

    #[test]
    fn stream_credit_record_received_emits_at_threshold() {
        let credit = StreamCredit::new(16); // threshold = 8
        assert_eq!(credit.record_received(4), None);
        // Crosses threshold (4 + 8 = 12 >= 8); returns the snapshot.
        let inc = credit.record_received(8).expect("threshold crossed");
        assert!(inc >= 8);
        assert_eq!(credit.pending_recv_unacked(), 0);
        // Sub-threshold afterwards: nothing.
        assert_eq!(credit.record_received(2), None);
    }

    #[tokio::test]
    async fn credit_map_per_stream_isolation() {
        let map = CreditMap::new(8);
        let a = map.get_or_create(1);
        let b = map.get_or_create(2);
        a.acquire_send(8).await.unwrap();
        // Stream 2 still has full credit.
        assert_eq!(b.available_send_credit(), 8);
        map.remove(1);
        // Subsequent lookups return None.
        assert!(map.get(1).is_none());
        assert!(map.get(2).is_some());
    }

    #[tokio::test]
    async fn mux_sender_routes_data_by_conn_id() {
        let (tx0, mut rx0) = tokio::sync::mpsc::channel::<Frame>(8);
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<Frame>(8);
        let m = MuxSender::new(tx0);
        m.push_lane(tx1).await;

        // Conn 1 -> lane 1, conn 2 -> lane 0.
        m.send(data_frame(1, 4)).await.unwrap();
        m.send(data_frame(2, 4)).await.unwrap();
        let f0 = rx0.recv().await.unwrap();
        let f1 = rx1.recv().await.unwrap();
        assert_eq!(f0.conn_id, 2);
        assert_eq!(f1.conn_id, 1);
    }

    #[tokio::test]
    async fn mux_sender_falls_back_to_lane_zero_when_target_unattached() {
        // 4 expected lanes, only lane 0 attached so far.
        let (tx0, mut rx0) = tokio::sync::mpsc::channel::<Frame>(8);
        let m = MuxSender::with_capacity(tx0, 4);
        // conn_id=2 would normally route to lane 2 (2 % 4 = 2), but
        // lane 2 is not yet attached → should fall back to lane 0.
        m.send(data_frame(2, 4)).await.unwrap();
        let f = rx0.recv().await.unwrap();
        assert_eq!(f.conn_id, 2);
    }

    #[tokio::test]
    async fn mux_sender_falls_back_when_target_closed() {
        let (tx0, mut rx0) = tokio::sync::mpsc::channel::<Frame>(8);
        let (tx1, rx1) = tokio::sync::mpsc::channel::<Frame>(8);
        let m = MuxSender::with_capacity(tx0, 2);
        m.set_lane(1, tx1).await;
        // Drop the lane-1 receiver to mark its sender closed.
        drop(rx1);
        // conn_id=1 → lane 1 normally; falls back to lane 0 since
        // lane 1 is now closed.
        m.send(data_frame(1, 4)).await.unwrap();
        let f = rx0.recv().await.unwrap();
        assert_eq!(f.conn_id, 1);
    }

    #[tokio::test]
    async fn mux_sender_clear_lane_routes_to_fallback() {
        let (tx0, mut rx0) = tokio::sync::mpsc::channel::<Frame>(8);
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<Frame>(8);
        let m = MuxSender::with_capacity(tx0, 2);
        m.set_lane(1, tx1).await;
        // Sanity: conn_id=1 routes to lane 1.
        m.send(data_frame(1, 4)).await.unwrap();
        assert_eq!(rx1.recv().await.unwrap().conn_id, 1);
        // Vacate lane 1 → subsequent conn_id=1 falls back to lane 0.
        m.clear_lane(1).await;
        m.send(data_frame(1, 4)).await.unwrap();
        assert_eq!(rx0.recv().await.unwrap().conn_id, 1);
        assert!(rx1.try_recv().is_err());
    }

    #[tokio::test]
    async fn mux_sender_send_errors_when_all_closed() {
        let (tx0, rx0) = tokio::sync::mpsc::channel::<Frame>(1);
        let m = MuxSender::new(tx0);
        drop(rx0);
        let err = m.send(data_frame(1, 4)).await.unwrap_err();
        assert_eq!(err.0.conn_id, 1);
    }

    #[tokio::test]
    async fn mux_sender_control_always_lane_zero() {
        let (tx0, mut rx0) = tokio::sync::mpsc::channel::<Frame>(8);
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<Frame>(8);
        let m = MuxSender::new(tx0);
        m.push_lane(tx1).await;
        m.send(window_update_frame(123, 1024)).await.unwrap();
        // Should land on lane 0 even though conn_id=123 % 2 = 1.
        let f = rx0.recv().await.unwrap();
        assert_eq!(f.msg_type, MessageType::WindowUpdate);
        assert!(rx1.try_recv().is_err());
    }

    #[tokio::test]
    async fn next_scheduled_frame_returns_none_when_closed_and_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame>(4);
        drop(tx);
        let mut sched = Scheduler::new();
        assert!(next_scheduled_frame(&mut sched, &mut rx).await.is_none());
    }

    #[test]
    fn negotiate_substitutes_zero_with_default() {
        let p = MuxParams::negotiate(0, 0, 0, 4, 16 * 1024, 256 * 1024);
        assert_eq!(p.lanes, 4);
        assert_eq!(p.max_frame_size, 16 * 1024);
        assert_eq!(p.initial_window, 256 * 1024);
    }
}
