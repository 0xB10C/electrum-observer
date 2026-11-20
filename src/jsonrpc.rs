//! Line-delimited JSON-RPC 2.0, stamped where the bytes arrive.
//!
//! Electrum is JSON-RPC 2.0 over a stream, one message per line, with
//! requests carrying a numeric `id` that the matching response repeats and
//! notifications carrying none. That is the whole wire format, and
//! DESIGN.md section 2 says why this crate speaks it itself rather than
//! through `electrum-client`: the number this tool exists to collect is *when
//! a line arrived*, to a resolution of tens of milliseconds, and a client
//! that only tells you when someone got round to polling for it has already
//! added more error than the signal.
//!
//! So the read loop here does one thing before anything else. It reads until
//! the newline that ends a line, takes `SystemTime::now()` the instant that
//! byte is in hand -- before the line is copied out of the buffer, before it
//! is parsed, before it is routed -- and carries that stamp on every
//! [`Response`] and [`Notification`] it hands out. Everything downstream, the
//! channels and the writer task of DESIGN.md section 3, is then free to be as
//! slow as it likes without moving a measurement.
//!
//! Two consequences shape the rest of the API.
//!
//! **A server error is data, not a failure.** DESIGN.md section 6 fingerprints
//! servers by the verbatim strings they return for deliberately malformed
//! requests, so an `error` object comes back as the `Err` side of
//! [`Response::outcome`] with its [`RpcError::raw`] kept exactly as it
//! arrived; only a broken connection, a timeout or a violated framing rule is
//! an [`Error`].
//!
//! **A hostile or merely sloppy server must not take the process with it.** A
//! line that is not JSON is counted and logged and the connection carries on,
//! because Electrum servers do occasionally emit a banner or a stray blank
//! line; a line longer than [`MAX_LINE_BYTES`] is not survivable in the same
//! way, because believing it means letting the other end choose how much
//! memory we allocate, so it closes the connection.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tracing::{debug, warn};

use crate::TARGET_JSONRPC;

/// The longest line this client will assemble, 16 MiB.
///
/// Every Electrum response that matters is kilobytes; the largest plausible
/// one, a `server.peers.subscribe` list or a fee histogram from a very full
/// mempool, is far below this. The cap is not a guess at the protocol but a
/// bound on what a server can make this process allocate: without it, a line
/// that never ends is a memory limit set by the other end of the socket.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// How many notifications may queue before the read loop waits.
///
/// Headers arrive one per block per server, so this only fills if the session
/// has stopped reading entirely; the stamp is already taken by then, and
/// waiting is better than dropping an announcement whose timing is the point.
const NOTIFICATION_CAPACITY: usize = 1024;

/// How much of an unparseable line is logged.
const PREVIEW_CHARS: usize = 200;

/// What can go wrong with a call, as opposed to what a server can answer.
///
/// A server replying "unknown method" is not in here: that is a successful
/// call whose [`Response::outcome`] is an [`RpcError`], and it is recorded
/// rather than retried. These four are the ways a call produces no answer at
/// all.
#[derive(Debug)]
pub enum Error {
    /// The socket failed while the request was being written.
    Io(std::io::Error),
    /// No answer within the configured request timeout
    /// (`timeouts.request_secs`). The pending entry is dropped, so a late
    /// answer is discarded rather than delivered to the next caller.
    Timeout,
    /// The connection is gone; the string is why, as the read loop saw it.
    Closed(String),
    /// The framing rule was broken, by the server or by the caller.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Timeout => write!(f, "the request timed out"),
            Error::Closed(reason) => write!(f, "the connection is closed: {reason}"),
            Error::Protocol(what) => write!(f, "protocol error: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// An `error` object as the server sent it.
///
/// The parsed fields are a convenience; [`raw`](Self::raw) is the point. Two
/// servers answering an unknown method with byte-identical JSON are running
/// the same software (DESIGN.md section 6), and that comparison is only sound
/// if nothing on the way in normalised the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    /// `error.code`, when there is one and it is an integer.
    pub code: Option<i64>,
    /// `error.message`, or the whole error rendered back to JSON when the
    /// server did not send one -- some send a bare string instead of an
    /// object, and that string is the message.
    pub message: String,
    /// `error.data`, which ElectrumX uses and others do not.
    pub data: Option<Value>,
    /// The error value exactly as it arrived.
    pub raw: Value,
}

impl RpcError {
    fn from_value(raw: Value) -> Self {
        let code = raw.get("code").and_then(Value::as_i64);
        let data = raw.get("data").cloned();
        let message = raw
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| raw.as_str())
            .map_or_else(|| raw.to_string(), str::to_owned);
        RpcError {
            code,
            message,
            data,
            raw,
        }
    }
}

/// One answer to one request.
///
/// Both stamps are from the same clock as every other session's, which is the
/// reason the whole collector is one process (DESIGN.md section 4); the
/// difference between them is the round trip that `pings.rtt_us` and
/// `probes.rtt_us` record.
#[derive(Clone, Debug)]
pub struct Response {
    /// The request id this answers.
    pub id: u64,
    /// When the request was written to the socket.
    pub sent_at: SystemTime,
    /// When the line carrying this response was read, taken at the newline.
    pub received_at: SystemTime,
    /// `result`, or the server's `error` object.
    pub outcome: Result<Value, RpcError>,
}

/// A message the server sent unprompted, which in practice is
/// `blockchain.headers.subscribe`.
///
/// `received_at` is the measurement of DESIGN.md section 1: the per-server
/// first-seen time of a block header, compared across servers to the
/// microsecond.
#[derive(Clone, Debug)]
pub struct Notification {
    /// The `method` field, e.g. `blockchain.headers.subscribe`.
    pub method: String,
    /// The `params` field, or `null` when there was none.
    pub params: Value,
    /// When the line was read, taken at the newline.
    pub received_at: SystemTime,
}

/// A line delivered to a [`Client::call_raw`] in flight, verbatim.
#[derive(Clone, Debug)]
pub struct RawLine {
    /// When the line was read, taken at the newline.
    pub received_at: SystemTime,
    /// The line as it arrived, without its newline, lossily decoded as UTF-8
    /// so that a server answering with invalid encoding is still recorded.
    pub text: String,
    /// The numeric ids found in it, in order; empty when the server answered
    /// with an id that is not a number, which is itself one of the
    /// fingerprints.
    pub ids: Vec<u64>,
}

/// The outcome of a [`Client::call_raw`].
#[derive(Clone, Debug)]
pub struct RawCall {
    /// When the line was written to the socket.
    pub sent_at: SystemTime,
    /// Every line the call collected, in arrival order.
    pub lines: Vec<RawLine>,
    /// Whether the wait ended because the expectation was met rather than
    /// because the request timeout elapsed or the connection closed.
    pub complete: bool,
}

/// The receiving end of the notification stream.
///
/// It ends when the connection does, so a session that selects on it learns
/// about a closed socket without polling anything else.
pub struct Notifications(mpsc::Receiver<Notification>);

impl Notifications {
    /// The next notification, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Notification> {
        self.0.recv().await
    }
}

/// What a caller waits for: a response body, minus the parts the caller
/// already knows.
#[derive(Debug)]
struct Reply {
    received_at: SystemTime,
    outcome: Result<Value, RpcError>,
}

/// State shared between the handles and the read loop.
struct Shared {
    /// The write half, boxed so that [`Client`] is not generic over the
    /// stream: a session holds one of these whether it dialed TCP, TLS or
    /// Tor, and the type of the socket is not its business.
    writer: tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>,
    /// Waiting calls by request id, or `None` once the connection has
    /// closed: taking the map is what fails every pending call at once, and
    /// what makes a later call fail immediately instead of waiting out the
    /// timeout.
    pending: Mutex<Option<HashMap<u64, oneshot::Sender<Reply>>>>,
    /// The sink for lines that answer nothing, installed while a
    /// [`Client::call_raw`] is in flight.
    raw: Mutex<Option<mpsc::UnboundedSender<RawLine>>>,
    next_id: AtomicU64,
    malformed: AtomicU64,
    request_timeout: Duration,
    /// Why the connection closed, once it has.
    closed: watch::Sender<Option<String>>,
    /// Raised when the last handle is dropped, so the read loop ends and the
    /// socket with it.
    stop: Notify,
}

impl Shared {
    fn close(&self, reason: String) {
        let pending = lock(&self.pending).take();
        lock(&self.raw).take();
        // The reason before the wakeups: a caller woken by its sender being
        // dropped reads the reason to build its `Closed`.
        self.closed.send_replace(Some(reason));
        drop(pending);
    }

    fn close_reason(&self) -> Option<String> {
        self.closed.borrow().clone()
    }
}

/// Dropped with the last [`Client`], which ends the read loop.
///
/// Without it a session that gives up on a server leaves a task reading a
/// socket nobody owns; with 450 servers reconnecting, that is the leak that
/// eventually runs the process out of descriptors.
struct StopOnDrop(Arc<Shared>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        // `notify_one` rather than `notify_waiters`, so that a read loop
        // which is between lines when this happens still sees it.
        self.0.stop.notify_one();
    }
}

/// A handle on one connection. Cloning it is how several tasks share one.
#[derive(Clone)]
pub struct Client {
    shared: Arc<Shared>,
    /// Never read: it exists so that the read loop learns when the last
    /// handle went away.
    _stop: Arc<StopOnDrop>,
}

impl Client {
    /// Takes over a connected stream and starts reading it.
    ///
    /// The returned [`Notifications`] is the only way to see unprompted
    /// messages; dropping it closes the connection the next time one arrives,
    /// because a session that is not listening for headers has nothing left
    /// to do with the socket.
    ///
    /// `request_timeout` is `timeouts.request_secs` from the configuration,
    /// and bounds one request rather than the connection (DESIGN.md section
    /// 8): a server that never answers one probe keeps its subscription.
    pub fn new<S>(stream: S, request_timeout: Duration) -> (Client, Notifications)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let (closed, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            writer: tokio::sync::Mutex::new(Box::new(writer)),
            pending: Mutex::new(Some(HashMap::new())),
            raw: Mutex::new(None),
            next_id: AtomicU64::new(1),
            malformed: AtomicU64::new(0),
            request_timeout,
            closed,
            stop: Notify::new(),
        });
        let (notifications_tx, notifications_rx) = mpsc::channel(NOTIFICATION_CAPACITY);
        tokio::spawn(read_loop(
            BufReader::new(reader),
            Arc::clone(&shared),
            notifications_tx,
        ));
        let client = Client {
            _stop: Arc::new(StopOnDrop(Arc::clone(&shared))),
            shared,
        };
        (client, Notifications(notifications_rx))
    }

    /// The next request id. Public because [`call_raw`](Self::call_raw)
    /// builds its own request lines and still has to use ids that no ordinary
    /// call will reuse.
    pub fn next_id(&self) -> u64 {
        self.shared.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// How many lines so far were not JSON. Logged as they happen; the count
    /// is what a session records about a server that talks nonsense without
    /// ever breaking the connection.
    pub fn malformed_lines(&self) -> u64 {
        self.shared.malformed.load(Ordering::Relaxed)
    }

    /// Resolves when the connection closes, with the reason.
    ///
    /// Already-closed connections resolve immediately, so a session can
    /// `select!` on this without racing the close it is waiting for.
    pub fn closed(&self) -> impl Future<Output = String> + Send + 'static {
        let shared = Arc::clone(&self.shared);
        async move {
            let mut changed = shared.closed.subscribe();
            loop {
                if let Some(reason) = shared.close_reason() {
                    return reason;
                }
                if changed.changed().await.is_err() {
                    // Unreachable while this future holds `shared`, which
                    // holds the sender.
                    return "closed".to_string();
                }
            }
        }
    }

    /// Sends one request and waits for the response with its id.
    ///
    /// Responses may arrive in any order and are matched by id, so several
    /// calls can be in flight on one connection -- which is what a probe set
    /// (DESIGN.md section 6) is: one set of requests written together and
    /// stamped as one row.
    pub async fn call(&self, method: &str, params: Value) -> Result<Response, Error> {
        let id = self.next_id();
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let waiter = self.register(id)?;
        let sent_at = match self.write_line(&request.to_string()).await {
            Ok(at) => at,
            Err(e) => {
                self.forget(id);
                return Err(e);
            }
        };
        match tokio::time::timeout(self.shared.request_timeout, waiter).await {
            Ok(Ok(reply)) => Ok(Response {
                id,
                sent_at,
                received_at: reply.received_at,
                outcome: reply.outcome,
            }),
            // The sender is dropped by `Shared::close` and by nothing else.
            Ok(Err(_)) => Err(Error::Closed(self.closed_reason())),
            Err(_) => {
                self.forget(id);
                Err(Error::Timeout)
            }
        }
    }

    /// Sends a pre-built line and collects the stamped lines that answer it.
    ///
    /// The escape hatch for the fingerprint set of DESIGN.md section 6, which
    /// is deliberately malformed requests: a JSON-RPC batch, a request whose
    /// `id` is not a number, a request with no `jsonrpc` field. None of those
    /// can be built by [`call`](Self::call), and the answers to some of them
    /// cannot be routed by id, because the id that comes back is whatever the
    /// server made of the one that went out.
    ///
    /// So routing is turned around: while this call is in flight, every line
    /// that answers *nothing* -- an unknown id, a non-numeric id, a line that
    /// is not JSON at all -- is handed to it verbatim and stamped, instead of
    /// being logged and dropped. Lines that do answer an ordinary [`call`]
    /// still go to that call, so a probe set running alongside is unaffected.
    ///
    /// `expect_ids` says when to stop early: the wait ends once every id in
    /// it has appeared in some line, which for a batch is both ids in the one
    /// array the server sends back. An empty `expect_ids` ends the wait at
    /// the first line, which is what the odd-id probes need, since the id
    /// that comes back cannot be predicted. Either way the request timeout
    /// bounds it, and `complete` says which way it ended.
    ///
    /// One raw call at a time per connection: a second overlapping one is an
    /// [`Error::Protocol`] rather than a silent split of the lines. The
    /// fingerprint set is once a day and sequential, and sharing an untyped
    /// sink between two callers would make "whose line was that" unanswerable.
    pub async fn call_raw(&self, line: &str, expect_ids: &[u64]) -> Result<RawCall, Error> {
        if line.contains('\n') {
            return Err(Error::Protocol(
                "a request line cannot contain a newline".to_string(),
            ));
        }
        let (lines_tx, mut lines_rx) = mpsc::unbounded_channel();
        {
            let mut slot = lock(&self.shared.raw);
            if slot.is_some() {
                return Err(Error::Protocol(
                    "another raw call is already in flight".to_string(),
                ));
            }
            *slot = Some(lines_tx);
        }
        // From here every exit, cancellation included, has to take the sink
        // back out again or no later raw call can install one.
        let _sink = SinkGuard(&self.shared);
        let sent_at = self.write_line(line).await?;

        let deadline = tokio::time::Instant::now() + self.shared.request_timeout;
        let mut lines: Vec<RawLine> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let complete = loop {
            let answered = if expect_ids.is_empty() {
                !lines.is_empty()
            } else {
                expect_ids.iter().all(|id| seen.contains(id))
            };
            if answered {
                break true;
            }
            match tokio::time::timeout_at(deadline, lines_rx.recv()).await {
                Ok(Some(line)) => {
                    seen.extend(line.ids.iter().copied());
                    lines.push(line);
                }
                // The sink was dropped: the connection closed under us.
                Ok(None) => break false,
                Err(_) => break false,
            }
        };
        Ok(RawCall {
            sent_at,
            lines,
            complete,
        })
    }

    fn register(&self, id: u64) -> Result<oneshot::Receiver<Reply>, Error> {
        let (tx, rx) = oneshot::channel();
        let mut guard = lock(&self.shared.pending);
        match guard.as_mut() {
            Some(pending) => {
                pending.insert(id, tx);
                Ok(rx)
            }
            None => {
                drop(guard);
                Err(Error::Closed(self.closed_reason()))
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Some(pending) = lock(&self.shared.pending).as_mut() {
            pending.remove(&id);
        }
    }

    fn closed_reason(&self) -> String {
        self.shared
            .close_reason()
            .unwrap_or_else(|| "closed".to_string())
    }

    /// Writes one line and returns the moment it went out, taken with the
    /// write lock already held so that `sent_at` is not the time this task
    /// started waiting for another one's write.
    async fn write_line(&self, line: &str) -> Result<SystemTime, Error> {
        if let Some(reason) = self.shared.close_reason() {
            return Err(Error::Closed(reason));
        }
        let mut framed = String::with_capacity(line.len() + 1);
        framed.push_str(line);
        framed.push('\n');
        let mut writer = self.shared.writer.lock().await;
        let sent_at = SystemTime::now();
        writer.write_all(framed.as_bytes()).await?;
        writer.flush().await?;
        Ok(sent_at)
    }
}

/// Removes the raw sink however [`Client::call_raw`] ends.
struct SinkGuard<'a>(&'a Shared);

impl Drop for SinkGuard<'_> {
    fn drop(&mut self) {
        lock(&self.0.raw).take();
    }
}

/// A mutex guard without the poisoning branch: every critical section in this
/// module is a map insertion or a take, so a panic inside one cannot leave
/// anything half-written, and failing a call because an unrelated task
/// panicked would hide the panic behind a connection error.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads lines until the connection or the last handle goes away.
async fn read_loop<R>(
    mut reader: BufReader<R>,
    shared: Arc<Shared>,
    notifications: mpsc::Sender<Notification>,
) where
    R: AsyncRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    let reason = loop {
        line.clear();
        let read = tokio::select! {
            read = read_line(&mut reader, &mut line) => read,
            () = shared.stop.notified() => break "the last client handle was dropped".to_string(),
        };
        let received_at = match read {
            Ok(Some(at)) => at,
            Ok(None) => break "eof".to_string(),
            Err(e) => break e.to_string(),
        };
        if !dispatch(&shared, &line, received_at, &notifications).await {
            break "the notification receiver was dropped".to_string();
        }
    };
    shared.close(reason);
}

/// Reads one line into `line`, and returns when its last byte arrived.
///
/// The stamp is taken the moment the newline is found in the buffer, which is
/// earlier than any caller could take one: the copy out of the buffer and the
/// return from this function both happen after it. `Ok(None)` is a clean end
/// of stream with nothing buffered; a final line without a newline is still a
/// line.
async fn read_line<R>(
    reader: &mut BufReader<R>,
    line: &mut Vec<u8>,
) -> Result<Option<SystemTime>, Error>
where
    R: AsyncRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                None
            } else {
                Some(SystemTime::now())
            });
        }
        // What is left of the cap. Nothing past the cap is ever copied into
        // `line`, so the subtraction cannot wrap.
        let room = MAX_LINE_BYTES - line.len();
        if let Some(end) = available.iter().position(|b| *b == b'\n') {
            let received_at = SystemTime::now();
            if end > room {
                return Err(oversize());
            }
            line.extend_from_slice(&available[..end]);
            reader.consume(end + 1);
            return Ok(Some(received_at));
        }
        let taken = available.len();
        if taken > room {
            return Err(oversize());
        }
        line.extend_from_slice(available);
        reader.consume(taken);
    }
}

fn oversize() -> Error {
    Error::Protocol(format!("a line longer than {MAX_LINE_BYTES} bytes"))
}

/// Routes one line. Returns false when the notification receiver is gone,
/// which ends the connection.
async fn dispatch(
    shared: &Shared,
    line: &[u8],
    received_at: SystemTime,
    notifications: &mpsc::Sender<Notification>,
) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        shared.malformed.fetch_add(1, Ordering::Relaxed);
        warn!(
            target: TARGET_JSONRPC,
            count = shared.malformed.load(Ordering::Relaxed),
            line = preview(line),
            "ignoring a line that is not JSON"
        );
        offer_raw(shared, line, received_at, Vec::new());
        return true;
    };
    // A batch reply is an array of the same objects, so both shapes are the
    // same loop.
    let elements: &[Value] = value
        .as_array()
        .map_or(std::slice::from_ref(&value), Vec::as_slice);
    let mut ids: Vec<u64> = Vec::new();
    let mut unrouted = elements.is_empty();
    for element in elements {
        match classify(element, received_at) {
            Message::Notification(notification) => {
                if notifications.send(notification).await.is_err() {
                    return false;
                }
            }
            Message::Response(id, reply) => {
                ids.push(id);
                if !deliver(shared, id, reply) {
                    debug!(target: TARGET_JSONRPC, id, "a response to an id nobody is waiting for");
                    unrouted = true;
                }
            }
            Message::Unknown => unrouted = true,
        }
    }
    if unrouted {
        offer_raw(shared, line, received_at, ids);
    }
    true
}

/// What one JSON value on the wire turned out to be.
enum Message {
    Notification(Notification),
    Response(u64, Reply),
    /// Neither: an id this client cannot have sent, or an object with no
    /// `result` and no `error`. Kept rather than discarded, because an
    /// unroutable answer is exactly what some fingerprint probes expect.
    Unknown,
}

fn classify(value: &Value, received_at: SystemTime) -> Message {
    let Some(object) = value.as_object() else {
        return Message::Unknown;
    };
    let id = object.get("id");
    // `jsonrpc` is not checked: some servers omit it, and a reply that is
    // otherwise well formed is not worth refusing over a missing constant.
    if let Some(method) = object.get("method").and_then(Value::as_str)
        && id.is_none_or(Value::is_null)
    {
        return Message::Notification(Notification {
            method: method.to_owned(),
            params: object.get("params").cloned().unwrap_or(Value::Null),
            received_at,
        });
    }
    let Some(id) = id.and_then(Value::as_u64) else {
        return Message::Unknown;
    };
    let outcome = if let Some(error) = object.get("error").filter(|e| !e.is_null()) {
        Err(RpcError::from_value(error.clone()))
    } else if let Some(result) = object.get("result") {
        Ok(result.clone())
    } else {
        return Message::Unknown;
    };
    Message::Response(
        id,
        Reply {
            received_at,
            outcome,
        },
    )
}

/// Hands a reply to the call waiting for it. False when there is none.
fn deliver(shared: &Shared, id: u64, reply: Reply) -> bool {
    let waiter = lock(&shared.pending)
        .as_mut()
        .and_then(|pending| pending.remove(&id));
    match waiter {
        // The receiver can be gone if the caller timed out in the moment
        // between the lookup and here; the answer is as dropped as it would
        // have been anyway, and the id was still ours.
        Some(tx) => {
            let _ = tx.send(reply);
            true
        }
        None => false,
    }
}

/// Offers a line that answers nothing to a raw call, if one is in flight.
fn offer_raw(shared: &Shared, line: &[u8], received_at: SystemTime, ids: Vec<u64>) {
    let slot = lock(&shared.raw);
    let Some(sink) = slot.as_ref() else {
        debug!(target: TARGET_JSONRPC, line = preview(line), "dropping a line that answers nothing");
        return;
    };
    let raw = RawLine {
        received_at,
        text: String::from_utf8_lossy(line).into_owned(),
        ids,
    };
    // The receiver outlives the sink -- `SinkGuard` takes the sink out when
    // the raw call ends, cancelled or not -- so a failed send is not a case
    // to handle, only one not to panic on.
    let _ = sink.send(raw);
}

/// A bounded, escaped prefix of a line, for a log field.
///
/// Both bounds matter: the line is a server's, so it can be a megabyte long
/// and can carry newlines and control characters that would otherwise make
/// one log line look like several.
fn preview(line: &[u8]) -> String {
    let text = String::from_utf8_lossy(line);
    let mut preview: String = text
        .chars()
        .take(PREVIEW_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if text.chars().nth(PREVIEW_CHARS).is_some() {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    use tokio::io::DuplexStream;

    /// How long any wait in these tests may take before it is a failure.
    ///
    /// Every await below is bounded by it, because a test that hangs says
    /// nothing: it is the same symptom whether the client lost a reply or the
    /// machine is slow, and a hung suite also means a mutation run that never
    /// ends. Generous, because these are in-memory pipes.
    const PATIENCE: Duration = Duration::from_secs(5);

    async fn soon<F: Future>(what: &str, future: F) -> F::Output {
        tokio::time::timeout(PATIENCE, future)
            .await
            .unwrap_or_else(|_| panic!("waited {PATIENCE:?} for {what}"))
    }

    /// The other end of the socket: reads what the client wrote, writes what
    /// a server would.
    struct Server {
        stream: BufReader<DuplexStream>,
    }

    impl Server {
        /// The next line the client sent, as JSON.
        async fn request(&mut self) -> Value {
            let line = self.line().await;
            serde_json::from_str(&line).expect("the client writes JSON")
        }

        async fn line(&mut self) -> String {
            let mut line = String::new();
            soon("a request", self.stream.read_line(&mut line))
                .await
                .expect("the client is connected");
            assert!(line.ends_with('\n'), "every request is one line: {line:?}");
            line.trim_end().to_string()
        }

        /// Writes `count` bytes that are not a newline, in chunks, so a test
        /// can build a line of a given length. Bounded like every other wait
        /// here: a client that has stopped reading fails the test rather
        /// than hanging it.
        async fn fill(&mut self, count: usize) {
            let chunk = vec![b'x'; 64 * 1024];
            let mut written = 0;
            while written < count {
                let take = chunk.len().min(count - written);
                soon(
                    "room to write",
                    self.stream.get_mut().write_all(&chunk[..take]),
                )
                .await
                .expect("the client is connected");
                written += take;
            }
        }

        async fn send(&mut self, line: &str) {
            self.stream
                .get_mut()
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("the client is connected");
        }
    }

    /// What a spawned call returned.
    async fn answer(
        call: tokio::task::JoinHandle<Result<Response, Error>>,
    ) -> Result<Response, Error> {
        soon("a call", call).await.expect("the task ran")
    }

    /// Calls in the background, so the test can play the server meanwhile.
    fn spawn_call(
        client: &Client,
        method: &'static str,
    ) -> tokio::task::JoinHandle<Result<Response, Error>> {
        let client = client.clone();
        tokio::spawn(async move { client.call(method, json!([])).await })
    }

    fn connect(request_timeout: Duration) -> (Client, Notifications, Server) {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (client, notifications) = Client::new(client_side, request_timeout);
        (
            client,
            notifications,
            Server {
                stream: BufReader::new(server_side),
            },
        )
    }

    fn pair() -> (Client, Notifications, Server) {
        connect(Duration::from_secs(30))
    }

    /// The handle is shared between a session's tasks, so it has to be both.
    #[test]
    fn client_is_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<Client>();
        assert::<Notifications>();
    }

    /// The cap is 16 MiB, as the documentation on it says: a server that
    /// could move it could choose this process's memory use.
    #[test]
    fn the_line_cap_is_sixteen_mebibytes() {
        assert_eq!(MAX_LINE_BYTES, 16_777_216);
    }

    #[tokio::test]
    async fn a_request_gets_its_reply() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");

        let request = server.request().await;
        assert_eq!(request["jsonrpc"], json!("2.0"));
        assert_eq!(request["method"], json!("server.ping"));
        assert_eq!(request["params"], json!([]));
        let id = request["id"].as_u64().expect("ids are numbers");
        server
            .send(&format!(r#"{{"jsonrpc":"2.0","id":{id},"result":"pong"}}"#))
            .await;

        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.id, id);
        assert_eq!(response.outcome, Ok(json!("pong")));
        assert!(response.sent_at <= response.received_at);
    }

    #[tokio::test]
    async fn replies_are_matched_by_id_not_by_order() {
        let (client, _notifications, mut server) = pair();
        let first = spawn_call(&client, "server.banner");
        let first_id = server.request().await["id"].as_u64().expect("an id");
        let second = spawn_call(&client, "blockchain.relayfee");
        let second_id = server.request().await["id"].as_u64().expect("an id");
        assert_ne!(first_id, second_id);

        // Answered the other way round.
        server
            .send(&format!(
                r#"{{"jsonrpc":"2.0","id":{second_id},"result":0.00001}}"#
            ))
            .await;
        server
            .send(&format!(
                r#"{{"jsonrpc":"2.0","id":{first_id},"result":"a banner"}}"#
            ))
            .await;

        let first = answer(first).await.expect("the call worked");
        let second = answer(second).await.expect("the call worked");
        assert_eq!(first.id, first_id);
        assert_eq!(first.outcome, Ok(json!("a banner")));
        assert_eq!(second.id, second_id);
        assert_eq!(second.outcome, Ok(json!(0.00001)));
    }

    #[tokio::test]
    async fn a_notification_is_stamped_on_arrival() {
        let (_client, mut notifications, mut server) = pair();

        let before = SystemTime::now();
        server
            .send(
                r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"hex":"00","height":900000}]}"#,
            )
            .await;
        let notification = soon("a notification", notifications.recv())
            .await
            .expect("a notification");
        let after = SystemTime::now();

        assert_eq!(notification.method, "blockchain.headers.subscribe");
        assert_eq!(notification.params[0]["height"], json!(900_000));
        assert!(
            notification.received_at >= before && notification.received_at <= after,
            "{:?} is outside {:?}..={:?}",
            notification.received_at,
            before,
            after
        );
    }

    #[tokio::test]
    async fn a_notification_without_params_is_still_one() {
        let (_client, mut notifications, mut server) = pair();
        server
            .send(r#"{"jsonrpc":"2.0","method":"nothing.happened"}"#)
            .await;
        let notification = soon("a notification", notifications.recv())
            .await
            .expect("a notification");
        assert_eq!(notification.method, "nothing.happened");
        assert_eq!(notification.params, Value::Null);
    }

    #[tokio::test]
    async fn a_notification_arrives_between_a_request_and_its_reply() {
        let (client, mut notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(r#"{"method":"blockchain.headers.subscribe","params":[{"height":1}]}"#)
            .await;
        server
            .send(&format!(r#"{{"id":{id},"result":null}}"#))
            .await;

        let notification = soon("a notification", notifications.recv())
            .await
            .expect("a notification");
        assert_eq!(notification.method, "blockchain.headers.subscribe");
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(Value::Null));
    }

    /// A reply with no `"jsonrpc"` field: several server implementations omit
    /// it, and refusing it would lose every measurement from those servers.
    #[tokio::test]
    async fn a_reply_without_the_jsonrpc_field_is_accepted() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
    }

    /// The reason there is an `outcome` rather than an error variant: this is
    /// the data the fingerprint set collects (DESIGN.md section 6).
    #[tokio::test]
    async fn a_server_error_is_data_and_not_a_failed_call() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "no.such.method");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(
                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"unknown method \"no.such.method\"","data":{{"extra":1}}}}}}"#
            ))
            .await;

        let response = answer(call).await.expect("the call worked");
        let error = response.outcome.expect_err("the server said no");
        assert_eq!(error.code, Some(-32601));
        assert_eq!(error.message, "unknown method \"no.such.method\"");
        assert_eq!(error.data, Some(json!({"extra": 1})));
        assert_eq!(
            error.raw,
            json!({"code": -32601, "message": "unknown method \"no.such.method\"", "data": {"extra": 1}}),
            "the error object is kept exactly as it arrived"
        );
    }

    /// Some servers answer with a bare string instead of an error object.
    #[tokio::test]
    async fn an_error_that_is_a_bare_string_keeps_the_string() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"error":"server busy"}}"#))
            .await;
        let error = answer(call)
            .await
            .expect("the call worked")
            .outcome
            .expect_err("the server said no");
        assert_eq!(error.code, None);
        assert_eq!(error.message, "server busy");
        assert_eq!(error.data, None);
        assert_eq!(error.raw, json!("server busy"));
    }

    /// An error object with nothing recognisable in it still has to produce a
    /// message, because `probes.error` is never empty for a failed probe.
    #[test]
    fn an_error_object_without_a_message_renders_itself() {
        let error = RpcError::from_value(json!({"oops": true}));
        assert_eq!(error.code, None);
        assert_eq!(error.message, r#"{"oops":true}"#);
        assert_eq!(error.raw, json!({"oops": true}));
    }

    /// Paused time, so that a thirty-second timeout costs nothing: every
    /// timer in the test fires in order and immediately.
    #[tokio::test(start_paused = true)]
    async fn a_call_times_out_and_forgets_itself() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");

        let error = call.await.expect("the task ran").expect_err("no answer");
        assert!(matches!(error, Error::Timeout), "{error:?}");
        assert!(
            lock(&client.shared.pending)
                .as_ref()
                .expect("still open")
                .is_empty(),
            "the pending entry is removed, so a late answer is dropped"
        );

        // The connection is still usable, and the late answer is ignored.
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let response = call.await.expect("the task ran").expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
    }

    #[tokio::test]
    async fn eof_fails_pending_calls_and_resolves_closed() {
        let (client, mut notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        server.request().await;
        drop(server);

        let error = answer(call).await.expect_err("no answer");
        assert!(
            matches!(&error, Error::Closed(reason) if reason == "eof"),
            "{error:?}"
        );
        assert_eq!(soon("the close", client.closed()).await, "eof");
        assert!(
            soon("the end of the stream", notifications.recv())
                .await
                .is_none(),
            "the stream ends too"
        );

        // And a call afterwards fails without waiting out the timeout.
        let error = soon(
            "a call on a closed connection",
            client.call("server.ping", json!([])),
        )
        .await
        .expect_err("the connection is gone");
        assert!(
            matches!(&error, Error::Closed(reason) if reason == "eof"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn closed_resolves_for_a_connection_that_already_closed() {
        let (client, _notifications, server) = pair();
        drop(server);
        assert_eq!(soon("the close", client.closed()).await, "eof");
        // Twice: it is not a one-shot, several tasks select on it.
        assert_eq!(soon("the close again", client.closed()).await, "eof");
    }

    /// Junk between messages is a banner or a bug, not a reason to drop a
    /// server that is otherwise answering.
    #[tokio::test]
    async fn a_line_that_is_not_json_is_counted_and_survived() {
        let (client, _notifications, mut server) = pair();
        server.send("Welcome to the server.\tEnjoy.").await;
        server.send("").await;

        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;

        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
        assert_eq!(client.malformed_lines(), 2);
    }

    /// A line without an end is a server choosing how much memory this
    /// process allocates, so it ends the connection.
    #[tokio::test]
    async fn an_oversize_line_closes_the_connection() {
        let (client, _notifications, mut server) = pair();
        tokio::spawn(async move {
            let chunk = vec![b'x'; 64 * 1024];
            // One chunk past the cap, and never a newline.
            for _ in 0..=(MAX_LINE_BYTES / chunk.len()) {
                if server.stream.get_mut().write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let reason = soon("the close", client.closed()).await;
        assert!(
            reason.contains(&format!("a line longer than {MAX_LINE_BYTES} bytes")),
            "{reason:?}"
        );
        assert_eq!(client.malformed_lines(), 0, "it was never parsed");
    }

    /// The same cap for a line that does end: the bytes that cross it are
    /// refused even though the newline is right behind them.
    #[tokio::test]
    async fn a_terminated_line_past_the_cap_closes_the_connection() {
        let (client, _notifications, mut server) = pair();
        server.fill(MAX_LINE_BYTES).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        // One byte past the cap, and then the newline that would have ended
        // it.
        server.send("x").await;

        let reason = soon("the close", client.closed()).await;
        assert!(
            reason.contains(&format!("a line longer than {MAX_LINE_BYTES} bytes")),
            "{reason:?}"
        );
    }

    /// The cap is a length and not an estimate: a line of exactly
    /// `MAX_LINE_BYTES` is read -- it is not JSON, so it is only counted --
    /// and the connection is still good afterwards.
    #[tokio::test]
    async fn a_line_of_exactly_the_cap_is_read() {
        let (client, _notifications, mut server) = pair();
        server.fill(MAX_LINE_BYTES).await;
        // Let the reader take all of it before the newline arrives, so that
        // the last read of the line is one that ends exactly on the cap.
        tokio::time::sleep(Duration::from_millis(20)).await;
        server.send("").await;

        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
        assert_eq!(
            client.malformed_lines(),
            1,
            "the line was read whole, and was not JSON"
        );
    }

    /// Unsolicited, or ours and already timed out: either way nobody is
    /// waiting, and the connection carries on.
    #[tokio::test]
    async fn a_response_to_an_unknown_id_is_dropped() {
        let (client, _notifications, mut server) = pair();
        server
            .send(r#"{"jsonrpc":"2.0","id":999999,"result":"nobody asked"}"#)
            .await;

        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
        assert_eq!(client.malformed_lines(), 0);
    }

    /// The batch of the fingerprint set: one line out, one array back, both
    /// ids answered in it.
    #[tokio::test]
    async fn a_raw_batch_comes_back_stamped() {
        let (client, _notifications, mut server) = pair();
        let first = client.next_id();
        let second = client.next_id();
        let batch = format!(
            r#"[{{"jsonrpc":"2.0","id":{first},"method":"server.ping","params":[]}},{{"jsonrpc":"2.0","id":{second},"method":"server.banner","params":[]}}]"#
        );

        let before = SystemTime::now();
        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call_raw(&batch, &[first, second]).await }
        });

        let sent = server.request().await;
        assert!(sent.is_array(), "the batch went out as one line: {sent}");
        server
            .send(&format!(
                r#"[{{"jsonrpc":"2.0","id":{first},"result":null}},{{"jsonrpc":"2.0","id":{second},"error":{{"code":-32601,"message":"no banner"}}}}]"#
            ))
            .await;

        let raw = soon("the raw call", call)
            .await
            .expect("the task ran")
            .expect("the call worked");
        let after = SystemTime::now();
        assert!(raw.complete);
        assert_eq!(raw.lines.len(), 1);
        assert_eq!(raw.lines[0].ids, vec![first, second]);
        assert!(raw.lines[0].text.contains("no banner"));
        assert!(raw.sent_at >= before);
        assert!(raw.lines[0].received_at >= raw.sent_at && raw.lines[0].received_at <= after);
    }

    /// The odd-id probe: the id that comes back cannot be predicted, so the
    /// call expects no ids and takes the first line it gets.
    #[tokio::test]
    async fn a_raw_call_with_no_expected_ids_takes_the_first_line() {
        let (client, _notifications, mut server) = pair();
        let call = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .call_raw(
                        r#"{"jsonrpc":"2.0","id":{"not":"a number"},"method":"server.ping","params":[]}"#,
                        &[],
                    )
                    .await
            }
        });
        server.request().await;
        server
            .send(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"bad id"}}"#)
            .await;

        let raw = soon("the raw call", call)
            .await
            .expect("the task ran")
            .expect("the call worked");
        assert!(raw.complete);
        assert_eq!(raw.lines.len(), 1);
        assert!(raw.lines[0].ids.is_empty(), "the server answered no id");
        assert!(raw.lines[0].text.contains("bad id"));
    }

    /// Even a reply that is not JSON reaches the raw caller: what an
    /// implementation does with a malformed request is the measurement.
    #[tokio::test]
    async fn a_raw_call_collects_a_line_that_is_not_json() {
        let (client, _notifications, mut server) = pair();
        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call_raw("not even json", &[]).await }
        });
        server.line().await;
        server.send("ERROR: go away").await;

        let raw = soon("the raw call", call)
            .await
            .expect("the task ran")
            .expect("the call worked");
        assert!(raw.complete);
        assert_eq!(raw.lines[0].text, "ERROR: go away");
        assert_eq!(client.malformed_lines(), 1);
    }

    /// An ordinary call running alongside a raw one still gets its own reply.
    #[tokio::test]
    async fn a_raw_call_does_not_steal_an_ordinary_reply() {
        let (client, _notifications, mut server) = pair();
        let raw_id = client.next_id();
        let raw = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .call_raw(
                        &format!(r#"{{"id":{raw_id},"method":"server.ping"}}"#),
                        &[raw_id],
                    )
                    .await
            }
        });
        server.request().await;
        let call = spawn_call(&client, "server.banner");
        let call_id = server.request().await["id"].as_u64().expect("an id");

        server
            .send(&format!(r#"{{"id":{call_id},"result":"a banner"}}"#))
            .await;
        server
            .send(&format!(r#"{{"id":{raw_id},"result":"pong"}}"#))
            .await;

        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("a banner")));
        let raw = soon("the raw call", raw)
            .await
            .expect("the task ran")
            .expect("the call worked");
        assert_eq!(raw.lines.len(), 1, "only the unroutable line");
        assert_eq!(raw.lines[0].ids, vec![raw_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_raw_call_that_is_never_answered_is_incomplete() {
        let (client, _notifications, mut server) = pair();
        let id = client.next_id();
        let call = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .call_raw(&format!(r#"{{"id":{id},"method":"server.ping"}}"#), &[id])
                    .await
            }
        });
        server.line().await;

        let raw = call.await.expect("the task ran").expect("the call worked");
        assert!(!raw.complete);
        assert!(raw.lines.is_empty());
        assert!(
            lock(&client.shared.raw).is_none(),
            "the sink is removed, so the next raw call can install one"
        );
    }

    /// A server that hangs up in the middle of a fingerprint probe: the call
    /// ends with whatever it collected, and the session hears about the
    /// close where it hears about every other one.
    #[tokio::test]
    async fn a_raw_call_ends_when_the_connection_does() {
        let (client, _notifications, mut server) = pair();
        let id = client.next_id();
        let call = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .call_raw(&format!(r#"{{"id":{id},"method":"server.ping"}}"#), &[id])
                    .await
            }
        });
        server.line().await;
        drop(server);

        let raw = soon("the raw call", call)
            .await
            .expect("the task ran")
            .expect("the line went out");
        assert!(!raw.complete);
        assert!(raw.lines.is_empty());
        assert_eq!(soon("the close", client.closed()).await, "eof");
    }

    #[tokio::test]
    async fn two_raw_calls_at_once_are_refused() {
        let (client, _notifications, mut server) = connect(Duration::from_millis(50));
        let line = r#"{"id":1,"method":"server.ping"}"#;
        let (first, second) = soon(
            "both raw calls",
            futures_join(client.call_raw(line, &[1]), client.call_raw(line, &[2])),
        )
        .await;
        assert!(first.expect("the first one was installed").lines.is_empty());
        let error = second.expect_err("only one at a time");
        assert!(
            matches!(&error, Error::Protocol(what) if what.contains("already in flight")),
            "{error:?}"
        );
        assert_eq!(server.line().await, line, "only the first went out");
    }

    /// `tokio::join!` as a function, so it can be handed to [`soon`].
    async fn futures_join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
        tokio::join!(a, b)
    }

    /// A line with a newline in it would be two messages on the wire, and the
    /// caller would be waiting for an answer to a request it did not make.
    #[tokio::test]
    async fn a_raw_line_with_a_newline_is_refused() {
        let (client, _notifications, _server) = pair();
        let error = client
            .call_raw("{\"id\":1}\n{\"id\":2}", &[])
            .await
            .expect_err("that is two lines");
        assert!(
            matches!(&error, Error::Protocol(what) if what.contains("newline")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_raw_call_on_a_closed_connection_fails() {
        let (client, _notifications, server) = pair();
        drop(server);
        soon("the close", client.closed()).await;
        let error = soon("the raw call", client.call_raw(r#"{"id":1}"#, &[]))
            .await
            .expect_err("the connection is gone");
        assert!(
            matches!(&error, Error::Closed(reason) if reason == "eof"),
            "{error:?}"
        );
    }

    /// Dropping the last handle has to end the read task, or a session that
    /// gives up on a server leaks it.
    #[tokio::test]
    async fn dropping_the_last_handle_ends_the_connection() {
        let (client, mut notifications, mut server) = pair();
        let clone = client.clone();
        drop(client);
        // Still one handle, so the connection is still live.
        server.send(r#"{"method":"still.here","params":[]}"#).await;
        assert_eq!(
            soon("a notification", notifications.recv())
                .await
                .expect("a notification")
                .method,
            "still.here"
        );

        let closed = clone.closed();
        drop(clone);
        assert_eq!(
            soon("the close", closed).await,
            "the last client handle was dropped"
        );
        assert!(
            soon("the end of the stream", notifications.recv())
                .await
                .is_none()
        );
    }

    /// Nobody is listening for headers any more, so the socket is of no use.
    #[tokio::test]
    async fn dropping_the_notifications_closes_the_connection() {
        let (client, notifications, mut server) = pair();
        drop(notifications);
        server
            .send(r#"{"method":"nobody.listens","params":[]}"#)
            .await;
        assert_eq!(
            soon("the close", client.closed()).await,
            "the notification receiver was dropped"
        );
    }

    /// Everything that is JSON but not a message: the reader has to keep
    /// going, because none of it says anything about the connection.
    #[tokio::test]
    async fn json_that_is_not_a_message_is_survived() {
        let (client, _notifications, mut server) = pair();
        for line in [
            "[]",
            "42",
            r#""a string""#,
            r#"{"id":1}"#,
            r#"{"id":"a string","result":1}"#,
            r#"{"method":"has.an.id","id":7}"#,
        ] {
            server.send(line).await;
        }
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .send(&format!(r#"{{"id":{id},"result":"pong"}}"#))
            .await;
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
        assert_eq!(client.malformed_lines(), 0, "all of it was valid JSON");
    }

    /// A reply arriving without the newline that would normally end it, right
    /// before the server hangs up, is still a reply.
    #[tokio::test]
    async fn a_last_line_without_a_newline_is_still_read() {
        let (client, _notifications, mut server) = pair();
        let call = spawn_call(&client, "server.ping");
        let id = server.request().await["id"].as_u64().expect("an id");
        server
            .stream
            .get_mut()
            .write_all(format!(r#"{{"id":{id},"result":"pong"}}"#).as_bytes())
            .await
            .expect("the client is connected");
        drop(server);
        let response = answer(call).await.expect("the call worked");
        assert_eq!(response.outcome, Ok(json!("pong")));
    }

    #[tokio::test]
    async fn a_write_to_a_dead_socket_is_an_io_error() {
        // A one-byte pipe, so the write blocks and then fails when the other
        // end goes away mid-write.
        let (client_side, server_side) = tokio::io::duplex(1);
        let (client, _notifications) = Client::new(client_side, Duration::from_secs(30));
        let call = spawn_call(&client, "server.ping");
        tokio::task::yield_now().await;
        drop(server_side);
        let error = answer(call).await.expect_err("no socket");
        assert!(
            matches!(error, Error::Io(_) | Error::Closed(_)),
            "{error:?}"
        );
    }

    #[test]
    fn errors_say_what_happened() {
        let io = Error::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"));
        assert_eq!(io.to_string(), "io error: gone");
        assert!(std::error::Error::source(&io).is_some());
        assert_eq!(Error::Timeout.to_string(), "the request timed out");
        assert!(std::error::Error::source(&Error::Timeout).is_none());
        assert_eq!(
            Error::Closed("eof".to_string()).to_string(),
            "the connection is closed: eof"
        );
        assert_eq!(
            Error::Protocol("two lines".to_string()).to_string(),
            "protocol error: two lines"
        );
        let from_io: Error = std::io::Error::other("boom").into();
        assert!(matches!(from_io, Error::Io(_)), "{from_io:?}");
    }

    #[test]
    fn a_preview_is_bounded_and_escaped() {
        assert_eq!(preview(b"a\nb\t\"c\""), r#"a\nb\t\"c\""#);
        assert_eq!(preview(&[0xff, b'!']), "\u{fffd}!");

        let long = "x".repeat(PREVIEW_CHARS + 1);
        let bounded = preview(long.as_bytes());
        assert_eq!(bounded.chars().count(), PREVIEW_CHARS + 1);
        assert!(bounded.ends_with('…'));

        let exact = "x".repeat(PREVIEW_CHARS);
        assert_eq!(
            preview(exact.as_bytes()),
            exact,
            "no ellipsis when it just fits"
        );
    }

    /// The stamp is taken at the newline, not when the line is handled: a
    /// slow handler must not move it.
    #[tokio::test]
    async fn the_stamp_is_taken_before_the_line_is_handled() {
        let (_client, mut notifications, mut server) = pair();
        server
            .send(r#"{"method":"blockchain.headers.subscribe","params":[]}"#)
            .await;
        // Nothing reads the notification for a while; it was already stamped.
        let waited_from = Instant::now();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let notification = soon("a notification", notifications.recv())
            .await
            .expect("a notification");
        let handled_at = SystemTime::now();
        assert!(
            handled_at
                .duration_since(notification.received_at)
                .expect("the stamp is older")
                >= waited_from
                    .elapsed()
                    .saturating_sub(Duration::from_millis(10)),
            "the stamp is from arrival, not from the handler"
        );
    }
}
