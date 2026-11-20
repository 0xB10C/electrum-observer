//! An Electrum server that answers what a test tells it to, over a real
//! socket.
//!
//! The integration tests are about what a *session* does to a server and
//! what it makes of the answers: the handshake order, the probe sets, a
//! header announcement stamped as it arrives, a reorg seen as two hashes at
//! one height, a disconnection and the backoff after it. None of that can be
//! tested against public servers -- they do not announce a block on request,
//! do not fork on request and are not ours to hammer -- and none of it can be
//! tested against a hand-rolled `tokio::io::duplex` pair either, because the
//! thing under test is a session that dials an address.
//!
//! So this is a server: it binds `127.0.0.1:0`, speaks newline-delimited
//! JSON-RPC 2.0 to as many connections as a test opens, answers the methods
//! this crate asks for from a [`Behaviour`] the test built, and lets the test
//! push a header announcement whenever it likes.
//!
//! Three things shape the design.
//!
//! **A canned answer is the baseline, not the point.** [`Behaviour`] carries
//! a realistic answer for every method the collector sends, so a test that
//! cares about one of them does not have to spell out the other twelve. The
//! defaults are real mainnet data -- the genesis header and block 1, their
//! real hashes, a real coinbase txid -- because a test that asserts on a
//! block hash should be asserting on a hash that exists.
//!
//! **Misbehaviour is configurable, because misbehaviour is what is being
//! collected.** The fingerprint set identifies servers by the verbatim
//! strings they return for odd requests, so the knobs here model the
//! differences between implementations rather than hiding them:
//! [`Behaviour::require_version_first`] is ElectrumX's handshake rule,
//! [`Behaviour::malformed_batch_support`] is the difference between a server
//! that answers a JSON-RPC batch and one that refuses it, and
//! [`Reaction::Never`] is the server that simply stops answering, which is
//! what `timeouts.request_secs` exists for.
//!
//! **Nothing a test client sends may take the server down.** The connection
//! tasks have no `unwrap` on anything derived from the socket: a line that is
//! not JSON is answered with a `-32700` parse error, a request without a
//! method with `-32600`, an unknown method with `-32601`, exactly as a real
//! server does, and the connection carries on. Only the setup path -- binding
//! the listener, decoding the compiled-in header constants -- panics, and it
//! panics in the test's own task where the failure is legible.
//!
//! TLS is deliberately absent: the dial tests bring a rustls listener of
//! their own for the certificate capture, and a TLS flag here would be a
//! second implementation of it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// The mainnet genesis header, 80 bytes of it, hex.
///
/// Compiled in rather than built with `bitcoin::blockdata::constants`,
/// because what the wire carries is this string: a test that asserts a
/// session stored the right hex is asserting against the bytes a server
/// sends, and deriving them from the same crate the code under test uses
/// would make that assertion circular.
pub const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

/// The mainnet header at height 1, hex. The default tip.
pub const BLOCK_1_HEADER: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";

/// The coinbase txid of the genesis block, which is also its merkle root.
///
/// What `blockchain.transaction.id_from_pos(0, 0)` answers by default, so
/// that the divergence probe has something real to find.
pub const GENESIS_COINBASE_TXID: &str =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

/// ElectrumX's `BAD_REQUEST`, from `electrumx/server/session.py`.
///
/// Not a JSON-RPC code at all: the ElectrumX family answers a well-formed
/// request it dislikes -- a height out of range, a second `server.version` --
/// with application code `1`, while aiorpcX answers a request it could not
/// route with the negative codes of the specification. Keeping both apart is
/// the whole point of a fingerprint, so the harness keeps them apart too.
pub const BAD_REQUEST: i64 = 1;

/// The hash of an 80-byte header, as the protocol spells it.
///
/// Panics on anything that is not a header: the callers are this file's
/// constants and a test's own fixtures, and a bad fixture should stop the
/// test that wrote it rather than turn into a server answer.
#[must_use]
pub fn header_hash(hex: &str) -> String {
    let bytes = hex::decode(hex).expect("a header fixture is hex");
    let header: bitcoin::block::Header =
        bitcoin::consensus::deserialize(&bytes).expect("a header fixture is 80 bytes of header");
    header.block_hash().to_string()
}

/// An `error` object, the shape every server puts in the `error` field.
#[must_use]
pub fn rpc_error(code: i64, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

/// What a server answers for one method, when the canned answer is not it.
///
/// Each variant is a thing a real server does, and each is why a session
/// needs the behaviour the variant provokes.
#[derive(Clone, Debug)]
pub enum Reaction {
    /// An arbitrary `error` object, as in the fingerprint set: what a test
    /// needs when it cares about the exact string.
    Error(Value),
    /// An arbitrary `result`, for shapes this harness has no canned answer
    /// for -- a `blockchain.block.header` with a `cp_height`, say.
    Result(Value),
    /// No answer at all, ever. The connection stays open and every other
    /// method still works, which is exactly the case `timeouts.request_secs`
    /// exists for and the case a dropped socket does *not* reproduce.
    Never,
    /// The canned answer, late. For the timing assertions of a session that
    /// has to keep a subscription alive while a probe is still outstanding.
    Delay(Duration),
}

/// The tip a new subscriber is told about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    pub height: u64,
    pub hex: String,
}

/// Everything the server answers, and every way it can misbehave.
///
/// A plain struct with public fields and a `Default`, plus setters for the
/// knobs that are fiddly to spell out, so a test can either take the defaults
/// and change one thing or build the whole thing by hand.
///
/// The defaults are a healthy mainnet Fulcrum whose chain is the first two
/// blocks.
#[derive(Clone, Debug)]
pub struct Behaviour {
    /// `server.version` -> `[software, protocol]`, both of which the
    /// collector stores on the connection.
    pub server_version: (String, String),
    /// `server.features`. Kept as a `Value` rather than a struct because the
    /// collector stores it verbatim and the interesting servers are the ones
    /// whose object is not the documented shape.
    pub features: Value,
    /// `server.banner`.
    pub banner: String,
    /// `server.donation_address`.
    pub donation_address: String,
    /// `blockchain.relayfee`, BTC per kilobyte.
    pub relayfee: Value,
    /// `mempool.get_fee_histogram`, an array of `[fee, vsize]` pairs.
    pub fee_histogram: Value,
    /// `mempool.get_info`.
    pub mempool_info: Value,
    /// `blockchain.estimatefee` by target. A target that is not in here is
    /// answered `-1`, which is what a server with no estimate for that
    /// horizon returns -- and the edge-case targets (`0`, `1009`, `100000`)
    /// are deliberately absent so that the default server is one of the
    /// implementations that answers `-1` rather than one that errors.
    pub estimatefee: BTreeMap<i64, Value>,
    /// `server.peers.subscribe`, rows of `[ip, host, [features...]]`.
    pub peers: Value,
    /// What `blockchain.headers.subscribe` answers, and what
    /// [`MockServer::announce_header`] replaces.
    pub tip: Tip,
    /// `blockchain.block.header(height)`. A height that is not in here is an
    /// error, as on a server that does not have the block.
    pub headers: BTreeMap<u64, String>,
    /// `blockchain.transaction.id_from_pos(height, pos)`, keyed by both.
    pub txids: BTreeMap<(u64, u64), String>,
    /// Per-method departures from all of the above.
    pub overrides: BTreeMap<String, Reaction>,
    /// ElectrumX's handshake rule: any method before `server.version` is an
    /// error, and a second `server.version` is the error
    /// `server.version already sent`. The reason the handshake is the first
    /// message on every connection, and therefore the reason to be able to
    /// test that it is.
    pub require_version_first: bool,
    /// Lines that are not JSON, written the moment the connection is
    /// accepted.
    ///
    /// Servers really do this -- a banner, a blank line, a proxy's
    /// greeting -- and `jsonrpc::Client` counts them rather than failing, so
    /// the harness has to be able to produce them.
    pub junk_lines_before_first_reply: Vec<String>,
    /// Whether a JSON array request is answered with an array of responses
    /// (ElectrumX, Fulcrum) or with a single error (the servers that never
    /// implemented batching). One of the nine fingerprint probes.
    pub malformed_batch_support: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Behaviour {
            server_version: ("Fulcrum 1.12.0".to_string(), "1.4".to_string()),
            features: json!({
                "genesis_hash": header_hash(GENESIS_HEADER),
                "hash_function": "sha256",
                "hosts": {
                    "mock.example.com": { "tcp_port": 50001, "ssl_port": 50002 },
                },
                "protocol_max": "1.5",
                "protocol_min": "1.4",
                "pruning": Value::Null,
                "server_version": "Fulcrum 1.12.0",
            }),
            banner: "Connected to a Fulcrum 1.12.0 server\nBitcoin Core 29.0".to_string(),
            donation_address: "1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj".to_string(),
            relayfee: json!(0.00001),
            fee_histogram: json!([[12, 128_812], [4, 92_524], [2, 6_478_638], [1, 22_890_421]]),
            mempool_info: json!({
                "mempoolminfee": 0.00001,
                "minrelaytxfee": 0.00001,
                "incrementalrelayfee": 0.00001,
            }),
            estimatefee: [
                (1, json!(0.00018)),
                (2, json!(0.00015)),
                (3, json!(0.00012)),
                (6, json!(0.00009)),
                (25, json!(0.00005)),
                (144, json!(0.00002)),
                (1008, json!(0.00001)),
            ]
            .into_iter()
            .collect(),
            peers: json!([
                [
                    "104.198.149.61",
                    "electrum.example.com",
                    ["v1.4", "s50002", "t50001"]
                ],
                [
                    "2a01:4f8:c17:3f6f::1",
                    "fulcrum.example.de",
                    ["v1.4.5", "s50002"]
                ],
                ["91.121.108.61", "electrum.example.fr", ["v1.4", "t50001"]],
            ]),
            tip: Tip {
                height: 1,
                hex: BLOCK_1_HEADER.to_string(),
            },
            headers: [
                (0, GENESIS_HEADER.to_string()),
                (1, BLOCK_1_HEADER.to_string()),
            ]
            .into_iter()
            .collect(),
            txids: [((0, 0), GENESIS_COINBASE_TXID.to_string())]
                .into_iter()
                .collect(),
            overrides: BTreeMap::new(),
            require_version_first: false,
            junk_lines_before_first_reply: Vec::new(),
            malformed_batch_support: true,
        }
    }
}

impl Behaviour {
    /// Answers `method` with `reaction` instead of the canned answer.
    #[must_use]
    pub fn on(mut self, method: &str, reaction: Reaction) -> Self {
        self.overrides.insert(method.to_string(), reaction);
        self
    }

    /// Sets the pair `server.version` answers with.
    #[must_use]
    pub fn version(mut self, software: &str, protocol: &str) -> Self {
        self.server_version = (software.to_string(), protocol.to_string());
        self
    }

    /// Sets the tip `blockchain.headers.subscribe` answers with, without
    /// announcing it.
    #[must_use]
    pub fn tip(mut self, height: u64, hex: &str) -> Self {
        self.tip = Tip {
            height,
            hex: hex.to_string(),
        };
        self
    }

    /// Adds one height to what `blockchain.block.header` knows.
    #[must_use]
    pub fn header(mut self, height: u64, hex: &str) -> Self {
        self.headers.insert(height, hex.to_string());
        self
    }

    /// Adds one `(height, position)` to what
    /// `blockchain.transaction.id_from_pos` knows.
    #[must_use]
    pub fn txid(mut self, height: u64, pos: u64, txid: &str) -> Self {
        self.txids.insert((height, pos), txid.to_string());
        self
    }

    /// Turns on ElectrumX's handshake rule.
    #[must_use]
    pub fn require_version_first(mut self) -> Self {
        self.require_version_first = true;
        self
    }

    /// Emits these lines, each followed by a newline, as soon as a
    /// connection is accepted.
    #[must_use]
    pub fn junk_lines(mut self, lines: &[&str]) -> Self {
        self.junk_lines_before_first_reply = lines.iter().map(|l| (*l).to_string()).collect();
        self
    }

    /// Whether a JSON-RPC batch is answered with an array or refused.
    #[must_use]
    pub fn batches(mut self, supported: bool) -> Self {
        self.malformed_batch_support = supported;
        self
    }
}

/// One line as the server received it.
///
/// Every line is recorded, in arrival order across all connections, including
/// the ones that were not valid requests: what a session *sent*, and in which
/// order, is half of what the session and end-to-end tests assert, and a
/// session that sends a probe twice or sends it before the handshake leaves
/// its trace here and nowhere else.
///
/// A batch line yields one entry per element, each carrying the whole line in
/// [`raw`](Self::raw); a line that was not a request at all yields one entry
/// with an empty `method`.
#[derive(Clone, Debug)]
pub struct ReceivedRequest {
    /// Which connection sent it, numbered from 0 in accept order.
    pub connection: usize,
    /// The `id` verbatim, or `None` when there was none: the fingerprint set
    /// sends ids that are not numbers, and normalising them here would lose
    /// the thing being tested.
    pub id: Option<Value>,
    /// The `method`, or empty when the line carried none.
    pub method: String,
    /// The `params` verbatim, or `Null` when there were none.
    pub params: Value,
    /// The line as it arrived, without its newline.
    pub raw: String,
    /// When the line was read.
    pub at: SystemTime,
}

/// A live connection, as the control functions see it.
struct Connection {
    /// Lines to write. Dropping it ends the writer task and the socket with
    /// it.
    out: mpsc::UnboundedSender<String>,
    /// Whether this connection has sent `blockchain.headers.subscribe`.
    /// Announcements go only to the ones that have, because a server that
    /// pushes headers at a client which never subscribed is a bug a session
    /// should not be written against.
    subscribed: Arc<AtomicBool>,
    /// Raised to close this connection from the outside.
    close: watch::Sender<bool>,
}

/// What a connection task knows about itself.
struct ConnectionState {
    id: usize,
    subscribed: Arc<AtomicBool>,
    /// Whether `server.version` has been seen, for
    /// [`Behaviour::require_version_first`].
    version_seen: AtomicBool,
}

/// Shared between the accept loop, the connection tasks and the handle.
struct State {
    behaviour: Mutex<Behaviour>,
    requests: Mutex<Vec<ReceivedRequest>>,
    connections: Mutex<BTreeMap<usize, Connection>>,
    next_connection: AtomicUsize,
}

/// A mutex guard without the poisoning branch.
///
/// Every critical section here is a map insertion, a clone or a push, so a
/// panic inside one cannot leave anything half-written -- and a test that
/// panicked once should fail on its own assertion rather than on a poisoned
/// lock three lines later.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running mock server. Dropping it closes the listener and every
/// connection.
pub struct MockServer {
    addr: SocketAddr,
    state: Arc<State>,
    accept: JoinHandle<()>,
}

impl MockServer {
    /// Binds `127.0.0.1:0` and starts accepting.
    ///
    /// The port is the kernel's choice because a test suite that picks its
    /// own ports fails when two of them run at once, and these do: every test
    /// below starts its own server.
    ///
    /// Panics if the loopback interface cannot be bound, which is a broken
    /// environment rather than a failing test.
    pub async fn start(behaviour: Behaviour) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a test machine can bind loopback");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");
        let state = Arc::new(State {
            behaviour: Mutex::new(behaviour),
            requests: Mutex::new(Vec::new()),
            connections: Mutex::new(BTreeMap::new()),
            next_connection: AtomicUsize::new(0),
        });
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&state)));
        MockServer {
            addr,
            state,
            accept,
        }
    }

    /// Where to dial.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Pushes a `blockchain.headers.subscribe` notification to every
    /// subscribed connection and makes the header the new tip.
    ///
    /// This is the collector's measurement turned inside out: the collector
    /// exists to record when an announcement arrived, so a test has to be
    /// able to say when it was sent. Returns how many connections were
    /// notified.
    ///
    /// The tip is replaced but `headers` is not: announcing a hash at a
    /// height whose `blockchain.block.header` answer is still the old one is
    /// a server mid-reorg, and [`set_header`](Self::set_header) is how a test
    /// completes the reorg afterwards.
    pub fn announce_header(&self, height: u64, hex: &str) -> usize {
        let line = {
            let mut behaviour = lock(&self.state.behaviour);
            behaviour.tip = Tip {
                height,
                hex: hex.to_string(),
            };
            json!({
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [{ "height": height, "hex": hex }],
            })
            .to_string()
        };
        let connections = lock(&self.state.connections);
        connections
            .values()
            .filter(|connection| connection.subscribed.load(Ordering::Acquire))
            .filter(|connection| connection.out.send(line.clone()).is_ok())
            .count()
    }

    /// Changes what `blockchain.block.header(height)` answers.
    ///
    /// Together with [`announce_header`](Self::announce_header) this is a
    /// reorg: announce a different header at a height that was already
    /// announced, then switch the polled answer to match, and a session in
    /// divergence mode sees exactly what it would see against a server that
    /// reorganised.
    pub fn set_header(&self, height: u64, hex: &str) {
        lock(&self.state.behaviour)
            .headers
            .insert(height, hex.to_string());
    }

    /// Replaces the whole behaviour, for a test that wants a server to change
    /// its mind mid-connection -- a banner edit, a method that starts
    /// failing.
    pub fn set_behaviour(&self, behaviour: Behaviour) {
        *lock(&self.state.behaviour) = behaviour;
    }

    /// Closes every open connection without closing the listener, so the
    /// client sees an EOF and the test can watch it reconnect.
    pub fn disconnect_all(&self) {
        let connections = std::mem::take(&mut *lock(&self.state.connections));
        for (_, connection) in connections {
            // The connection task is also watching this; dropping `out` after
            // it closes the socket either way.
            let _ = connection.close.send(true);
        }
    }

    /// How many connections are open right now.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        lock(&self.state.connections).len()
    }

    /// Every line received so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<ReceivedRequest> {
        lock(&self.state.requests).clone()
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        self.accept.abort();
        self.disconnect_all();
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Accepts until the task is aborted.
async fn accept_loop(listener: TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            // A loopback listener fails to accept when the process is out of
            // descriptors, which is not something retrying fixes.
            return;
        };
        let id = state.next_connection.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(serve(Arc::clone(&state), stream, id));
    }
}

/// One connection, from accept to close.
async fn serve(state: Arc<State>, stream: TcpStream, id: usize) {
    // Nagle would coalesce a reply with the next one and move the arrival
    // stamp this whole crate is built around.
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();
    let (out, out_rx) = mpsc::unbounded_channel::<String>();
    let (close, close_rx) = watch::channel(false);
    let connection = ConnectionState {
        id,
        subscribed: Arc::new(AtomicBool::new(false)),
        version_seen: AtomicBool::new(false),
    };

    for junk in lock(&state.behaviour).junk_lines_before_first_reply.clone() {
        let _ = out.send(junk);
    }

    lock(&state.connections).insert(
        id,
        Connection {
            out: out.clone(),
            subscribed: Arc::clone(&connection.subscribed),
            close,
        },
    );
    let writing = tokio::spawn(write_lines(writer, out_rx, close_rx.clone()));

    read_lines(&state, &connection, reader, &out, close_rx).await;

    lock(&state.connections).remove(&id);
    drop(out);
    let _ = writing.await;
}

/// Reads request lines until the socket or the test says to stop.
async fn read_lines(
    state: &State,
    connection: &ConnectionState,
    reader: OwnedReadHalf,
    out: &mpsc::UnboundedSender<String>,
    mut close: watch::Receiver<bool>,
) {
    let mut lines = BufReader::new(reader).lines();
    loop {
        let line = tokio::select! {
            line = lines.next_line() => line,
            _ = close.changed() => return,
        };
        // A read error is a client that went away mid-line, or bytes that are
        // not UTF-8; either way there is nothing left to answer.
        let Ok(Some(line)) = line else { return };
        handle_line(state, connection, &line, out);
    }
}

/// Writes whole lines until the channel or the test says to stop.
async fn write_lines(
    mut writer: OwnedWriteHalf,
    mut out: mpsc::UnboundedReceiver<String>,
    mut close: watch::Receiver<bool>,
) {
    loop {
        let line = tokio::select! {
            line = out.recv() => line,
            _ = close.changed() => return,
        };
        let Some(line) = line else { return };
        if writer.write_all(line.as_bytes()).await.is_err()
            || writer.write_all(b"\n").await.is_err()
            || writer.flush().await.is_err()
        {
            return;
        }
    }
}

/// Records one line, works out what it deserves and arranges for it to be
/// sent.
fn handle_line(
    state: &State,
    connection: &ConnectionState,
    line: &str,
    out: &mpsc::UnboundedSender<String>,
) {
    let at = SystemTime::now();
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        record(state, connection.id, None, "", &Value::Null, line, at);
        send(out, None, Some(error_response(Value::Null, parse_error())));
        return;
    };

    let Some(elements) = value.as_array() else {
        let (delay, response) = one(state, connection, &value, line, at);
        send(out, delay, response);
        return;
    };

    // A batch. The elements are answered as a server would answer them --
    // each on its own, in order -- and then either returned as one array or
    // refused wholesale.
    if !lock(&state.behaviour).malformed_batch_support {
        for element in elements {
            record_element(state, connection.id, element, line, at);
        }
        send(
            out,
            None,
            Some(error_response(
                Value::Null,
                rpc_error(-32600, "batches are not supported"),
            )),
        );
        return;
    }
    if elements.is_empty() {
        record(state, connection.id, None, "", &Value::Null, line, at);
        send(
            out,
            None,
            Some(error_response(
                Value::Null,
                rpc_error(-32600, "invalid request"),
            )),
        );
        return;
    }
    let mut responses = Vec::with_capacity(elements.len());
    // One delay for the array, the longest of its members': a batch is one
    // reply, so a member that is slow makes the whole reply slow.
    let mut delay: Option<Duration> = None;
    for element in elements {
        let (member_delay, response) = one(state, connection, element, line, at);
        delay = delay.max(member_delay);
        if let Some(response) = response {
            responses.push(response);
        }
    }
    if responses.is_empty() {
        return;
    }
    send(out, delay, Some(Value::Array(responses)));
}

/// Answers one request object: its delay, and the response to send, if any.
fn one(
    state: &State,
    connection: &ConnectionState,
    element: &Value,
    raw: &str,
    at: SystemTime,
) -> (Option<Duration>, Option<Value>) {
    let (id, method, params) = record_element(state, connection.id, element, raw, at);
    let Some(method) = method else {
        // No method at all, so nothing to dispatch on: a response without an
        // id is still sent here, because a malformed request is the one case
        // the specification answers with a null id rather than with silence.
        return (
            None,
            Some(error_response(
                id.unwrap_or(Value::Null),
                rpc_error(-32600, "invalid request"),
            )),
        );
    };
    let (delay, outcome) = dispatch(state, connection, &method, &params);
    // No id is a JSON-RPC notification, which a server does not answer.
    let response = id.zip(outcome).map(|(id, outcome)| match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => error_response(id, error),
    });
    (delay, response)
}

/// Pulls the request fields out of one element and records it.
fn record_element(
    state: &State,
    connection: usize,
    element: &Value,
    raw: &str,
    at: SystemTime,
) -> (Option<Value>, Option<String>, Value) {
    let id = element.get("id").filter(|id| !id.is_null()).cloned();
    let method = element
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string);
    let params = element.get("params").cloned().unwrap_or(Value::Null);
    record(
        state,
        connection,
        id.clone(),
        method.as_deref().unwrap_or(""),
        &params,
        raw,
        at,
    );
    (id, method, params)
}

fn record(
    state: &State,
    connection: usize,
    id: Option<Value>,
    method: &str,
    params: &Value,
    raw: &str,
    at: SystemTime,
) {
    lock(&state.requests).push(ReceivedRequest {
        connection,
        id,
        method: method.to_string(),
        params: params.clone(),
        raw: raw.to_string(),
        at,
    });
}

/// Sends a response, now or after a delay, if there is one to send.
///
/// The delay is a task of its own rather than a sleep in the read loop,
/// because a server that is slow to answer one request still answers the
/// next one and still pushes notifications; a read loop that slept would
/// model a server that had stopped reading, which is a different failure.
fn send(out: &mpsc::UnboundedSender<String>, delay: Option<Duration>, response: Option<Value>) {
    let Some(response) = response else { return };
    let line = response.to_string();
    match delay {
        None => {
            let _ = out.send(line);
        }
        Some(delay) => {
            let out = out.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = out.send(line);
            });
        }
    }
}

/// The framing rules, the overrides and the canned answers, in that order.
///
/// The order is the server's: `require_version_first` is a rule about the
/// connection and comes before anything about the method, so a test can have
/// a method both overridden and refused for being asked too early, which is
/// what a session that gets its handshake wrong would meet.
///
/// `None` for the outcome means no answer at all.
#[allow(clippy::type_complexity)]
fn dispatch(
    state: &State,
    connection: &ConnectionState,
    method: &str,
    params: &Value,
) -> (Option<Duration>, Option<Result<Value, Value>>) {
    let behaviour = lock(&state.behaviour);
    if behaviour.require_version_first
        && method != "server.version"
        && !connection.version_seen.load(Ordering::Relaxed)
    {
        return (
            None,
            Some(Err(rpc_error(
                BAD_REQUEST,
                "use server.version to declare your protocol version first",
            ))),
        );
    }
    match behaviour.overrides.get(method) {
        Some(Reaction::Never) => (None, None),
        Some(Reaction::Error(error)) => (None, Some(Err(error.clone()))),
        Some(Reaction::Result(result)) => (None, Some(Ok(result.clone()))),
        Some(Reaction::Delay(delay)) => (
            Some(*delay),
            Some(canned(&behaviour, connection, method, params)),
        ),
        None => (None, Some(canned(&behaviour, connection, method, params))),
    }
}

/// What the configured server answers, with no override in the way.
///
/// `Ok` is a `result`, `Err` an `error` object. Both are answers: the
/// fingerprint set collects error strings as data, so an error here is a
/// canned answer like any other and not a failure of the harness.
fn canned(
    behaviour: &Behaviour,
    connection: &ConnectionState,
    method: &str,
    params: &Value,
) -> Result<Value, Value> {
    match method {
        "server.version" => {
            if behaviour.require_version_first
                && connection.version_seen.swap(true, Ordering::Relaxed)
            {
                // ElectrumX's wording, which is one of the strings the
                // fingerprint set collects.
                return Err(rpc_error(BAD_REQUEST, "server.version already sent"));
            }
            connection.version_seen.store(true, Ordering::Relaxed);
            let (software, protocol) = &behaviour.server_version;
            Ok(json!([software, protocol]))
        }
        "server.features" => Ok(behaviour.features.clone()),
        "server.banner" => Ok(json!(behaviour.banner)),
        "server.donation_address" => Ok(json!(behaviour.donation_address)),
        // Protocol 1.4 answers `null`; the `pong_len` form of the
        // documentation is a later draft nothing in the field implements, and
        // a test that wants it can override the method.
        "server.ping" => Ok(Value::Null),
        "server.peers.subscribe" => Ok(behaviour.peers.clone()),
        "blockchain.relayfee" => Ok(behaviour.relayfee.clone()),
        "mempool.get_fee_histogram" => Ok(behaviour.fee_histogram.clone()),
        "mempool.get_info" => Ok(behaviour.mempool_info.clone()),
        "blockchain.estimatefee" => {
            let Some(target) = argument(params, 0).and_then(Value::as_i64) else {
                return Err(invalid_params("a block target"));
            };
            Ok(behaviour
                .estimatefee
                .get(&target)
                .cloned()
                // What a server with no estimate for that horizon answers,
                // which is the interesting half of the edge-case targets.
                .unwrap_or_else(|| json!(-1)))
        }
        "blockchain.headers.subscribe" => {
            connection.subscribed.store(true, Ordering::Release);
            Ok(json!({ "height": behaviour.tip.height, "hex": behaviour.tip.hex }))
        }
        "blockchain.block.header" => {
            let Some(height) = argument(params, 0).and_then(Value::as_u64) else {
                return Err(invalid_params("a height"));
            };
            // `cp_height` is ignored: the checkpoint form answers an object
            // with a merkle branch, and a test that wants one overrides the
            // method with the object it wants.
            behaviour
                .headers
                .get(&height)
                .map(|hex| json!(hex))
                .ok_or_else(|| rpc_error(BAD_REQUEST, &format!("height {height} out of range")))
        }
        "blockchain.transaction.id_from_pos" => {
            let height = argument(params, 0).and_then(Value::as_u64);
            let position = argument(params, 1).and_then(Value::as_u64);
            let (Some(height), Some(position)) = (height, position) else {
                return Err(invalid_params("a height and a position"));
            };
            behaviour
                .txids
                .get(&(height, position))
                .map(|txid| json!(txid))
                .ok_or_else(|| {
                    rpc_error(
                        BAD_REQUEST,
                        &format!("no tx at position {position} in block at height {height}"),
                    )
                })
        }
        _ => Err(unknown_method()),
    }
}

/// One positional parameter. Electrum sends arrays; an object is not
/// something any implementation of this protocol accepts.
fn argument(params: &Value, index: usize) -> Option<&Value> {
    params.as_array()?.get(index)
}

/// The default answer to a method the server does not have, and the first of
/// the nine fingerprint probes.
fn unknown_method() -> Value {
    rpc_error(-32601, "unknown method")
}

fn invalid_params(wanted: &str) -> Value {
    rpc_error(-32602, &format!("invalid parameters: expected {wanted}"))
}

/// What a real server answers to a line that is not JSON, rather than closing
/// the connection or saying nothing.
fn parse_error() -> Value {
    rpc_error(-32700, "parse error")
}

fn error_response(id: Value, error: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}
