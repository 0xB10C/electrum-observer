//! One connection to one server: the handshake, the probes, the headers, and
//! the reconnect after it ends.
//!
//! This is DESIGN.md section 5 written down. A session owns everything it
//! writes -- its `connections` row and every `header_events`, `pings`,
//! `probes` and `tip_checks` row that names it -- and it is the only part of
//! the collector that talks to a server, so the order of what it does is the
//! order the design prescribes and not an implementation detail:
//!
//! 1. the dial, recorded whether or not it succeeds;
//! 2. `server.version`, which ElectrumX requires to be the first message on
//!    the connection and which therefore is;
//! 3. the initial probe set, whose `server.features` answer decides whether
//!    this server is on the configured chain at all;
//! 4. `blockchain.headers.subscribe`, whose reply and whose every later
//!    notification is a `header_events` row stamped where the bytes arrived;
//! 5. the timers -- ping, fees, identity, fingerprint -- from `cadence`;
//! 6. the divergence poll, which runs in every session including the
//!    noise-floor ones, because which branch a server is on is exactly what
//!    several connections to one server can disagree about.
//!
//! **Sessions after the first do headers and pings only.** `session_index`
//! is which of a server's `sessions_per_server` connections this is, and
//! only index 0 probes: the others exist to measure the floor two
//! connections to one endpoint put under every cross-server delta (thread
//! #167, DESIGN.md section 5), and a probe set sent down them would cost a
//! server twice for data that is already collected.
//!
//! **Nothing here takes a measurement's timestamp.** Every `at` is the
//! `received_at` the JSON-RPC client stamped as the last byte of the line
//! arrived, and every `rtt_us` is a difference of two of those. A probe set
//! that holds the select loop for a few seconds therefore moves no
//! measurement, which is why the loop runs one thing at a time rather than
//! spawning: the stamp is already taken before this module sees the value.
//!
//! **The tracker is shared.** `headers::Tracker` is the cross-server block
//! book, so every session of the process locks the same one. The lock is
//! taken around `observe`, `open_window` and `close_expired` and released
//! before anything is awaited, because it is a `std::sync::Mutex` and
//! because the work under it is a map insert.
//!
//! ## `end_reason`
//!
//! Exactly one `ConnectionEnded` is written for every `ConnectionStarted`,
//! and its reason is one of these short words, plus the dial's own from
//! [`DialError::end_reason`](crate::dial::DialError::end_reason):
//! [`END_EOF`], [`END_READ_ERROR`], [`END_PROTOCOL`], [`END_SHUTDOWN`],
//! [`END_TIMEOUT`], [`END_HANDSHAKE_ERROR`], [`END_PING_FAILED`] and
//! [`END_GENESIS_MISMATCH`]. They are column contents a query filters on, so
//! they are as stable as the table.
//!
//! ## Backoff
//!
//! A connection that ended is reopened after `reconnect.min_secs`, doubling
//! to `reconnect.max_secs`, with plus or minus 20 % jitter. The jitter is the
//! point of the whole scheme: without it a restart makes every session
//! reconnect in lockstep and the first-seen timings of the next few blocks
//! measure our own scheduler (DESIGN.md section 5 step 7). The backoff resets
//! to the minimum after a connection that lasted longer than
//! [`LONG_CONNECTION`], so a server that is up for a day and then restarts is
//! retried promptly rather than at whatever ceiling a bad week left behind.
//!
//! The first fee and fingerprint sets are staggered the same way, by a random
//! fraction of their own cadence, so that six hundred sessions established in
//! the same second do not ask six hundred servers the same question at the
//! same moment for the rest of the run.

use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant as Deadline, Interval, MissedTickBehavior, interval_at};
use tracing::{debug, info, warn};

use crate::TARGET_SESSION as TARGET;
use crate::dial::Dialer;
use crate::discovery::AdvertisedPeer;
use crate::headers::{self, Announcement, Tracker};
use crate::jsonrpc::{self, Client, Notification, Notifications};
use crate::probes::{self, ProbeArgs, ProbeIds, ProbeKind, ProbeSet};
use crate::settings::Settings;
use crate::store::{Event, HeaderKind, Micros, ServerRow, Store, StoreWriter};

/// What this client calls itself in `server.version`, which is what the
/// servers' own logs will show.
///
/// The fingerprint set's second `server.version` repeats these two strings
/// (DESIGN.md section 6), so they live here, beside the handshake that first
/// sent them, rather than in two places that could drift apart.
pub const CLIENT_NAME: &str = concat!("electrum-observer/", env!("CARGO_PKG_VERSION"));

/// The protocol version the handshake asks for. 1.4 is what every server this
/// crate is pointed at speaks, and what `server.peers.subscribe` advertises.
pub const PROTOCOL_VERSION: &str = "1.4";

/// The subscription, which is both a method and the notification it sends.
const HEADERS_SUBSCRIBE: &str = "blockchain.headers.subscribe";

/// The connection ended as the server closed it, with nothing in flight.
pub const END_EOF: &str = "eof";

/// The socket failed in a way that was not a clean end of stream.
pub const END_READ_ERROR: &str = "read_error";

/// The server broke the framing: a line past the client's cap, or an answer
/// that could not be routed at all. Also what a server that refuses
/// `blockchain.headers.subscribe` is recorded as, because a connection that
/// cannot subscribe is of no use to this collector.
pub const END_PROTOCOL: &str = "protocol";

/// The daemon is stopping.
pub const END_SHUTDOWN: &str = "shutdown";

/// A request of the setup -- the handshake or the subscription -- went
/// unanswered for `timeouts.request_secs`.
pub const END_TIMEOUT: &str = "timeout";

/// The server refused `server.version`, which is the one request it has to
/// answer before anything else can be asked.
pub const END_HANDSHAKE_ERROR: &str = "handshake_error";

/// A `server.ping` was refused or never answered. The connection is dropped
/// rather than kept, because the ping exists to tell a live connection from a
/// socket that is open and dead.
pub const END_PING_FAILED: &str = "ping_failed";

/// `server.features` named another chain's genesis hash. The server is
/// disabled with the same word in `servers.disabled_reason` and this session
/// does not come back (DESIGN.md section 5 step 3).
pub const END_GENESIS_MISMATCH: &str = "genesis_mismatch";

/// The initial probe set of DESIGN.md section 6, in the order it is asked.
///
/// The identity set plus `blockchain.relayfee` and `mempool.get_info`: a
/// connection starts with one of everything slow-moving, so that a server
/// which is only reachable for a minute still leaves a full identity behind.
/// [`ProbeKind::Features`] is first because the genesis check decides whether
/// the rest is worth asking at all.
const INITIAL_KINDS: &[ProbeKind] = &[
    ProbeKind::Features,
    ProbeKind::Banner,
    ProbeKind::DonationAddress,
    ProbeKind::Relayfee,
    ProbeKind::MempoolInfo,
    ProbeKind::Peers,
];

/// How long a connection has to have lasted for the backoff to forget that
/// anything ever went wrong.
///
/// Ten minutes is several blocks and many pings: a connection that lived that
/// long was a working one, and the next failure is a new fact rather than the
/// continuation of the old one. Without a reset, one bad hour would leave a
/// server being retried hourly for the rest of the run.
const LONG_CONNECTION: Duration = Duration::from_secs(600);

/// How far the reconnect delay is moved either way, as a fraction.
const JITTER: f64 = 0.2;

/// The largest fraction of its own cadence that the first fee or fingerprint
/// set is held back by.
const STAGGER: f64 = 0.25;

/// Everything a session needs that it does not own.
///
/// Cloning is cheap and shares all of it: the store's connection and id
/// counters, the writer's channel, and the one tracker. The supervisor builds
/// one of these and hands a clone to every session.
#[derive(Clone)]
pub struct SessionContext {
    /// The whole configuration: timeouts, cadences, the reconnect window, and
    /// the chain whose genesis hash the handshake checks.
    pub settings: Arc<Settings>,
    /// The shared dialer -- the resolver, the TLS configuration and, once it
    /// is installed, the Tor seam.
    pub dialer: Arc<Dialer>,
    /// The database itself, for the two things a session cannot do through
    /// the writer: taking the ids its rows will have, and disabling a server
    /// that turned out to be on another chain.
    pub store: Store,
    /// Where every observation goes.
    pub writer: StoreWriter,
    /// The cross-server block book, shared by every session of the process.
    pub tracker: Arc<Mutex<Tracker>>,
    /// Where a `server.peers.subscribe` answer's parsed rows are handed to
    /// the run loop, which decides what becomes a server of ours.
    ///
    /// `None` is a session that discovers nothing -- the peer list is still
    /// probed, still stored and still turned into `peer_edges`, because the
    /// advertisement graph is data whether or not anything is dialed because
    /// of it (DESIGN.md section 7).
    pub peers_tx: Option<mpsc::Sender<(i64, Vec<AdvertisedPeer>)>>,
}

impl SessionContext {
    /// Queues one event, and says so when there is nowhere to put it.
    ///
    /// A failure here means the writer task is gone, which happens at
    /// shutdown and after it panicked. The session carries on: the stop flag
    /// is what ends it, and an observation that cannot be written is better
    /// logged than turned into a second way for a session to die.
    async fn record(&self, event: Event) {
        if let Err(error) = self.writer.send(event).await {
            warn!(target: TARGET, %error, "an observation was not queued");
        }
    }
}

/// Why a connection ended, and whether to open another one.
struct Ended {
    reason: String,
    /// Set when this server should not be connected to again at all, which
    /// today is the genesis mismatch alone.
    fatal: bool,
}

impl Ended {
    fn new(reason: &str) -> Self {
        Ended {
            reason: reason.to_string(),
            fatal: false,
        }
    }

    fn fatal(reason: &str) -> Self {
        Ended {
            reason: reason.to_string(),
            fatal: true,
        }
    }
}

/// Keeps one server connected until the daemon stops.
///
/// Returns when `stop` is raised, or for good when the server turned out to
/// be on another chain. Everything else -- a refused port, a server that
/// stops answering, a handshake that fails -- is a connection that ended and
/// is retried after the backoff.
pub async fn run_session(
    ctx: SessionContext,
    server: ServerRow,
    session_index: usize,
    mut stop: watch::Receiver<bool>,
) {
    let min = ctx.settings.reconnect.min();
    let max = ctx.settings.reconnect.max();
    let mut backoff = min;
    while !*stop.borrow() {
        let opened = Instant::now();
        let ended = connect_once(&ctx, &server, session_index, &mut stop).await;
        if ended.fatal {
            return;
        }
        backoff = after_connection(opened.elapsed(), backoff, min);
        let delay = jitter(backoff);
        debug!(
            target: TARGET,
            server_id = server.id,
            session_index,
            delay_ms = delay.as_millis(),
            "waiting before reconnecting",
        );
        if !sleep_or_stop(delay, &mut stop).await {
            return;
        }
        backoff = doubled(backoff, max);
    }
}

/// One connection, from the id it will be written under to the row that says
/// it is over.
///
/// The one place `ConnectionEnded` is written, so that the "exactly one per
/// `ConnectionStarted`" of DESIGN.md section 4 is a property of the control
/// flow rather than a rule every error path has to remember.
async fn connect_once(
    ctx: &SessionContext,
    server: &ServerRow,
    session_index: usize,
    stop: &mut watch::Receiver<bool>,
) -> Ended {
    let id = ctx.store.next_connection_id();
    ctx.record(Event::ConnectionStarted {
        id,
        server_id: server.id,
        session_index: as_i64(session_index),
        started_at: Micros::now(),
    })
    .await;

    let ended = establish(ctx, server, session_index, id, stop).await;
    info!(
        target: TARGET,
        server_id = server.id,
        endpoint = %server.endpoint,
        session_index,
        connection_id = id,
        end_reason = %ended.reason,
        "the connection ended",
    );
    ctx.record(Event::ConnectionEnded {
        id,
        ended_at: Micros::now(),
        end_reason: ended.reason.clone(),
    })
    .await;
    ended
}

/// The dial, the handshake, and the serving if both worked.
///
/// A connection whose handshake did not finish has no `connected_at`: the
/// `connections` row is filled in when the server has answered, because what
/// that column is read as is "this server was usable at this moment" and a
/// socket that opened and then said nothing was not.
async fn establish(
    ctx: &SessionContext,
    server: &ServerRow,
    session_index: usize,
    id: i64,
    stop: &mut watch::Receiver<bool>,
) -> Ended {
    let dialed = match ctx.dialer.dial(&server.endpoint).await {
        Ok(dialed) => dialed,
        Err(error) => {
            debug!(
                target: TARGET,
                server_id = server.id,
                endpoint = %server.endpoint,
                %error,
                "the dial failed",
            );
            return Ended::new(error.end_reason());
        }
    };

    // The lookup is a row of its own and the connection names it, so that a
    // hostname with several addresses can be read back as the set it is
    // rather than as the one address this attempt happened to pick.
    let dns_id = match &dialed.dns {
        Some(dns) => {
            let dns_id = ctx.store.next_dns_id();
            ctx.record(Event::DnsResolved {
                id: dns_id,
                server_id: server.id,
                at: dns.at.into(),
                addresses: dns.addresses.iter().map(ToString::to_string).collect(),
                error: dns.error.clone(),
            })
            .await;
            Some(dns_id)
        }
        None => None,
    };

    let (client, mut notifications) = Client::new(dialed.stream, ctx.settings.timeouts.request());
    let versions = match handshake(&client).await {
        Ok(versions) => versions,
        Err(reason) => return Ended::new(reason),
    };
    ctx.record(Event::ConnectionEstablished {
        id,
        connected_at: dialed.connected_at.into(),
        remote_ip: dialed.remote_ip.map(|ip| ip.to_string()),
        tls: dialed.tls,
        dns_id,
        server_version: versions.server.clone(),
        protocol_version: versions.protocol.clone(),
    })
    .await;
    info!(
        target: TARGET,
        server_id = server.id,
        endpoint = %server.endpoint,
        session_index,
        connection_id = id,
        server_version = versions.server.as_deref().unwrap_or("?"),
        protocol_version = versions.protocol.as_deref().unwrap_or("?"),
        "connected",
    );

    let mut connection = Connection {
        ctx,
        server,
        session_index,
        id,
        client,
        coinbases: HashSet::new(),
    };
    connection.serve(&mut notifications, stop).await
}

/// The two strings `server.version` answered with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Versions {
    server: Option<String>,
    protocol: Option<String>,
}

/// `server.version`, which has to be the first message on the connection.
///
/// An `Err` is the `end_reason` the connection takes. A server that answers
/// something other than the documented `[software, protocol]` pair is *not*
/// an error: what it said is recorded as far as it can be and the connection
/// carries on, because an unusual answer here is one of the things this crate
/// collects. Only a refusal, or no answer at all, ends it.
async fn handshake(client: &Client) -> Result<Versions, &'static str> {
    match client
        .call("server.version", json!([CLIENT_NAME, PROTOCOL_VERSION]))
        .await
    {
        Ok(response) => match response.outcome {
            Ok(result) => Ok(versions(&result)),
            Err(error) => {
                debug!(
                    target: TARGET,
                    message = %error.message,
                    "the handshake was refused",
                );
                Err(END_HANDSHAKE_ERROR)
            }
        },
        Err(error) => {
            debug!(target: TARGET, %error, "the handshake did not finish");
            Err(call_end_reason(&error))
        }
    }
}

/// The pair out of whatever `server.version` answered.
///
/// The documented answer is `[software, protocol]`; a few servers answer the
/// software string alone, and an element that is not a string at all is kept
/// as the JSON it was, because `connections.server_version` is meant to say
/// what the server claimed.
fn versions(result: &Value) -> Versions {
    match result {
        Value::Array(pair) => Versions {
            server: pair.first().and_then(version_string),
            protocol: pair.get(1).and_then(version_string),
        },
        other => Versions {
            server: version_string(other),
            protocol: None,
        },
    }
}

/// One of the two strings, or `None` for a null.
fn version_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

/// One open connection, and the few things it remembers about itself.
struct Connection<'a> {
    ctx: &'a SessionContext,
    server: &'a ServerRow,
    session_index: usize,
    /// The `connections.id` every row this connection writes carries.
    id: i64,
    client: Client,
    /// The heights whose coinbase txid has already been asked for.
    ///
    /// Per connection rather than per process: the probe is "which branch was
    /// this server on", and a reconnect is a new answer to it. Within one
    /// connection it is asked once per height, because a divergence is
    /// reported on every announcement that lands inside the window and the
    /// answer does not change between two of them (DESIGN.md section 5 step
    /// 6).
    coinbases: HashSet<u64>,
}

impl Connection<'_> {
    /// Everything after the handshake, until the connection ends.
    async fn serve(
        &mut self,
        notifications: &mut Notifications,
        stop: &mut watch::Receiver<bool>,
    ) -> Ended {
        if self.session_index == 0
            && let Some(ended) = self.initial_probes().await
        {
            return ended;
        }
        if let Some(ended) = self.subscribe().await {
            return ended;
        }
        self.serve_until_closed(notifications, stop).await
    }

    /// The initial set, and the genesis check its first member decides.
    ///
    /// `Some` only for the mismatch: a probe that fails is a recorded failure
    /// and not a reason to drop a connection, because a server that refuses
    /// `server.banner` still announces headers.
    async fn initial_probes(&mut self) -> Option<Ended> {
        for kind in INITIAL_KINDS {
            let result = self.run_probe(*kind, ProbeArgs::default()).await;
            if *kind == ProbeKind::Features
                && let Some(ended) = self.check_genesis(result.as_ref()).await
            {
                return Some(ended);
            }
        }
        None
    }

    /// Whether `server.features` named this chain's genesis block.
    ///
    /// A server on another chain is disabled rather than ignored: its headers
    /// would otherwise go into the cross-server block book and every query
    /// over `blocks` would have to know which rows to leave out (DESIGN.md
    /// section 5 step 3). A `features` answer that failed, or that has no
    /// `genesis_hash` at all, is not a mismatch -- it is a server that did
    /// not say, and nothing is concluded from silence.
    async fn check_genesis(&self, features: Option<&Value>) -> Option<Ended> {
        let announced = features?.get("genesis_hash")?.as_str()?;
        let expected = self.ctx.settings.chain.genesis_hash().to_string();
        if announced.eq_ignore_ascii_case(&expected) {
            return None;
        }
        info!(
            target: TARGET,
            server_id = self.server.id,
            endpoint = %self.server.endpoint,
            announced,
            expected = %expected,
            "the server is on another chain and is disabled",
        );
        if let Err(error) = self
            .ctx
            .store
            .disable_server(self.server.id, END_GENESIS_MISMATCH)
        {
            warn!(
                target: TARGET,
                server_id = self.server.id,
                %error,
                "the server could not be disabled",
            );
        }
        Some(Ended::fatal(END_GENESIS_MISMATCH))
    }

    /// `blockchain.headers.subscribe`, whose reply is the first header row.
    async fn subscribe(&mut self) -> Option<Ended> {
        // The server's announcement history is forgotten first: the reply
        // below is whatever its tip happens to be now, and comparing that
        // against what it said on an earlier connection would record a
        // reconnect as a reorg.
        lock(&self.ctx.tracker).session_started(self.server.id);

        match self.client.call(HEADERS_SUBSCRIBE, json!([])).await {
            Ok(response) => match response.outcome {
                Ok(result) => {
                    self.record_header(HeaderKind::Subscribe, &result, response.received_at)
                        .await;
                    None
                }
                Err(error) => {
                    debug!(
                        target: TARGET,
                        server_id = self.server.id,
                        message = %error.message,
                        "the subscription was refused",
                    );
                    Some(Ended::new(END_PROTOCOL))
                }
            },
            Err(error) => {
                debug!(
                    target: TARGET,
                    server_id = self.server.id,
                    %error,
                    "the subscription did not finish",
                );
                Some(Ended::new(call_end_reason(&error)))
            }
        }
    }

    /// The timers and the notifications, until something ends the connection.
    ///
    /// One thing happens at a time. A probe set that takes seconds delays the
    /// handling of a notification that arrived while it ran, and that is
    /// deliberate: the notification was stamped by the read loop as its last
    /// byte arrived, so the delay moves no measurement, and a session that
    /// spawned a task per timer would need a second answer for what happens
    /// when the connection closes under it.
    async fn serve_until_closed(
        &mut self,
        notifications: &mut Notifications,
        stop: &mut watch::Receiver<bool>,
    ) -> Ended {
        let cadence = &self.ctx.settings.cadence;
        let probing = self.session_index == 0;
        let now = Deadline::now();
        // The ping and the identity set start a full cadence out: the
        // connection has just answered the handshake and has just been asked
        // the whole identity set, so asking either again now would be asking
        // twice. The fee and fingerprint sets have not run at all, so they
        // start soon -- but staggered, so that a fleet of sessions
        // established together does not stay in lockstep for the rest of the
        // run.
        let mut ping = every(now + cadence.ping(), cadence.ping());
        let mut fees = every(now + stagger(cadence.fees()), cadence.fees());
        let mut identity = every(now + cadence.identity(), cadence.identity());
        let mut fingerprint = every(now + stagger(cadence.fingerprint()), cadence.fingerprint());
        let poll_every = self.ctx.settings.divergence.poll();
        let mut poll = every(now + poll_every, poll_every);

        let closed = self.client.closed();
        tokio::pin!(closed);
        loop {
            tokio::select! {
                notification = notifications.recv() => match notification {
                    Some(notification) => self.notified(notification).await,
                    // The notification stream ends with the connection, so
                    // the reason is already waiting.
                    None => return Ended::new(close_end_reason(&self.client.closed().await)),
                },
                reason = &mut closed => return Ended::new(close_end_reason(&reason)),
                // The flag only ever goes from false to true, and a sender
                // that was dropped is a supervisor that has gone away, so
                // either outcome is the same shutdown.
                _ = stop.changed() => return Ended::new(END_SHUTDOWN),
                _ = ping.tick() => if let Some(ended) = self.ping().await {
                    return ended;
                },
                _ = poll.tick() => self.poll_divergence().await,
                _ = fees.tick(), if probing => self.run_set(ProbeSet::Fees).await,
                _ = identity.tick(), if probing => self.run_set(ProbeSet::Identity).await,
                _ = fingerprint.tick(), if probing => {
                    self.run_set(ProbeSet::Fingerprint).await;
                },
            }
        }
    }

    /// One message the server sent unprompted.
    async fn notified(&mut self, notification: Notification) {
        if notification.method != HEADERS_SUBSCRIBE {
            debug!(
                target: TARGET,
                server_id = self.server.id,
                method = %notification.method,
                "an unexpected notification was ignored",
            );
            return;
        }
        let Some(value) = notification.params.get(0) else {
            debug!(
                target: TARGET,
                server_id = self.server.id,
                params = %notification.params,
                "a header notification carried no header",
            );
            return;
        };
        self.record_header(HeaderKind::Notification, value, notification.received_at)
            .await;
    }

    /// One header a server told us about, however it told us.
    ///
    /// `at` is the arrival stamp of the line it came in and nothing else:
    /// this is the measurement of DESIGN.md section 1, and a timestamp taken
    /// here would be the measurement of this function's own scheduling.
    async fn record_header(&mut self, kind: HeaderKind, value: &Value, at: SystemTime) {
        let announcement = match Announcement::from_value(value) {
            Ok(announcement) => announcement,
            Err(error) => {
                debug!(
                    target: TARGET,
                    server_id = self.server.id,
                    kind = kind.as_str(),
                    %error,
                    "a header could not be read",
                );
                return;
            }
        };
        let at = Micros::from(at);
        let observation = lock(&self.ctx.tracker).observe(self.server.id, &announcement, at);
        debug!(
            target: TARGET,
            server_id = self.server.id,
            kind = kind.as_str(),
            height = announcement.height,
            hash = %announcement.header.hash,
            reorg = observation.reorg,
            "a header arrived",
        );
        self.ctx
            .record(Event::Header {
                connection_id: self.id,
                server_id: self.server.id,
                at,
                kind,
                height: as_i64(announcement.height),
                hash: announcement.header.hash.to_string(),
                prev_hash: Some(announcement.header.prev_hash.to_string()),
                header_hex: announcement.header.hex.clone(),
                reorg: observation.reorg,
            })
            .await;

        // A stale block's coinbase identifies the branch long after the
        // branch is gone, and it is cheap to ask once while it still exists.
        let Some(divergence) = observation.divergence else {
            return;
        };
        if self.coinbases.insert(divergence.height) {
            debug!(
                target: TARGET,
                server_id = self.server.id,
                height = divergence.height,
                hashes = divergence.hashes.len(),
                "asking for the coinbase of a contested height",
            );
            self.run_probe(
                ProbeKind::CoinbaseTxid,
                ProbeArgs::at_height(as_i64(divergence.height)),
            )
            .await;
        }
    }

    /// `server.ping`, which keeps ElectrumX from dropping an idle connection
    /// and whose round trip is the baseline every header delta is read
    /// against.
    ///
    /// `Some` ends the connection: a ping that was refused or never answered
    /// is the one failure that says the connection itself is no good, which
    /// is the whole reason to send one.
    async fn ping(&self) -> Option<Ended> {
        match self.client.call("server.ping", json!([])).await {
            Ok(response) => match &response.outcome {
                Ok(_) => {
                    self.ctx
                        .record(Event::Ping {
                            connection_id: self.id,
                            at: response.received_at.into(),
                            rtt_us: micros_between(response.sent_at, response.received_at),
                        })
                        .await;
                    None
                }
                Err(error) => {
                    debug!(
                        target: TARGET,
                        server_id = self.server.id,
                        message = %error.message,
                        "the ping was refused",
                    );
                    Some(Ended::new(END_PING_FAILED))
                }
            },
            // A ping that could not be sent because the connection is
            // already gone says what closed it, not that the ping failed.
            Err(jsonrpc::Error::Closed(reason)) => Some(Ended::new(close_end_reason(&reason))),
            Err(error) => {
                debug!(
                    target: TARGET,
                    server_id = self.server.id,
                    %error,
                    "the ping did not come back",
                );
                Some(Ended::new(END_PING_FAILED))
            }
        }
    }

    /// The divergence poll of DESIGN.md section 5 step 6.
    ///
    /// Every session polls, the noise-floor ones included: a subscription
    /// says when a server *announces* a tip, and only this says when it
    /// *switches*, which is the measurement thread #167 could not take.
    async fn poll_divergence(&mut self) {
        let now = Micros::now();
        let (expired, window) = {
            let mut tracker = lock(&self.ctx.tracker);
            (tracker.close_expired(now), tracker.open_window(now))
        };
        for closed in expired {
            info!(
                target: TARGET,
                server_id = self.server.id,
                heights = ?closed.heights,
                since = closed.since.as_i64(),
                until = closed.until.as_i64(),
                "the divergence window closed",
            );
        }
        let Some(window) = window else {
            return;
        };
        for height in window.heights {
            let event = self.tip_check(height).await;
            self.ctx.record(event).await;
        }
    }

    /// One `blockchain.block.header` poll, as the row it becomes.
    ///
    /// Never fails: a refusal and a timeout are both `tip_checks.error`,
    /// because "this server would not say what it has at that height" is as
    /// much of an answer as a hash is.
    async fn tip_check(&self, height: u64) -> Event {
        let height = as_i64(height);
        match self
            .client
            .call("blockchain.block.header", json!([height]))
            .await
        {
            Ok(response) => {
                let at = Micros::from(response.received_at);
                let rtt_us = Some(micros_between(response.sent_at, response.received_at));
                let (hash, error) = match &response.outcome {
                    Ok(result) => match result.as_str() {
                        Some(hex) => match headers::parse_header(hex) {
                            Ok(header) => (Some(header.hash.to_string()), None),
                            Err(error) => (None, Some(error.to_string())),
                        },
                        None => (None, Some(format!("the header is not a string: {result}"))),
                    },
                    // The error object verbatim, as everything else keeps a
                    // server's own words.
                    Err(error) => (None, Some(error.raw.to_string())),
                };
                Event::TipCheck {
                    server_id: self.server.id,
                    connection_id: self.id,
                    at,
                    height: Some(height),
                    hash,
                    rtt_us,
                    error,
                }
            }
            Err(error) => Event::TipCheck {
                server_id: self.server.id,
                connection_id: self.id,
                at: Micros::now(),
                height: Some(height),
                hash: None,
                rtt_us: None,
                error: Some(error.to_string()),
            },
        }
    }

    /// One probe set, as its kinds in order.
    async fn run_set(&mut self, set: ProbeSet) {
        debug!(
            target: TARGET,
            server_id = self.server.id,
            set = ?set,
            "a probe set is going out",
        );
        for kind in set.kinds() {
            self.run_probe(*kind, ProbeArgs::default()).await;
        }
    }

    /// One probe, its row, its edges, and -- for a peer list -- the rows
    /// discovery gets to look at.
    ///
    /// Returns the result so that the initial set can read the genesis hash
    /// out of `server.features` without asking the server twice.
    async fn run_probe(&mut self, kind: ProbeKind, args: ProbeArgs) -> Option<Value> {
        let ids = ProbeIds {
            probe_id: self.ctx.store.next_probe_id(),
            connection_id: self.id,
            server_id: self.server.id,
        };
        let outcome = probes::run(&self.client, kind, ids, args).await;
        let result = probe_result(&outcome.event).cloned();
        self.ctx.record(outcome.event).await;
        if let Some(edges) = outcome.peer_edges {
            self.ctx.record(edges).await;
        }
        if kind == ProbeKind::Peers {
            self.offer_peers(result.as_ref()).await;
        }
        result
    }

    /// Hands a peer list to whoever is doing discovery.
    ///
    /// Nothing is sent for a list that held no readable row: the probe row
    /// has already recorded what the server said, and an empty handover would
    /// only wake the run loop up.
    async fn offer_peers(&self, result: Option<&Value>) {
        let Some(tx) = &self.ctx.peers_tx else {
            return;
        };
        let Some(result) = result else {
            return;
        };
        let peers = AdvertisedPeer::parse_list(result);
        if peers.is_empty() {
            return;
        }
        debug!(
            target: TARGET,
            server_id = self.server.id,
            peers = peers.len(),
            "advertised peers handed to discovery",
        );
        if tx.send((self.server.id, peers)).await.is_err() {
            debug!(
                target: TARGET,
                server_id = self.server.id,
                "discovery is gone; the peer list was only stored",
            );
        }
    }
}

/// The result a probe row carries, for the callers that read one back.
fn probe_result(event: &Event) -> Option<&Value> {
    match event {
        Event::Probe { result, .. } => result.as_ref(),
        _ => None,
    }
}

/// A timer that fires at `first` and then every `period`.
///
/// Missed ticks are delayed rather than burst: a probe set that overran its
/// own cadence should not be followed by the two it has fallen behind, which
/// against a server that has become slow is exactly the wrong thing to do.
fn every(first: Deadline, period: Duration) -> Interval {
    let mut interval = interval_at(first, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// The tracker, recovering a mutex poisoned by a panicking session.
///
/// A panic under this lock would leave the block book as it was -- the work
/// under it is a map insert -- and a collector that stopped observing headers
/// because one session panicked would be the worse failure.
fn lock(tracker: &Mutex<Tracker>) -> MutexGuard<'_, Tracker> {
    tracker.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The `end_reason` for a call that produced no answer.
fn call_end_reason(error: &jsonrpc::Error) -> &'static str {
    match error {
        jsonrpc::Error::Timeout => END_TIMEOUT,
        jsonrpc::Error::Closed(reason) => close_end_reason(reason),
        jsonrpc::Error::Io(_) => END_READ_ERROR,
        jsonrpc::Error::Protocol(_) => END_PROTOCOL,
    }
}

/// The `end_reason` for the reason the read loop gave for closing.
///
/// The read loop's reasons are prose -- they are logged -- and this is the
/// column: a clean end of stream is [`END_EOF`], a broken framing rule is
/// [`END_PROTOCOL`], and everything else is the socket having failed.
fn close_end_reason(reason: &str) -> &'static str {
    if reason == END_EOF {
        END_EOF
    } else if reason.starts_with("protocol error") {
        END_PROTOCOL
    } else {
        END_READ_ERROR
    }
}

/// Waits, unless the daemon is stopping. `false` means it is.
async fn sleep_or_stop(delay: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        _ = stop.changed() => false,
    }
}

/// The next delay of the backoff: twice this one, up to the ceiling.
fn doubled(backoff: Duration, max: Duration) -> Duration {
    backoff.saturating_mul(2).min(max)
}

/// What the backoff is worth after a connection that lasted `lasted`.
///
/// A connection that lived longer than [`LONG_CONNECTION`] is forgiven
/// whatever came before it and the next attempt waits the minimum; a short
/// one leaves the climb where it was. Separated from
/// [`run_session`](run_session) so that both branches are a test rather than
/// a ten-minute wait.
fn after_connection(lasted: Duration, backoff: Duration, min: Duration) -> Duration {
    if lasted >= LONG_CONNECTION {
        min
    } else {
        backoff
    }
}

/// `base` moved by up to [`JITTER`] either way.
fn jitter(base: Duration) -> Duration {
    base.mul_f64(1.0 - JITTER + 2.0 * JITTER * fraction())
}

/// Up to [`STAGGER`] of a cadence, as the delay before its first run.
fn stagger(cadence: Duration) -> Duration {
    cadence.mul_f64(STAGGER * fraction())
}

/// A number in `[0, 1)`.
///
/// `RandomState` rather than a random-number generator because the crate
/// needs no other randomness and this one is in the standard library, which
/// is the same reason `dial::choose` uses it: a fresh `RandomState` is seeded
/// differently every time it is built, so hashing a constant through one is a
/// different number on every call. The top 53 bits are the ones taken,
/// because that is what an `f64` holds without rounding two of them together.
fn fraction() -> f64 {
    (RandomState::new().hash_one(0u8) >> 11) as f64 / (1u64 << 53) as f64
}

/// Microseconds between two stamps of the same clock.
fn micros_between(sent: SystemTime, received: SystemTime) -> i64 {
    Micros::from(received).as_i64() - Micros::from(sent).as_i64()
}

/// A count the schema stores as an integer, saturating rather than wrapping.
///
/// The callers are heights and session indexes, which are small; the
/// saturation is for a server that claims a height no chain will ever have,
/// and it saturates rather than panicking because that claim is data too.
fn as_i64<T: TryInto<i64>>(value: T) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    //! What can be tested without a server: the vocabulary, the arithmetic,
    //! and -- over a `tokio::io::duplex` pair with a few canned answers --
    //! the two ways one connection ends that do not need a socket.
    //!
    //! Everything that is about a session *dialling* something is in
    //! `tests/session.rs`, against the mock Electrum server: a connection
    //! that reconnects, a probe set that lands in `probes`, a notification
    //! stamped on arrival and a genesis mismatch that disables a server are
    //! all claims about rows in a database, and a test that asserted them
    //! against a hand-fed duplex pair would be asserting about its own
    //! fixtures.

    use std::str::FromStr;

    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use crate::endpoint::Endpoint;

    use super::*;

    /// The mainnet genesis header, which is what the fake server below
    /// answers `blockchain.headers.subscribe` with.
    const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    /// A context on a temporary database, with the writer task running.
    struct Harness {
        _dir: TempDir,
        ctx: SessionContext,
        server: ServerRow,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(dir.path().join("observer.sqlite")).expect("the schema applies");
        let (writer, task) = store.writer();
        tokio::spawn(task);
        let settings = Settings::default();
        let endpoint = Endpoint::from_str("tcp://127.0.0.1:50001").expect("the endpoint parses");
        let server = store
            .upsert_server(&endpoint, "config", None)
            .expect("the server is inserted");
        let tracker = Arc::new(Mutex::new(Tracker::new(settings.divergence.window())));
        let dialer = Arc::new(Dialer::new(&settings).expect("a dialer is built"));
        Harness {
            _dir: dir,
            ctx: SessionContext {
                settings: Arc::new(settings),
                dialer,
                store,
                writer,
                tracker,
                peers_tx: None,
            },
            server,
        }
    }

    /// The answer a healthy server gives, for the three methods a
    /// noise-floor session asks.
    fn respond(line: &str) -> Option<String> {
        let request: Value = serde_json::from_str(line).ok()?;
        let id = request.get("id")?.clone();
        let result = match request.get("method")?.as_str()? {
            "server.version" => json!(["unit 1.0", PROTOCOL_VERSION]),
            HEADERS_SUBSCRIBE => json!({ "height": 0, "hex": GENESIS_HEADER }),
            "server.ping" => Value::Null,
            _ => {
                return Some(
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "unknown method" },
                    })
                    .to_string(),
                );
            }
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string())
    }

    /// Answers `replies` requests and then drops the connection.
    ///
    /// `usize::MAX` is a server that stays up for as long as the test does.
    async fn fake_server(stream: DuplexStream, replies: usize) {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        let mut answered = 0;
        while answered < replies {
            let Ok(Some(line)) = lines.next_line().await else {
                return;
            };
            let Some(reply) = respond(&line) else {
                continue;
            };
            if writer
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            answered += 1;
        }
    }

    /// One connection over a duplex pair, served to its end.
    ///
    /// `session_index` is 1 throughout: a noise-floor session asks the
    /// handshake and the subscription and nothing else, which is as much as
    /// a fake server of twenty lines should have to answer.
    async fn serve_over_duplex(
        harness: &Harness,
        replies: usize,
        stop: &mut watch::Receiver<bool>,
    ) -> Ended {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_server(theirs, replies));
        let (client, mut notifications) =
            Client::new(ours, harness.ctx.settings.timeouts.request());
        let versions = handshake(&client).await.expect("the fake server answers");
        assert_eq!(versions.server.as_deref(), Some("unit 1.0"));
        assert_eq!(versions.protocol.as_deref(), Some(PROTOCOL_VERSION));
        let mut connection = Connection {
            ctx: &harness.ctx,
            server: &harness.server,
            session_index: 1,
            id: 1,
            client,
            coinbases: HashSet::new(),
        };
        connection.serve(&mut notifications, stop).await
    }

    #[tokio::test]
    async fn a_server_that_goes_away_ends_the_connection_as_eof() {
        let harness = harness();
        let (_tx, mut stop) = watch::channel(false);
        // Two answers: the handshake and the subscription, and then the
        // socket is gone.
        let ended = serve_over_duplex(&harness, 2, &mut stop).await;
        assert_eq!(ended.reason, END_EOF);
        assert!(!ended.fatal, "an EOF is retried");
        assert!(
            lock(&harness.ctx.tracker)
                .tip_of(harness.server.id)
                .is_some(),
            "the subscribe reply was handed to the tracker",
        );
    }

    #[tokio::test]
    async fn the_stop_flag_ends_the_connection() {
        let harness = harness();
        let (tx, mut stop) = watch::channel(false);
        tokio::spawn(async move {
            // Long enough for the subscription to have been answered, short
            // enough to be nothing a test waits for.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });
        let ended = serve_over_duplex(&harness, usize::MAX, &mut stop).await;
        assert_eq!(ended.reason, END_SHUTDOWN);
        assert!(!ended.fatal);
    }

    /// Three notifications that say nothing about a header: a method this
    /// crate never subscribed to, a header announcement with no header in it,
    /// and a header that is not 80 bytes of hexadecimal. None of them may
    /// reach the block book, because each of them is a server doing something
    /// odd rather than a block existing.
    #[tokio::test]
    async fn a_notification_that_carries_no_header_is_ignored() {
        let harness = harness();
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (client, _notifications) = Client::new(ours, Duration::from_secs(1));
        let mut connection = Connection {
            ctx: &harness.ctx,
            server: &harness.server,
            session_index: 0,
            id: 1,
            client,
            coinbases: HashSet::new(),
        };
        for notification in [
            Notification {
                method: "blockchain.scripthash.subscribe".to_string(),
                params: json!([]),
                received_at: SystemTime::now(),
            },
            Notification {
                method: HEADERS_SUBSCRIBE.to_string(),
                params: json!([]),
                received_at: SystemTime::now(),
            },
            Notification {
                method: HEADERS_SUBSCRIBE.to_string(),
                params: json!([{ "height": 2, "hex": "not a header" }]),
                received_at: SystemTime::now(),
            },
        ] {
            connection.notified(notification).await;
        }
        assert!(
            lock(&harness.ctx.tracker)
                .tip_of(harness.server.id)
                .is_none(),
            "nothing unreadable was booked",
        );
    }

    #[test]
    fn a_long_connection_forgives_the_backoff() {
        let min = Duration::from_secs(10);
        let climbed = Duration::from_secs(1280);
        assert_eq!(
            after_connection(LONG_CONNECTION, climbed, min),
            min,
            "a connection that lasted is a server that works",
        );
        assert_eq!(
            after_connection(LONG_CONNECTION - Duration::from_secs(1), climbed, min),
            climbed,
            "and a short one leaves the climb where it was",
        );
        assert_eq!(after_connection(Duration::ZERO, climbed, min), climbed);
    }

    #[test]
    fn close_end_reason_separates_an_ending_from_a_failure() {
        assert_eq!(close_end_reason("eof"), END_EOF);
        assert_eq!(
            close_end_reason("protocol error: a line longer than 16 bytes"),
            END_PROTOCOL,
        );
        assert_eq!(close_end_reason("connection reset by peer"), END_READ_ERROR,);
        assert_eq!(
            close_end_reason("the last client handle was dropped"),
            END_READ_ERROR,
        );
    }

    #[test]
    fn call_end_reason_covers_every_way_a_call_fails() {
        assert_eq!(call_end_reason(&jsonrpc::Error::Timeout), END_TIMEOUT);
        assert_eq!(
            call_end_reason(&jsonrpc::Error::Closed("eof".to_string())),
            END_EOF,
        );
        assert_eq!(
            call_end_reason(&jsonrpc::Error::Closed("broken pipe".to_string())),
            END_READ_ERROR,
        );
        assert_eq!(
            call_end_reason(&jsonrpc::Error::Protocol("two lines".to_string())),
            END_PROTOCOL,
        );
        assert_eq!(
            call_end_reason(&jsonrpc::Error::Io(std::io::Error::other("gone"))),
            END_READ_ERROR,
        );
    }

    #[test]
    fn versions_keeps_whatever_the_server_claimed() {
        assert_eq!(
            versions(&json!(["Fulcrum 1.12.0", "1.4"])),
            Versions {
                server: Some("Fulcrum 1.12.0".to_string()),
                protocol: Some("1.4".to_string()),
            },
        );
        assert_eq!(
            versions(&json!("ElectrumX 1.16")),
            Versions {
                server: Some("ElectrumX 1.16".to_string()),
                protocol: None,
            },
            "a server that answers one string answered the software version",
        );
        assert_eq!(
            versions(&json!(["electrs", 1.4])),
            Versions {
                server: Some("electrs".to_string()),
                protocol: Some("1.4".to_string()),
            },
            "a protocol version that is not a string is kept as the JSON it was",
        );
        assert_eq!(versions(&Value::Null), Versions::default());
        assert_eq!(
            versions(&json!([])),
            Versions::default(),
            "an empty array claims nothing",
        );
    }

    #[test]
    fn the_backoff_doubles_to_its_ceiling() {
        let min = Duration::from_secs(10);
        let max = Duration::from_secs(3600);
        let mut backoff = min;
        let mut seen = vec![backoff];
        for _ in 0..12 {
            backoff = doubled(backoff, max);
            seen.push(backoff);
        }
        assert_eq!(seen[1], Duration::from_secs(20));
        assert_eq!(seen[2], Duration::from_secs(40));
        assert_eq!(
            *seen.last().expect("twelve steps"),
            max,
            "the ceiling is reached and not passed",
        );
        assert_eq!(doubled(max, max), max);
    }

    #[test]
    fn the_jitter_stays_within_a_fifth_and_moves() {
        let base = Duration::from_secs(100);
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..200 {
            let delay = jitter(base);
            assert!(
                delay >= base.mul_f64(1.0 - JITTER) && delay <= base.mul_f64(1.0 + JITTER),
                "{delay:?} is outside the jitter window",
            );
            distinct.insert(delay);
        }
        assert!(
            distinct.len() > 100,
            "the jitter is random, not a constant: {} distinct delays",
            distinct.len(),
        );
    }

    #[test]
    fn the_stagger_is_a_fraction_of_the_cadence() {
        let cadence = Duration::from_secs(300);
        for _ in 0..200 {
            let delay = stagger(cadence);
            assert!(
                delay <= cadence.mul_f64(STAGGER),
                "{delay:?} is more than a quarter of the cadence",
            );
        }
    }

    #[test]
    fn micros_between_two_stamps_is_their_difference() {
        let sent = SystemTime::UNIX_EPOCH + Duration::from_micros(1_000);
        let received = sent + Duration::from_micros(2_500);
        assert_eq!(micros_between(sent, received), 2_500);
        assert_eq!(micros_between(received, sent), -2_500);
    }

    #[test]
    fn as_i64_saturates_rather_than_wrapping() {
        assert_eq!(as_i64(7u64), 7);
        assert_eq!(as_i64(u64::MAX), i64::MAX);
    }

    #[test]
    fn probe_result_reads_the_probe_row_and_nothing_else() {
        let probe = Event::Probe {
            id: 1,
            connection_id: 2,
            server_id: 3,
            kind: ProbeKind::Features.as_str().to_string(),
            params: json!([[]]),
            sent_at: Micros(1),
            recv_at: Some(Micros(2)),
            rtt_us: Some(1),
            result: Some(json!({ "genesis_hash": "abc" })),
            error: None,
        };
        assert_eq!(
            probe_result(&probe),
            Some(&json!({ "genesis_hash": "abc" })),
        );
        assert_eq!(
            probe_result(&Event::Ping {
                connection_id: 2,
                at: Micros(3),
                rtt_us: 4,
            }),
            None,
        );
    }
}
