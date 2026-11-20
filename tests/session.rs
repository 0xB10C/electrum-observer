//! A session against a real socket, and the rows it leaves behind.
//!
//! The unit tests in `src/session.rs` cover the vocabulary and the
//! arithmetic. What they cannot cover is the whole lifecycle, which is a
//! claim about a database: that a connection writes its `connections` row
//! with the two version strings on it, that the reply to
//! `blockchain.headers.subscribe` and every notification after it become
//! `header_events` stamped when the line arrived, that the probe timers fire
//! and land in `probes`, that two servers disagreeing at one height make
//! every session poll `blockchain.block.header`, that a dropped connection
//! comes back after the backoff, and that a server on another chain is
//! disabled and not dialed again.
//!
//! So these drive [`run_session`](electrum_observer::session::run_session)
//! against the mock Electrum server of `tests/common/mock_server.rs` with a
//! temporary database behind it, and read the tables back with `rusqlite`
//! exactly as an analysis would.
//!
//! **The cadences are one second.** They are whole seconds in the
//! configuration -- `cadence.ping_secs` and friends -- so one second is the
//! floor, and `tokio`'s paused clock is not an option here: the mock server
//! runs on a loopback socket, and auto-advancing time while a socket is in
//! flight makes every timer fire at once. Every wait is therefore a bounded
//! poll of the database rather than a sleep of a fixed length, so a slow
//! machine makes these tests slower rather than flaky.

mod common;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use electrum_observer::dial::Dialer;
use electrum_observer::discovery::AdvertisedPeer;
use electrum_observer::endpoint::Endpoint;
use electrum_observer::headers::Tracker;
use electrum_observer::session::{
    END_EOF, END_GENESIS_MISMATCH, END_HANDSHAKE_ERROR, END_PING_FAILED, END_PROTOCOL,
    END_SHUTDOWN, END_TIMEOUT, SessionContext, run_session,
};
use electrum_observer::settings::{
    CadenceSettings, DivergenceSettings, ReconnectSettings, Settings, TimeoutSettings,
};
use electrum_observer::store::{Micros, ServerRow, Store};

use common::mock_server::{
    BAD_REQUEST, BLOCK_1_HEADER, Behaviour, MockServer, Reaction, header_hash, rpc_error,
};

/// How long any wait here may take before it is a failure.
///
/// Generous on purpose: the cadences are a second and the store commits a
/// partial batch after half of one, so the expected waits are a second or
/// two and this is the bound on a loaded machine rather than the expected
/// cost.
const PATIENCE: Duration = Duration::from_secs(20);

/// How often a wait looks at the database again.
const TICK: Duration = Duration::from_millis(25);

/// The coinbase txid the contested height answers with, which is a real one
/// from block 1.
const BLOCK_1_COINBASE: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

/// Polls `ready` until it is true, or fails the test.
async fn wait_for<F: FnMut() -> bool>(what: &str, mut ready: F) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if ready() {
            return;
        }
        assert!(Instant::now() < deadline, "waited {PATIENCE:?} for {what}");
        tokio::time::sleep(TICK).await;
    }
}

/// The settings every test starts from: a second's ping and divergence poll,
/// a probe cadence far enough out that only the initial set runs, and a
/// reconnect that is quick enough to wait for.
fn settings() -> Settings {
    Settings {
        timeouts: TimeoutSettings {
            connect_secs: 5,
            request_secs: 2,
        },
        reconnect: ReconnectSettings {
            min_secs: 1,
            max_secs: 2,
        },
        cadence: CadenceSettings {
            ping_secs: 1,
            fees_secs: 60,
            identity_secs: 60,
            fingerprint_secs: 60,
        },
        divergence: DivergenceSettings {
            window_secs: 1800,
            poll_secs: 1,
        },
        ..Settings::default()
    }
}

/// The same, with every probe set on the one-second cadence too, for the
/// tests that are about the timers themselves.
fn probing_settings() -> Settings {
    Settings {
        cadence: CadenceSettings {
            ping_secs: 1,
            fees_secs: 1,
            identity_secs: 1,
            fingerprint_secs: 1,
        },
        ..settings()
    }
}

/// A header that extends `parent`, differing only in its nonce.
///
/// Two of these at one height are a chain split: real 80-byte headers that
/// name the same parent, so the tracker books two hashes at one height and
/// arms the divergence window exactly as it would against two servers on two
/// branches.
fn child(parent_hex: &str, nonce: u32) -> String {
    let bytes = hex::decode(parent_hex).expect("the parent is hex");
    let parent: Header = deserialize(&bytes).expect("the parent is a header");
    let header = Header {
        version: parent.version,
        prev_blockhash: parent.block_hash(),
        merkle_root: parent.merkle_root,
        time: parent.time + 600,
        bits: parent.bits,
        nonce,
    };
    hex::encode(serialize(&header))
}

/// A database, a writer, a tracker and a dialer: what the supervisor of step
/// 14 will build once per process.
struct Harness {
    /// Held for the lifetime of the test: dropping it deletes the database.
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: Store,
    ctx: SessionContext,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    peers_rx: mpsc::Receiver<(i64, Vec<AdvertisedPeer>)>,
}

impl Harness {
    fn new(settings: Settings) -> Harness {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let store = Store::open(&path).expect("the schema applies");
        let (writer, task) = store.writer();
        tokio::spawn(task);
        let tracker = Arc::new(Mutex::new(Tracker::new(settings.divergence.window())));
        let dialer = Arc::new(Dialer::new(&settings).expect("a dialer is built"));
        let (peers_tx, peers_rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = watch::channel(false);
        Harness {
            _dir: dir,
            path,
            store: store.clone(),
            ctx: SessionContext {
                settings: Arc::new(settings),
                dialer,
                store,
                writer,
                tracker,
                peers_tx: Some(peers_tx),
            },
            stop_tx,
            stop_rx,
            peers_rx,
        }
    }

    /// Inserts a server for a mock the test has started.
    fn add(&self, server: &MockServer) -> ServerRow {
        self.add_endpoint(&format!("tcp://{}", server.addr()))
    }

    fn add_endpoint(&self, text: &str) -> ServerRow {
        let endpoint = Endpoint::from_str(text).expect("the endpoint parses");
        self.store
            .upsert_server(&endpoint, "config", None)
            .expect("the server is inserted")
    }

    /// Starts one session, as the supervisor would.
    fn start(&self, server: &ServerRow, session_index: usize) -> JoinHandle<()> {
        tokio::spawn(run_session(
            self.ctx.clone(),
            server.clone(),
            session_index,
            self.stop_rx.clone(),
        ))
    }

    /// A reader on the live database, as `sqlite3` would attach one.
    fn db(&self) -> Connection {
        Connection::open(&self.path).expect("the database opens for reading")
    }

    fn count(&self, sql: &str) -> i64 {
        self.db()
            .query_row(sql, [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
    }

    /// The first column of the first row, if there is a row.
    fn text(&self, sql: &str) -> Option<String> {
        self.db()
            .query_row(sql, [], |row| row.get::<_, Option<String>>(0))
            .optional()
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .flatten()
    }

    fn int(&self, sql: &str) -> Option<i64> {
        self.db()
            .query_row(sql, [], |row| row.get::<_, Option<i64>>(0))
            .optional()
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .flatten()
    }

    fn texts(&self, sql: &str) -> Vec<String> {
        let db = self.db();
        let mut statement = db.prepare(sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    fn ints(&self, sql: &str) -> Vec<i64> {
        let db = self.db();
        let mut statement = db.prepare(sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
        statement
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .collect::<rusqlite::Result<Vec<i64>>>()
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    /// Raises the stop flag and waits for the session to return.
    async fn stop(&self, session: JoinHandle<()>) {
        let _ = self.stop_tx.send(true);
        tokio::time::timeout(PATIENCE, session)
            .await
            .expect("the session returns when the flag is raised")
            .expect("the session did not panic");
    }
}

/// Everything one healthy connection writes, in one test, because the point
/// of the row is that the others are beside it: a `connections` row with
/// both version strings and the address that was really reached, a
/// `header_events` row from the subscribe reply, pings, and one probe row per
/// kind of the initial, fee, identity and fingerprint sets.
#[tokio::test]
async fn a_connection_records_what_it_did() {
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(probing_settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the connection to be established", || {
        harness.count("SELECT count(*) FROM connections WHERE connected_at IS NOT NULL") == 1
    })
    .await;
    assert_eq!(
        harness
            .text("SELECT server_version FROM connections")
            .as_deref(),
        Some("Fulcrum 1.12.0"),
        "both strings server.version answered are on the connection",
    );
    assert_eq!(
        harness
            .text("SELECT protocol_version FROM connections")
            .as_deref(),
        Some("1.4"),
    );
    assert_eq!(
        harness.text("SELECT remote_ip FROM connections").as_deref(),
        Some("127.0.0.1"),
        "the address actually connected to",
    );

    wait_for("the subscribe reply", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 1
    })
    .await;
    assert_eq!(
        harness.text("SELECT hash FROM header_events").as_deref(),
        Some(header_hash(BLOCK_1_HEADER).as_str()),
        "the tip the mock server answers with",
    );
    assert_eq!(
        harness.int("SELECT height FROM header_events"),
        Some(1),
        "the height the server claimed",
    );
    assert_eq!(
        harness.int("SELECT reorg FROM header_events"),
        Some(0),
        "a subscribe reply is never a change of mind",
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM blocks"),
        1,
        "the header is booked in the cross-server block book",
    );

    wait_for("a ping", || {
        harness.count("SELECT count(*) FROM pings") >= 1
    })
    .await;
    assert!(
        harness
            .int("SELECT rtt_us FROM pings")
            .is_some_and(|rtt| rtt >= 0),
        "the ping round trip is a difference of two arrival stamps",
    );
    // The ping starts a whole cadence out rather than at once: the handshake
    // has just been answered, so a ping now would be asking the same
    // question twice. `cadence.ping_secs` is one second here, and half of it
    // is the margin.
    let connected_at = harness
        .int("SELECT connected_at FROM connections")
        .expect("the connection was established");
    let first_ping = harness
        .int("SELECT min(at) FROM pings")
        .expect("there is a ping");
    assert!(
        first_ping - connected_at >= 500_000,
        "the first ping came {} us after the connection was established",
        first_ping - connected_at,
    );

    // The initial set, then the fee set and the fingerprint set on their
    // staggered first run, then the identity set a cadence later.
    for kind in [
        "features",
        "banner",
        "donation_address",
        "relayfee",
        "mempool_info",
        "peers",
        "fee_histogram",
        "estimatefee",
        "fingerprint",
    ] {
        wait_for(kind, || {
            harness.count(&format!(
                "SELECT count(*) FROM probes WHERE kind = '{kind}'"
            )) >= 1
        })
        .await;
    }
    wait_for("the identity set to come round again", || {
        harness.count("SELECT count(*) FROM probes WHERE kind = 'features'") >= 2
    })
    .await;
    assert!(
        harness
            .text("SELECT result_blob FROM probes WHERE kind = 'features' LIMIT 1")
            .is_some(),
        "a probe result is stored by content",
    );
    // The identity set starts a whole cadence out for the same reason the
    // ping does: the initial set has just asked for all of it.
    let features = harness.ints("SELECT sent_at FROM probes WHERE kind = 'features' ORDER BY id");
    assert!(
        features[1] - features[0] >= 500_000,
        "the identity set repeated itself after {} us",
        features[1] - features[0],
    );
    // One row per advertised peer per peer list, and the identity set asks
    // for the list again, so what is constant is the three hosts.
    assert_eq!(
        harness.count("SELECT count(DISTINCT peer_host) FROM peer_edges"),
        3,
        "the three peers the mock server advertises",
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM peer_edges
             JOIN probes ON probes.id = peer_edges.probe_id
             WHERE probes.kind = 'peers'"
        ),
        harness.count("SELECT count(*) FROM peer_edges"),
        "every edge names the peer list that advertised it",
    );

    harness.stop(session).await;
    wait_for("the end of the connection", || {
        harness
            .text("SELECT end_reason FROM connections")
            .as_deref()
            == Some(END_SHUTDOWN)
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM connections"),
        1,
        "one ConnectionEnded for one ConnectionStarted",
    );
}

/// The measurement this crate exists for: a notification's `at` is when its
/// line arrived, which has to be inside the window the test held it in.
#[tokio::test]
async fn an_announcement_is_stamped_on_arrival() {
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the subscription", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 1
    })
    .await;

    let announced = child(BLOCK_1_HEADER, 7);
    let before = Micros::now();
    assert_eq!(
        server.announce_header(2, &announced),
        1,
        "the session is subscribed",
    );
    wait_for("the notification", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'notification'") == 1
    })
    .await;
    let after = Micros::now();

    let at = harness
        .int("SELECT at FROM header_events WHERE kind = 'notification'")
        .expect("the notification has a stamp");
    assert!(
        at >= before.as_i64() && at <= after.as_i64(),
        "{at} is outside {before:?}..{after:?}",
    );
    assert_eq!(
        harness
            .text("SELECT hash FROM header_events WHERE kind = 'notification'")
            .as_deref(),
        Some(header_hash(&announced).as_str()),
    );
    assert_eq!(
        harness.int("SELECT reorg FROM header_events WHERE kind = 'notification'"),
        Some(0),
        "a header that extends the tip is not a reorg",
    );
    harness.stop(session).await;
}

/// The `peers` probe's parsed rows reach the run loop, which is what makes
/// discovery possible without the session knowing anything about it.
#[tokio::test]
async fn the_peer_list_reaches_discovery() {
    let server = MockServer::start(Behaviour::default()).await;
    let mut harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    let (server_id, peers) = tokio::time::timeout(PATIENCE, harness.peers_rx.recv())
        .await
        .expect("the peer list arrives")
        .expect("the channel is open");
    assert_eq!(server_id, row.id, "the server that advertised them");
    let hosts: Vec<&str> = peers.iter().map(|peer| peer.host.as_str()).collect();
    assert_eq!(
        hosts,
        [
            "electrum.example.com",
            "fulcrum.example.de",
            "electrum.example.fr"
        ],
    );
    harness.stop(session).await;
}

/// Two servers with different hashes at one height: the block book holds
/// both, the window opens, and every session -- not only the one that saw
/// the second branch -- polls `blockchain.block.header` and asks once for the
/// coinbase of the contested height.
#[tokio::test]
async fn two_branches_make_every_session_poll() {
    let left_header = child(BLOCK_1_HEADER, 11);
    let right_header = child(BLOCK_1_HEADER, 22);
    let left = MockServer::start(Behaviour::default().header(2, &left_header).txid(
        2,
        0,
        BLOCK_1_COINBASE,
    ))
    .await;
    let right = MockServer::start(Behaviour::default().header(2, &right_header).txid(
        2,
        0,
        BLOCK_1_COINBASE,
    ))
    .await;
    let harness = Harness::new(settings());
    let left_row = harness.add(&left);
    let right_row = harness.add(&right);
    let left_session = harness.start(&left_row, 0);
    let right_session = harness.start(&right_row, 0);

    wait_for("both subscriptions", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 2
    })
    .await;

    left.announce_header(2, &left_header);
    wait_for("the first branch", || {
        harness.count(&format!(
            "SELECT count(*) FROM header_events WHERE kind = 'notification' AND server_id = {}",
            left_row.id
        )) == 1
    })
    .await;
    right.announce_header(2, &right_header);
    wait_for("the second branch", || {
        harness.count(&format!(
            "SELECT count(*) FROM header_events WHERE kind = 'notification' AND server_id = {}",
            right_row.id
        )) == 1
    })
    .await;
    // The window is open now, so the next announcement on the first server
    // lands inside it: which side a server is on is the measurement, and the
    // coinbase of the height is asked for once per connection.
    left.announce_header(2, &left_header);

    assert_eq!(
        harness.count("SELECT count(*) FROM blocks WHERE height = 2"),
        2,
        "both hashes at one height, which is the split",
    );
    for row in [&left_row, &right_row] {
        wait_for("a tip check", || {
            harness.count(&format!(
                "SELECT count(*) FROM tip_checks WHERE server_id = {} AND height = 2",
                row.id
            )) >= 1
        })
        .await;
        wait_for("a coinbase probe", || {
            harness.count(&format!(
                "SELECT count(*) FROM probes WHERE kind = 'coinbase_txid' AND server_id = {}",
                row.id
            )) == 1
        })
        .await;
    }
    assert_eq!(
        harness.text(&format!(
            "SELECT hash FROM tip_checks WHERE server_id = {} ORDER BY at LIMIT 1",
            left_row.id
        )),
        Some(header_hash(&left_header)),
        "each server is polled for what it has, not for what anyone else has",
    );
    assert_eq!(
        harness.text(&format!(
            "SELECT hash FROM tip_checks WHERE server_id = {} ORDER BY at LIMIT 1",
            right_row.id
        )),
        Some(header_hash(&right_header)),
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM probes WHERE kind = 'coinbase_txid'"),
        2,
        "once per connection per contested height, and no more",
    );

    let _ = harness.stop_tx.send(true);
    for session in [left_session, right_session] {
        let _ = tokio::time::timeout(PATIENCE, session).await;
    }
}

/// The reorg of thread #167: a server announces another header at a height
/// it has already announced, and then starts answering the poll with it.
/// `header_events.reorg` marks the change of mind and `tip_checks` shows the
/// moment the server switched.
#[tokio::test]
async fn a_reorg_shows_in_the_tip_checks() {
    let first = child(BLOCK_1_HEADER, 33);
    let second = child(BLOCK_1_HEADER, 44);
    let server = MockServer::start(Behaviour::default().header(2, &first).txid(
        2,
        0,
        BLOCK_1_COINBASE,
    ))
    .await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the subscription", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 1
    })
    .await;
    server.announce_header(2, &first);
    wait_for("the first header at that height", || {
        harness.count("SELECT count(*) FROM header_events WHERE height = 2") == 1
    })
    .await;

    // A second hash at the same height: the window opens, and
    // `blockchain.block.header` still answers the first one, which is a
    // server that has announced a branch it has not switched to yet.
    server.announce_header(2, &second);
    wait_for("the second header at that height", || {
        harness.count("SELECT count(*) FROM header_events WHERE height = 2") == 2
    })
    .await;
    assert_eq!(
        harness.count(&format!(
            "SELECT count(*) FROM header_events WHERE hash = '{}' AND reorg = 1",
            header_hash(&second)
        )),
        1,
        "a height that did not increase is the server changing its mind",
    );
    wait_for("a poll of the old branch", || {
        harness.count(&format!(
            "SELECT count(*) FROM tip_checks WHERE hash = '{}'",
            header_hash(&first)
        )) >= 1
    })
    .await;

    server.set_header(2, &second);
    wait_for("the switch", || {
        harness.count(&format!(
            "SELECT count(*) FROM tip_checks WHERE hash = '{}'",
            header_hash(&second)
        )) >= 1
    })
    .await;
    let hashes = harness.texts("SELECT hash FROM tip_checks ORDER BY at");
    assert_eq!(
        hashes.first().map(String::as_str),
        Some(header_hash(&first).as_str()),
        "the polls before the switch are the old branch: {hashes:?}",
    );
    assert_eq!(
        hashes.last().map(String::as_str),
        Some(header_hash(&second).as_str()),
        "and the polls after it are the new one: {hashes:?}",
    );
    harness.stop(session).await;
}

/// A server that will not answer the poll is recorded by what it said
/// instead: a refusal, an answer that is not a header, and a header that is
/// not 80 bytes of hexadecimal are all `tip_checks.error` with no hash,
/// because "this server would not say what it has at that height" is as much
/// of an answer as a hash is.
#[tokio::test]
async fn a_poll_that_cannot_be_read_is_recorded_as_the_error() {
    // The default `headers` knows heights 0 and 1 only, so the contested
    // height 2 is a height this server does not have.
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the subscription", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 1
    })
    .await;
    server.announce_header(2, &child(BLOCK_1_HEADER, 55));
    wait_for("the first header at that height", || {
        harness.count("SELECT count(*) FROM header_events WHERE height = 2") == 1
    })
    .await;
    server.announce_header(2, &child(BLOCK_1_HEADER, 66));
    wait_for("the refusal of the poll", || {
        harness.count(
            "SELECT count(*) FROM tip_checks
             WHERE height = 2 AND hash IS NULL AND error IS NOT NULL",
        ) >= 1
    })
    .await;
    assert!(
        harness
            .int("SELECT rtt_us FROM tip_checks WHERE error IS NOT NULL LIMIT 1")
            .is_some(),
        "a refusal is still a round trip",
    );

    server.set_behaviour(
        Behaviour::default().on("blockchain.block.header", Reaction::Result(json!(42))),
    );
    wait_for("an answer that is not a header", || {
        harness
            .count("SELECT count(*) FROM tip_checks WHERE error LIKE 'the header is not a string%'")
            >= 1
    })
    .await;

    server.set_behaviour(
        Behaviour::default().on("blockchain.block.header", Reaction::Result(json!("zz"))),
    );
    wait_for("a header that is not hexadecimal", || {
        harness.count(
            "SELECT count(*) FROM tip_checks WHERE error LIKE 'the header is not hexadecimal%'",
        ) >= 1
    })
    .await;

    // And a poll that is never answered at all, which is the one outcome
    // that has no round trip to record.
    server.set_behaviour(Behaviour::default().on("blockchain.block.header", Reaction::Never));
    wait_for("a poll that was never answered", || {
        harness.count("SELECT count(*) FROM tip_checks WHERE rtt_us IS NULL AND error IS NOT NULL")
            >= 1
    })
    .await;
    harness.stop(session).await;
}

/// A server that refuses `server.version` is a server that cannot be asked
/// anything else, which is why the handshake is the first message.
#[tokio::test]
async fn a_refused_handshake_ends_the_connection() {
    let server = MockServer::start(Behaviour::default().on(
        "server.version",
        Reaction::Error(rpc_error(BAD_REQUEST, "unsupported protocol version")),
    ))
    .await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the end of the connection", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some(END_HANDSHAKE_ERROR)
    })
    .await;
    assert_eq!(
        harness.int("SELECT connected_at FROM connections WHERE id = 1"),
        None,
        "a server that refused the handshake was never usable",
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM probes"),
        0,
        "and nothing was asked of it",
    );
    harness.stop(session).await;
}

/// A server that refuses the subscription has nothing this collector wants,
/// so the connection is ended rather than held open.
#[tokio::test]
async fn a_refused_subscription_ends_the_connection() {
    let server = MockServer::start(Behaviour::default().on(
        "blockchain.headers.subscribe",
        Reaction::Error(rpc_error(BAD_REQUEST, "subscriptions are disabled")),
    ))
    .await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the end of the connection", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some(END_PROTOCOL)
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM header_events"),
        0,
        "a server that does not subscribe announces nothing",
    );
    assert!(
        harness
            .int("SELECT connected_at FROM connections WHERE id = 1")
            .is_some(),
        "the handshake did finish, which is what the row says",
    );

    // A subscription that is never answered is the other half of the same
    // step, and `timeouts.request_secs` is what bounds it.
    server.set_behaviour(Behaviour::default().on("blockchain.headers.subscribe", Reaction::Never));
    wait_for("a subscription that was never answered", || {
        harness.count(&format!(
            "SELECT count(*) FROM connections WHERE end_reason = '{END_TIMEOUT}'"
        )) >= 1
    })
    .await;
    harness.stop(session).await;
}

/// A ping that is refused ends the connection: the ping exists to tell a
/// live connection from a socket that is open and dead.
#[tokio::test]
async fn a_refused_ping_ends_the_connection() {
    let server = MockServer::start(
        Behaviour::default().on("server.ping", Reaction::Error(rpc_error(BAD_REQUEST, "no"))),
    )
    .await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the end of the connection", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some(END_PING_FAILED)
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM pings"),
        0,
        "a refused ping is not a round trip",
    );
    wait_for("the reconnect", || {
        harness.count("SELECT count(*) FROM connections") == 2
    })
    .await;

    // A ping that is never answered is the same failure arriving as a
    // timeout rather than as a refusal.
    server.set_behaviour(Behaviour::default().on("server.ping", Reaction::Never));
    wait_for("a second connection ended by the ping", || {
        harness.count(&format!(
            "SELECT count(*) FROM connections WHERE end_reason = '{END_PING_FAILED}'"
        )) >= 2
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM pings"),
        0,
        "and a ping that never came back is not one either",
    );
    harness.stop(session).await;
}

/// A peer list nobody can read is still a `probes` row and is not handed to
/// discovery: what the server said is the datum, and there is nothing in it
/// to dial.
#[tokio::test]
async fn an_unreadable_peer_list_is_not_handed_on() {
    let server = MockServer::start(Behaviour::default().on(
        "server.peers.subscribe",
        Reaction::Error(rpc_error(BAD_REQUEST, "peers are not published")),
    ))
    .await;
    // The identity set repeats the peer list every second, so the second
    // shape below is asked for without waiting for a reconnect.
    let mut harness = Harness::new(probing_settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the refused peer list", || {
        harness.count("SELECT count(*) FROM probes WHERE kind = 'peers' AND error IS NOT NULL") >= 1
    })
    .await;

    server.set_behaviour(Behaviour {
        peers: json!("nonsense"),
        ..Behaviour::default()
    });
    wait_for("a peer list that is not a list", || {
        harness
            .count("SELECT count(*) FROM probes WHERE kind = 'peers' AND result_blob IS NOT NULL")
            >= 1
    })
    .await;

    assert_eq!(
        harness.count("SELECT count(*) FROM peer_edges"),
        0,
        "neither answer held a row to turn into an edge",
    );
    assert!(
        harness.peers_rx.try_recv().is_err(),
        "and neither was handed to discovery",
    );
    harness.stop(session).await;
}

/// A server named by a hostname has its lookup recorded, and the connection
/// names the lookup it used: a name that round-robins over several addresses
/// is a hint about how many machines are behind it.
#[tokio::test]
async fn a_hostname_records_the_lookup_it_used() {
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(settings());
    // `localhost` is in `/etc/hosts` on every host this runs on, and the
    // mock listens on 127.0.0.1; a dial that picked ::1 is refused and
    // retried, which is why this waits for a connection rather than the
    // first attempt.
    let row = harness.add_endpoint(&format!("tcp://localhost:{}", server.addr().port()));
    let session = harness.start(&row, 0);

    wait_for("a connection through the resolver", || {
        harness.count("SELECT count(*) FROM connections WHERE connected_at IS NOT NULL") == 1
    })
    .await;
    let addresses = harness
        .text("SELECT addresses FROM dns_resolutions ORDER BY id DESC LIMIT 1")
        .expect("the lookup is a row of its own");
    assert!(
        addresses.contains("127.0.0.1"),
        "every record of the lookup is kept: {addresses}",
    );
    assert!(
        harness
            .int("SELECT dns_id FROM connections WHERE connected_at IS NOT NULL")
            .is_some(),
        "the connection names the lookup that chose its address",
    );
    harness.stop(session).await;
}

/// A server that drops the connection is recorded as an EOF and dialed
/// again after the backoff, which is the uptime data in `connections`.
#[tokio::test]
async fn a_dropped_connection_comes_back() {
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the first connection", || {
        harness.count("SELECT count(*) FROM connections WHERE connected_at IS NOT NULL") == 1
    })
    .await;
    server.disconnect_all();

    wait_for("the end of the first connection", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some(END_EOF)
    })
    .await;
    wait_for("the second connection", || {
        harness.count("SELECT count(*) FROM connections WHERE connected_at IS NOT NULL") == 2
    })
    .await;

    let ended = harness
        .int("SELECT ended_at FROM connections WHERE id = 1")
        .expect("the first connection ended");
    let started = harness
        .int("SELECT started_at FROM connections WHERE id = 2")
        .expect("the second connection started");
    // `reconnect.min_secs` is one second and the jitter is a fifth either
    // way, so the gap is at least 0.8 s; the margin is for a clock that is
    // read twice rather than for the backoff.
    assert!(
        started - ended >= 700_000,
        "the reconnect waited {} us, which is no backoff at all",
        started - ended,
    );
    assert_eq!(
        harness.int("SELECT session_index FROM connections WHERE id = 2"),
        Some(0),
        "the reconnect is the same session",
    );
    harness.stop(session).await;
}

/// A server on another chain is disabled and not dialed again: its headers
/// would otherwise go into the cross-server block book.
#[tokio::test]
async fn a_genesis_mismatch_disables_the_server() {
    // A hash that is a real block hash and is not any chain's genesis.
    let behaviour = Behaviour {
        features: json!({
            "genesis_hash": header_hash(BLOCK_1_HEADER),
            "server_version": "Fulcrum 1.12.0",
        }),
        ..Behaviour::default()
    };
    let server = MockServer::start(behaviour).await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    tokio::time::timeout(PATIENCE, session)
        .await
        .expect("the session gives up on a server on another chain")
        .expect("the session did not panic");

    wait_for("the disabled server", || {
        harness.count("SELECT count(*) FROM servers WHERE enabled = 0") == 1
    })
    .await;
    assert_eq!(
        harness
            .text(&format!(
                "SELECT disabled_reason FROM servers WHERE id = {}",
                row.id
            ))
            .as_deref(),
        Some(END_GENESIS_MISMATCH),
    );
    wait_for("the end of the connection", || {
        harness
            .text("SELECT end_reason FROM connections")
            .as_deref()
            == Some(END_GENESIS_MISMATCH)
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM connections"),
        1,
        "and it is not dialed again",
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM header_events"),
        0,
        "nothing from another chain is booked",
    );
}

/// A session after the first is the noise floor of thread #167: headers and
/// pings, and not one probe set, however often the timers fire.
#[tokio::test]
async fn a_second_session_only_watches() {
    let server = MockServer::start(Behaviour::default()).await;
    let harness = Harness::new(probing_settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 1);

    wait_for("the subscription", || {
        harness.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 1
    })
    .await;
    wait_for("two pings, which is two cadences of probing", || {
        harness.count("SELECT count(*) FROM pings") >= 2
    })
    .await;
    assert_eq!(
        harness.count("SELECT count(*) FROM probes"),
        0,
        "a noise-floor session costs the server nothing beyond the ping",
    );
    assert_eq!(
        harness.int("SELECT session_index FROM connections"),
        Some(1),
    );
    harness.stop(session).await;
}

/// A server that answers the handshake with nothing at all is a timeout,
/// bounded by `timeouts.request_secs` rather than by the connection.
#[tokio::test]
async fn a_handshake_that_is_never_answered_times_out() {
    let server =
        MockServer::start(Behaviour::default().on("server.version", Reaction::Never)).await;
    let harness = Harness::new(settings());
    let row = harness.add(&server);
    let session = harness.start(&row, 0);

    wait_for("the timeout", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some(END_TIMEOUT)
    })
    .await;
    assert_eq!(
        harness.int("SELECT connected_at FROM connections WHERE id = 1"),
        None,
        "a connection that never answered was never usable",
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM header_events"),
        0,
        "nothing is asked before server.version has been answered",
    );
    harness.stop(session).await;
}

/// A port that refuses is a `connections` row too: that a server is gone is
/// the observation, and nothing else records it.
#[tokio::test]
async fn a_refused_port_is_a_connection_row() {
    let harness = Harness::new(settings());
    // Port 1 rather than a port this test bound and released: nothing an
    // unprivileged process can bind is ever listening there, while a
    // released ephemeral port is one the kernel may hand to the next test
    // that asks for one -- and then this test would be dialling a mock
    // server.
    let row = harness.add_endpoint("tcp://127.0.0.1:1");
    let session = harness.start(&row, 0);

    wait_for("the refusal", || {
        harness
            .text("SELECT end_reason FROM connections WHERE id = 1")
            .as_deref()
            == Some("refused")
    })
    .await;
    assert_eq!(
        harness.int("SELECT connected_at FROM connections WHERE id = 1"),
        None,
    );
    harness.stop(session).await;
}
