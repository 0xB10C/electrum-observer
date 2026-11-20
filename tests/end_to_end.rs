//! The collector itself, in process, against two mock Electrum servers.
//!
//! The claim this crate is verified against: two mock servers, one of them
//! announcing a fork, and the rows that have to appear in `header_events`,
//! `blocks`, `tip_checks`, `probes` and `peer_edges`. What the session tests
//! cannot show is everything that is only true of a *run* -- that the
//! configured list becomes sessions, that a peer list becomes a server and a
//! session of its own, that one tracker is shared so that two servers
//! disagreeing arms the divergence poll in both, that identical answers from
//! two servers key one blob, that `meta` says which configuration produced
//! the database, and that a shutdown ends every connection and loses
//! nothing.
//!
//! So this drives [`electrum_observer::run::run`] exactly as `main.rs` does,
//! from a configuration file written into a temporary directory, and reads
//! the tables back with `rusqlite` as an analysis would.
//!
//! **The cadences in that file are one second**, which is the floor the
//! configuration allows, and `tor.enabled` is false: nothing here may reach
//! the Tor network, and nothing here may sleep through a default cadence of
//! five minutes. Every wait is a bounded poll of the database rather than a
//! fixed sleep, so a loaded machine makes this test slower rather than
//! flaky.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;

use electrum_observer::store::sha256_hex;
use electrum_observer::{Settings, Shutdown, run};

use common::mock_server::{BLOCK_1_HEADER, Behaviour, MockServer, header_hash};

/// How long any wait here may take before it is a failure.
///
/// Generous on purpose: the cadences are a second, the store commits a
/// partial batch after half of one, and this test waits for a server to be
/// discovered before it is connected to. This is the bound on a loaded
/// machine and not the expected cost.
const PATIENCE: Duration = Duration::from_secs(30);

/// How often a wait looks at the database again.
const TICK: Duration = Duration::from_millis(25);

/// A real coinbase txid, which both servers answer for the contested height.
const BLOCK_1_COINBASE: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

/// Every probe kind a healthy connection writes within a second or two of
/// being established: the initial set, then the fee, identity and
/// fingerprint sets on their staggered first run.
const PROBE_KINDS: &[&str] = &[
    "features",
    "banner",
    "donation_address",
    "relayfee",
    "mempool_info",
    "peers",
    "fee_histogram",
    "estimatefee",
    "fingerprint",
];

/// A header that extends `parent`, differing only in its nonce.
///
/// Two of these at one height are a chain split: real 80-byte headers naming
/// the same parent, so the tracker books two hashes at one height and arms
/// the divergence window exactly as it would against two servers on two
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

/// The live database, read as `sqlite3` would attach to it.
struct Db(PathBuf);

impl Db {
    fn conn(&self) -> Connection {
        Connection::open(&self.0).expect("the database opens for reading")
    }

    fn count(&self, sql: &str) -> i64 {
        self.conn()
            .query_row(sql, [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
    }

    fn text(&self, sql: &str) -> Option<String> {
        self.conn()
            .query_row(sql, [], |row| row.get::<_, Option<String>>(0))
            .optional()
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .flatten()
    }

    /// Polls until the collector has opened the database.
    ///
    /// Nothing can be read before that, and not because of a race worth
    /// fixing: `run` creates the file, so until its first few lines have run
    /// there is no file to attach to. Opened only once it exists, because
    /// `rusqlite` would otherwise create an empty one at the path the
    /// collector is about to open.
    async fn wait_for_schema(&self) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if self.0.exists()
                && self
                    .conn()
                    .query_row(
                        "SELECT count(*) FROM sqlite_master WHERE name = 'connections'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap_or(0)
                    == 1
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "waited {PATIENCE:?} for the collector to open {}",
                self.0.display(),
            );
            tokio::time::sleep(TICK).await;
        }
    }

    /// Polls `ready` until it is true, or fails the test.
    async fn wait_for<F: FnMut(&Db) -> bool>(&self, what: &str, mut ready: F) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if ready(self) {
                return;
            }
            assert!(Instant::now() < deadline, "waited {PATIENCE:?} for {what}");
            tokio::time::sleep(TICK).await;
        }
    }
}

/// The configuration file the run is given, and the text it is hashed from.
///
/// Every cadence is a second, `tor.enabled` is false, and `discovery` is on
/// with a cap far above the two servers this test has: what is under test is
/// the wiring, so nothing here may be switched off that the daemon does by
/// default.
fn write_config(dir: &Path, database: &Path, servers_file: &Path) -> (PathBuf, String) {
    let path = dir.join("observer.yaml");
    let text = format!(
        "chain: mainnet\n\
         database: {database}\n\
         servers_file: {servers_file}\n\
         sessions_per_server: 1\n\
         timeouts: {{ connect_secs: 5, request_secs: 2 }}\n\
         reconnect: {{ min_secs: 1, max_secs: 2 }}\n\
         cadence: {{ ping_secs: 1, fees_secs: 1, identity_secs: 1, fingerprint_secs: 1 }}\n\
         divergence: {{ window_secs: 1800, poll_secs: 1 }}\n\
         discovery: {{ enabled: true, max_servers: 600 }}\n\
         tor: {{ enabled: false }}\n\
         log: {{ level: info }}\n",
        database = database.display(),
        servers_file = servers_file.display(),
    );
    std::fs::write(&path, &text).expect("the temporary directory is writable");
    (path, text)
}

/// The whole collector: two servers, a discovered third party, a fork, a
/// reorg, and a shutdown that loses nothing.
///
/// One test rather than five, because what is being asserted is that these
/// facts hold *of one run*: a second run would be a second process whose
/// sessions, tracker and writer are not the ones that produced the rows
/// before it, and the cost of starting one would be paid five times.
#[tokio::test]
async fn a_run_collects_two_servers_a_fork_and_its_own_shutdown() {
    // Server B is started first, because A advertises it and the
    // advertisement carries B's port.
    let branch_a = child(BLOCK_1_HEADER, 101);
    let branch_b = child(BLOCK_1_HEADER, 202);
    let server_b = MockServer::start(
        Behaviour {
            // B advertises nobody, so every `peer_edges` row and every
            // discovered server in this test came from A.
            peers: json!([]),
            ..Behaviour::default()
        }
        .header(2, &branch_b)
        .txid(2, 0, BLOCK_1_COINBASE),
    )
    .await;
    let port_b = server_b.addr().port();
    let server_a = MockServer::start(
        Behaviour {
            peers: json!([["127.0.0.1", "127.0.0.1", ["v1.4", format!("t{port_b}")]]]),
            ..Behaviour::default()
        }
        .header(2, &branch_a)
        .txid(2, 0, BLOCK_1_COINBASE),
    )
    .await;
    let port_a = server_a.addr().port();

    let dir = tempfile::tempdir().expect("a temporary directory");
    let database = dir.path().join("observer.sqlite");
    let list = dir.path().join("servers.txt");
    std::fs::write(&list, format!("tcp://127.0.0.1:{port_a}\n")).expect("the list is written");
    let (config, config_text) = write_config(dir.path(), &database, &list);

    let settings = Settings::load(&config).expect("the configuration loads");
    let shutdown = Shutdown::new();
    let collector = tokio::spawn(run::run(settings, shutdown.clone()));
    let db = Db(database.clone());
    db.wait_for_schema().await;

    // (a) Only A was configured. Its peer list names B, so discovery
    // inserts B with the source that says who advertised it, and the
    // supervisor opens a session to it on this run rather than the next one.
    db.wait_for("the configured server to connect", |db| {
        db.count(&format!(
            "SELECT count(*) FROM connections c JOIN servers s ON s.id = c.server_id
              WHERE s.port = {port_a} AND c.connected_at IS NOT NULL"
        )) == 1
    })
    .await;
    let id_a = db.count(&format!("SELECT id FROM servers WHERE port = {port_a}"));
    db.wait_for("the advertised server to be inserted", |db| {
        db.count(&format!(
            "SELECT count(*) FROM servers WHERE port = {port_b}"
        )) == 1
    })
    .await;
    assert_eq!(
        db.text(&format!("SELECT source FROM servers WHERE port = {port_b}")),
        Some(format!("peers:{id_a}")),
        "a discovered server says which server advertised it",
    );
    db.wait_for("the discovered server to connect", |db| {
        db.count(&format!(
            "SELECT count(*) FROM connections c JOIN servers s ON s.id = c.server_id
              WHERE s.port = {port_b} AND c.connected_at IS NOT NULL"
        )) == 1
    })
    .await;
    let id_b = db.count(&format!("SELECT id FROM servers WHERE port = {port_b}"));

    // (b) Two different hashes at one height: the book holds both, and the
    // window that opens makes *every* session poll, which is the thing one
    // shared tracker is for.
    db.wait_for("both subscriptions", |db| {
        db.count("SELECT count(*) FROM header_events WHERE kind = 'subscribe'") == 2
    })
    .await;
    assert_eq!(server_a.announce_header(2, &branch_a), 1);
    db.wait_for("the first branch", |db| {
        db.count(&format!(
            "SELECT count(*) FROM header_events
              WHERE kind = 'notification' AND server_id = {id_a}"
        )) == 1
    })
    .await;
    assert_eq!(server_b.announce_header(2, &branch_b), 1);
    db.wait_for("the second branch", |db| {
        db.count(&format!(
            "SELECT count(*) FROM header_events
              WHERE kind = 'notification' AND server_id = {id_b}"
        )) == 1
    })
    .await;
    assert_eq!(
        db.count("SELECT count(*) FROM blocks WHERE height = 2"),
        2,
        "both hashes at one height, which is the split",
    );
    // The window is open now, so this announcement lands inside it: the
    // coinbase of a contested height is asked for when a header arrives
    // while the split is open, once per connection, and B's own
    // announcement above was the one that opened it.
    assert_eq!(server_a.announce_header(2, &branch_a), 1);
    for (id, branch) in [(id_a, &branch_a), (id_b, &branch_b)] {
        db.wait_for("a tip check of the branch this server is on", |db| {
            db.count(&format!(
                "SELECT count(*) FROM tip_checks
                  WHERE server_id = {id} AND height = 2 AND hash = '{}'",
                header_hash(branch)
            )) >= 1
        })
        .await;
        db.wait_for("the coinbase of the contested height", |db| {
            db.count(&format!(
                "SELECT count(*) FROM probes
                  WHERE kind = 'coinbase_txid' AND server_id = {id}"
            )) == 1
        })
        .await;
    }

    // And the reorg of thread #167: B changes its mind and ends up on A's
    // branch, which is a `header_events` row flagged as a change of mind and
    // a `tip_check` that shows the moment it switched.
    server_b.set_header(2, &branch_a);
    assert_eq!(server_b.announce_header(2, &branch_a), 1);
    db.wait_for("B to announce the other branch as a reorg", |db| {
        db.count(&format!(
            "SELECT count(*) FROM header_events
              WHERE server_id = {id_b} AND hash = '{}' AND reorg = 1",
            header_hash(&branch_a)
        )) == 1
    })
    .await;
    db.wait_for("B to be polled on the branch it switched to", |db| {
        db.count(&format!(
            "SELECT count(*) FROM tip_checks WHERE server_id = {id_b} AND hash = '{}'",
            header_hash(&branch_a)
        )) >= 1
    })
    .await;

    // (c) The probe sets of both servers, the advertisement graph, and the
    // content addressing that makes "did these two answer the same thing" an
    // index lookup.
    for kind in PROBE_KINDS {
        for id in [id_a, id_b] {
            db.wait_for(kind, |db| {
                db.count(&format!(
                    "SELECT count(*) FROM probes WHERE kind = '{kind}' AND server_id = {id}"
                )) >= 1
            })
            .await;
        }
    }
    assert!(
        db.count(&format!(
            "SELECT count(*) FROM peer_edges WHERE from_server_id = {id_a}
              AND peer_host = '127.0.0.1'"
        )) >= 1,
        "A advertised B, which is an edge whether or not it was dialed",
    );
    assert_eq!(
        db.count(&format!(
            "SELECT count(*) FROM peer_edges WHERE from_server_id = {id_b}"
        )),
        0,
        "and B advertised nobody",
    );
    assert!(
        db.count("SELECT count(*) FROM probes WHERE kind = 'features'") >= 2,
        "both servers answered server.features",
    );
    assert_eq!(
        db.count("SELECT count(DISTINCT result_blob) FROM probes WHERE kind = 'features'"),
        1,
        "two servers answering the same thing key one blob",
    );

    // (d) What the database says about itself.
    assert_eq!(
        db.text("SELECT value FROM meta WHERE key = 'schema_version'"),
        Some("1".to_string()),
    );
    assert_eq!(
        db.text("SELECT value FROM meta WHERE key = 'config_sha256'"),
        Some(sha256_hex(config_text.as_bytes())),
        "the hash of the configuration text this run was given",
    );
    let started_at = db
        .text("SELECT value FROM meta WHERE key = 'started_at'")
        .expect("the run stamped its start")
        .parse::<i64>()
        .expect("started_at is microseconds");
    assert!(started_at > 1_700_000_000_000_000, "{started_at}");

    // (e) The shutdown: the flag, every connection ended with the reason
    // that says why, and a database a reader can still use.
    shutdown.stop();
    tokio::time::timeout(Duration::from_secs(20), collector)
        .await
        .expect("run returns when the flag is raised")
        .expect("the collector did not panic")
        .expect("the collector stopped cleanly");

    assert_eq!(
        db.count("SELECT count(*) FROM connections"),
        2,
        "one connection each, neither of which ever had to come back",
    );
    assert_eq!(
        db.count(
            "SELECT count(*) FROM connections
              WHERE ended_at IS NULL OR end_reason IS NOT 'shutdown'"
        ),
        0,
        "every connection was closed by the shutdown and says so",
    );
    assert_eq!(
        db.text("PRAGMA integrity_check").as_deref(),
        Some("ok"),
        "the database the sessions were writing to is consistent",
    );
}
