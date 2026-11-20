//! The SQLite database: the schema, the few direct queries, and the writer
//! task that everything else sends its observations to.
//!
//! This module is the only implementation of the data model: no other module
//! names a table, a column or a `rusqlite` type. What leaves here is
//! [`ServerRow`], [`Micros`] and the ids the counters hand out, so that a
//! change to the schema is a change to this file.
//!
//! The store has two faces, because what it is asked to do has two shapes.
//!
//! The **direct, synchronous API** -- [`Store::upsert_server`],
//! [`Store::enabled_servers`], [`Store::set_meta`] -- is for the handful of
//! operations whose answer the caller needs before it can continue: the
//! supervisor cannot open a session to a server whose id it does not know,
//! and the discovery cap is a count that has to be taken and acted on without
//! another thread inserting in between, which is why the check and the insert
//! are one transaction rather than two calls.
//!
//! The **writer task** is for everything else, which is almost everything:
//! header events, pings, probes, tip checks. Those are a stream that nobody
//! waits for, so they go down one mpsc channel to one task that owns the
//! connection and commits them in batched transactions. SQLite has one writer
//! anyway; making that explicit means no session ever blocks on a lock, and
//! the order of what is written is the order of what was observed.
//!
//! Three things the data model leaves to the implementation, decided here:
//!
//! - **Ids are chosen by the client, not by SQLite.** A session needs the id
//!   of its connection to label the rows it is about to write, and a probe's
//!   id has to be in `peer_edges` in the same batch that writes the probe.
//!   `last_insert_rowid` cannot answer either question, because the row does
//!   not exist yet when the session needs the number. So `connections`,
//!   `probes` and `dns_resolutions` get their ids from atomic counters
//!   seeded from `max(id)` when the database is opened.
//! - **`meta` is a key-value table**, not one row of three columns:
//!   `schema_version`, `config_sha256` and `started_at` are written at
//!   different moments by different callers, and the next fact about the
//!   database is then a row rather than a migration.
//! - **A failed write is logged and skipped, not propagated.** One row that
//!   violates a constraint must not stop the collection -- the point of the
//!   daemon is the rows that follow it. A failure to *open* or *migrate* is
//!   fatal, because a database the code does not understand is not one it
//!   should be appending to.

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::TARGET_STORE;
use crate::endpoint::Endpoint;
use crate::headers::KnownBlock;

/// The schema this build writes and reads, as it is stored in
/// `meta.schema_version`.
///
/// Always [`MIGRATIONS`]`.len()`: a version is the number of migrations that
/// have been applied, so the two cannot drift.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// The migrations, in order, each one taking the database from version `i` to
/// version `i + 1`.
///
/// There is one today and the list is still the mechanism: a schema change
/// appends a file here instead of editing `schema.sql`, and the loop in
/// [`Store::open`] applies whatever a database is missing in one transaction
/// per step, so a half-applied migration cannot be committed.
const MIGRATIONS: &[&str] = &[include_str!("store/schema.sql")];

/// How long a statement waits for another writer before it gives up.
///
/// There is one writer in this process, so the contention this covers is the
/// reader attached to the live database that WAL mode exists for, plus the
/// direct calls of the supervisor. A few seconds is far more than either
/// needs and still bounded, so a stuck reader shows up as a logged failure
/// rather than as a collector that silently stopped.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// How many events may be queued before a session waits.
///
/// 450 servers producing a header event each within a few milliseconds of one
/// another is the burst this absorbs; past it, backpressure is better than a
/// heap that grows with the disk's backlog.
pub const CHANNEL_EVENTS: usize = 8192;

/// How many events are committed in one transaction.
const BATCH_EVENTS: usize = 256;

/// How long a partial batch waits for company before it is committed anyway.
///
/// The bound on how long an observation can sit in memory, and so on what a
/// crash costs: half a second of a quiet chain is nothing, and half a second
/// of a busy one is a full batch long before the timer fires.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// A point in time as the database stores it: microseconds since the Unix
/// epoch.
///
/// Every timestamp in the schema is this. It is a newtype rather than an
/// `i64` so that the conversion from [`SystemTime`] happens once, here, at
/// the boundary: the rest of the crate stamps what it observes with
/// `SystemTime::now()` where the bytes arrive and hands that over, which is
/// the whole discipline of this crate -- the number in the row is when the
/// last byte was read, not when the row was written.
///
/// Microseconds because the signal is tens of milliseconds and the noise
/// floor is a scheduler's wake-up, so the unit has to be smaller than both
/// and need not be smaller than a microsecond. Signed because `SystemTime`
/// is, and a clock set before 1970 is a broken host rather than a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Micros(pub i64);

impl Micros {
    /// Now, from the system clock.
    pub fn now() -> Self {
        SystemTime::now().into()
    }

    /// The raw count, for arithmetic that has nothing to do with the
    /// database -- a round trip time is a difference of two of these.
    pub fn as_i64(self) -> i64 {
        self.0
    }

    /// Back to a [`SystemTime`], for a caller that has to compare against
    /// one it did not take itself.
    pub fn to_system_time(self) -> SystemTime {
        let magnitude = Duration::from_micros(self.0.unsigned_abs());
        if self.0.is_negative() {
            UNIX_EPOCH - magnitude
        } else {
            UNIX_EPOCH + magnitude
        }
    }
}

impl From<SystemTime> for Micros {
    /// Saturates rather than panicking on a clock far outside the range an
    /// `i64` of microseconds covers, which is ±292 000 years: a host whose
    /// clock says that has a problem this crate cannot fix and should not
    /// crash over.
    fn from(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(since) => Micros(i64::try_from(since.as_micros()).unwrap_or(i64::MAX)),
            Err(before) => {
                Micros(-i64::try_from(before.duration().as_micros()).unwrap_or(i64::MAX))
            }
        }
    }
}

impl ToSql for Micros {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0))
    }
}

impl FromSql for Micros {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        i64::column_result(value).map(Micros)
    }
}

/// The hexadecimal sha256 of some bytes, as `blobs.sha256` and
/// `meta.config_sha256` spell it.
///
/// Public because the configuration hash is taken by whoever read the
/// configuration file, not by the store, and both have to be the same
/// function or the two columns mean different things.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Which message a header arrived in.
///
/// The reply to `blockchain.headers.subscribe` and a later notification are
/// both first-seen evidence, but only the second one is evidence about *this*
/// block: the subscribe reply is whatever the server's tip happened to be
/// when we connected, so an analysis that does not separate them measures
/// our own connection times.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderKind {
    /// The reply to `blockchain.headers.subscribe`.
    Subscribe,
    /// A `blockchain.headers.subscribe` notification.
    Notification,
}

impl HeaderKind {
    /// The spelling in `header_events.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            HeaderKind::Subscribe => "subscribe",
            HeaderKind::Notification => "notification",
        }
    }
}

/// The disabled reason written when a server arrives past
/// `discovery.max_servers`.
pub const REASON_CAP: &str = "cap";

/// One known server, as the supervisor reads it back.
///
/// The endpoint is reassembled from its columns rather than kept as the
/// string, so a caller gets the same [`Endpoint`] the config file would have
/// given it -- including the host kind, which decides whether the session
/// needs Tor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRow {
    pub id: i64,
    pub endpoint: Endpoint,
    /// `config`, `1209k`, `sparrow` or `peers:<server_id>`.
    pub source: String,
    pub added_at: Micros,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}

/// A certificate as the handshake presented it, with what the handshake
/// negotiated around it.
///
/// One value rather than eight fields on the event because they arrive
/// together or not at all: a plain TCP connection has none of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsInfo {
    /// Hexadecimal sha256 of `der`, which is the certificate's identity in
    /// `tls_certs` and the join key of "which hostnames presented the same
    /// certificate".
    pub sha256: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    pub not_before: Option<Micros>,
    pub not_after: Option<Micros>,
    pub der: Vec<u8>,
    /// What the handshake negotiated; stored on the connection, not on the
    /// certificate, because it is a property of this conversation.
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
}

/// One peer a server advertised, normalised out of a
/// `server.peers.subscribe` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEdge {
    pub peer_host: String,
    pub peer_ip: Option<String>,
    pub features: Vec<String>,
}

/// Something a session observed, on its way to exactly one transaction.
///
/// One variant per write the schema accepts. The variants carry ids the
/// session chose ([`Store::next_connection_id`] and friends) rather than
/// returning them, because an event that had to be answered would make the
/// channel a round trip and put the writer back on the measurement path.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// A dial has begun. Written on the attempt, so a dial that never
    /// connects is a row too.
    ConnectionStarted {
        id: i64,
        server_id: i64,
        session_index: i64,
        started_at: Micros,
    },
    /// The dial succeeded and the handshake answered: fills in the rest of
    /// the `connections` row.
    ConnectionEstablished {
        id: i64,
        connected_at: Micros,
        remote_ip: Option<String>,
        tls: Option<TlsInfo>,
        dns_id: Option<i64>,
        server_version: Option<String>,
        protocol_version: Option<String>,
    },
    /// The connection is gone, for whatever reason.
    ConnectionEnded {
        id: i64,
        ended_at: Micros,
        end_reason: String,
    },
    /// One lookup, with every record it returned.
    DnsResolved {
        id: i64,
        server_id: i64,
        at: Micros,
        addresses: Vec<String>,
        error: Option<String>,
    },
    /// A header a server told us about. Writes `header_events` and books the
    /// block in `blocks`.
    Header {
        connection_id: i64,
        server_id: i64,
        at: Micros,
        kind: HeaderKind,
        height: i64,
        hash: String,
        prev_hash: Option<String>,
        header_hex: String,
        reorg: bool,
    },
    /// One `blockchain.block.header` poll during a divergence window.
    TipCheck {
        server_id: i64,
        connection_id: i64,
        at: Micros,
        height: Option<i64>,
        hash: Option<String>,
        rtt_us: Option<i64>,
        error: Option<String>,
    },
    /// One `server.ping` round trip.
    Ping {
        connection_id: i64,
        at: Micros,
        rtt_us: i64,
    },
    /// One probe set: its parameters, what came back, and how long it took.
    Probe {
        id: i64,
        connection_id: i64,
        server_id: i64,
        kind: String,
        params: Value,
        sent_at: Micros,
        recv_at: Option<Micros>,
        rtt_us: Option<i64>,
        /// Stored by content: the sha256 of this value's JSON text keys
        /// `blobs` and lands in `probes.result_blob`.
        result: Option<Value>,
        /// Stored inline, unlike the result: an error is small, it is read
        /// beside the row it belongs to, and `probes.error` is the column it
        /// has.
        error: Option<Value>,
    },
    /// The peers one `server.peers.subscribe` advertised, as edges of the
    /// advertisement graph. Carries the id of the probe that asked, which is
    /// why probe ids are chosen before the probe row is written.
    PeerEdges {
        probe_id: i64,
        from_server_id: i64,
        edges: Vec<PeerEdge>,
    },
}

impl Event {
    /// The variant's name, for the log line when its write fails.
    fn name(&self) -> &'static str {
        match self {
            Event::ConnectionStarted { .. } => "ConnectionStarted",
            Event::ConnectionEstablished { .. } => "ConnectionEstablished",
            Event::ConnectionEnded { .. } => "ConnectionEnded",
            Event::DnsResolved { .. } => "DnsResolved",
            Event::Header { .. } => "Header",
            Event::TipCheck { .. } => "TipCheck",
            Event::Ping { .. } => "Ping",
            Event::Probe { .. } => "Probe",
            Event::PeerEdges { .. } => "PeerEdges",
        }
    }
}

/// The ids the client chooses, seeded from the database at open.
///
/// Seeded from `max(id)` rather than restarted at one, so that a restarted
/// daemon appends to the same table without colliding with what the previous
/// process wrote.
#[derive(Debug)]
struct Ids {
    connections: AtomicI64,
    probes: AtomicI64,
    dns: AtomicI64,
}

/// The database.
///
/// Cloning is cheap and shares everything: the connection behind its mutex
/// and the id counters. Every clone is the same database, which is what the
/// supervisor hands to each session.
#[derive(Clone, Debug)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    ids: Arc<Ids>,
    /// The size of every batch that was committed, in order.
    ///
    /// What a transaction grouped is not a column, and SQLite's
    /// `data_version` only says *that* another connection committed, not how
    /// often, so the only way to assert the batching from outside the writer
    /// is for the writer to say what it did.
    #[cfg(test)]
    batches: Arc<Mutex<Vec<usize>>>,
}

impl Store {
    /// Opens or creates the database at `path`, applying whatever migrations
    /// it is missing.
    ///
    /// Fails, rather than carrying on, when the file is at a schema this
    /// build does not know: a newer collector may have added a column this
    /// one would leave null on every row it writes, and a database that is
    /// half one schema and half another is worse than a daemon that did not
    /// start.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut conn = Connection::open(path)
            .with_context(|| format!("opening the database {}", path.display()))?;
        configure(&conn).with_context(|| format!("configuring the database {}", path.display()))?;
        migrate(&mut conn).with_context(|| format!("migrating the database {}", path.display()))?;

        let ids = Arc::new(Ids {
            connections: AtomicI64::new(max_id(&conn, "connections")?),
            probes: AtomicI64::new(max_id(&conn, "probes")?),
            dns: AtomicI64::new(max_id(&conn, "dns_resolutions")?),
        });
        let store = Store {
            conn: Arc::new(Mutex::new(conn)),
            ids,
            #[cfg(test)]
            batches: Arc::new(Mutex::new(Vec::new())),
        };
        // When this process opened the database, which is what a reader
        // wants from `started_at`: the beginning of the collection that
        // produced the newest rows, not the day the file was created.
        store.set_meta("started_at", &Micros::now().as_i64().to_string())?;
        debug!(
            target: TARGET_STORE,
            path = %path.display(),
            schema_version = SCHEMA_VERSION,
            "database open",
        );
        Ok(store)
    }

    /// Writes one `meta` row, replacing what was there.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .with_context(|| format!("writing meta.{key}"))?;
        Ok(())
    }

    /// Reads one `meta` row, or `None` when it was never written.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let value = self
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .with_context(|| format!("reading meta.{key}"))?;
        Ok(value)
    }

    /// Inserts a server if it is unknown, and returns the row either way.
    ///
    /// The row an existing endpoint already has is returned unchanged: the
    /// source of a server is who told us about it *first*, and an operator
    /// who disabled one does not want the next peer list to enable it again.
    ///
    /// `cap` is `discovery.max_servers`, or `None` for the sources that are
    /// not subject to it -- the config file and the imports, which are what
    /// the operator asked for. At the cap the row is still inserted, with
    /// `enabled = false` and `disabled_reason = 'cap'`, because the
    /// advertisement is data whether or not it is connected to. The count and
    /// the insert are one transaction so that two callers at the cap cannot
    /// both see room.
    pub fn upsert_server(
        &self,
        endpoint: &Endpoint,
        source: &str,
        cap: Option<usize>,
    ) -> Result<ServerRow> {
        let host = endpoint.host.to_string();
        let port = i64::from(endpoint.port);
        let transport = endpoint.transport.as_str();

        let mut conn = self.conn();
        let tx = conn
            .transaction()
            .context("beginning the server upsert transaction")?;

        let existing = tx
            .query_row(
                &format!("{SELECT_SERVER} WHERE host = ?1 AND port = ?2 AND transport = ?3"),
                params![host, port, transport],
                server_row,
            )
            .optional()
            .context("looking up the server")?;
        if let Some(row) = existing {
            return Ok(row);
        }

        let enabled = match cap {
            None => true,
            Some(cap) => {
                let count: i64 = tx
                    .query_row(
                        "SELECT count(*) FROM servers WHERE enabled = 1",
                        [],
                        |row| row.get(0),
                    )
                    .context("counting the enabled servers")?;
                usize::try_from(count).unwrap_or(usize::MAX) < cap
            }
        };
        let disabled_reason = if enabled { None } else { Some(REASON_CAP) };
        let added_at = Micros::now();

        tx.execute(
            "INSERT INTO servers
                 (host, port, transport, network, source, added_at, enabled, disabled_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                host,
                port,
                transport,
                endpoint.network().as_str(),
                source,
                added_at,
                enabled,
                disabled_reason,
            ],
        )
        .context("inserting the server")?;
        let id = tx.last_insert_rowid();
        tx.commit().context("committing the server upsert")?;

        debug!(
            target: TARGET_STORE,
            id, endpoint = %endpoint, source, enabled, "server added",
        );
        Ok(ServerRow {
            id,
            endpoint: endpoint.clone(),
            source: source.to_string(),
            added_at,
            enabled,
            disabled_reason: disabled_reason.map(str::to_string),
        })
    }

    /// Stops sessions being opened to a server, and records why.
    ///
    /// `reason` is one of the values `servers.disabled_reason` takes:
    /// [`REASON_CAP`], `genesis_mismatch`, or whatever an operator typed.
    pub fn disable_server(&self, id: i64, reason: &str) -> Result<()> {
        self.conn()
            .execute(
                "UPDATE servers SET enabled = 0, disabled_reason = ?2 WHERE id = ?1",
                params![id, reason],
            )
            .with_context(|| format!("disabling server {id}"))?;
        debug!(target: TARGET_STORE, id, reason, "server disabled");
        Ok(())
    }

    /// The servers sessions are opened to, oldest first.
    pub fn enabled_servers(&self) -> Result<Vec<ServerRow>> {
        self.query_servers(&format!("{SELECT_SERVER} WHERE enabled = 1 ORDER BY id"))
    }

    /// Every known server, enabled or not, oldest first.
    pub fn servers(&self) -> Result<Vec<ServerRow>> {
        self.query_servers(&format!("{SELECT_SERVER} ORDER BY id"))
    }

    /// The highest `limit` blocks of the book, highest first.
    ///
    /// What [`crate::headers::Tracker::with_known_blocks`] is seeded with at
    /// startup, and the reason it exists: a hash this database already holds
    /// is not news, so a restart during or after a chain split must not see
    /// the first announcement of each branch as a new second hash at a
    /// height, arm a divergence window and poll every server about a fork
    /// that was over yesterday.
    ///
    /// By height rather than by `first_seen_at`, because what the tracker
    /// prunes by is height, and the rows worth seeding are the ones near the
    /// tip whatever order they were observed in. A row whose hashes are not
    /// hashes -- which only a hand-edited database or another writer can
    /// produce -- is counted and left out rather than failing the startup:
    /// the seed is an optimisation, and the collection is worth more than
    /// the consistency of a row nothing here wrote.
    pub fn recent_blocks(&self, limit: usize) -> Result<Vec<KnownBlock>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT hash, height, prev_hash, first_seen_at, first_seen_server_id
                   FROM blocks ORDER BY height DESC LIMIT ?1",
            )
            .context("preparing the known block query")?;
        let rows = statement
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Micros>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .context("running the known block query")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("reading a block row")?;

        let mut blocks = Vec::with_capacity(rows.len());
        for (hash, height, prev_hash, first_seen_at, first_seen_server_id) in rows {
            match known_block(
                &hash,
                height,
                prev_hash.as_deref(),
                first_seen_at,
                first_seen_server_id,
            ) {
                Some(block) => blocks.push(block),
                // Named rather than counted: a row like this cannot have
                // come from a header this crate wrote, so the only thing to
                // do with the line is go and look at the row it names.
                None => warn!(
                    target: TARGET_STORE,
                    hash = %hash,
                    height,
                    "a block row that no header could have written was not seeded",
                ),
            }
        }
        debug!(
            target: TARGET_STORE,
            blocks = blocks.len(),
            "the block book was read back",
        );
        Ok(blocks)
    }

    /// The id the next `connections` row will have.
    ///
    /// Taken before the dial, so that everything the session writes can carry
    /// it from the first byte.
    pub fn next_connection_id(&self) -> i64 {
        self.ids.connections.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The id the next `probes` row will have.
    ///
    /// Taken before the request goes out, so that `peer_edges.probe_id` can
    /// name a probe that is still in the same batch.
    pub fn next_probe_id(&self) -> i64 {
        self.ids.probes.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The id the next `dns_resolutions` row will have, which the
    /// `connections` row references before the lookup is written.
    pub fn next_dns_id(&self) -> i64 {
        self.ids.dns.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The channel every session writes into, and the task that drains it.
    ///
    /// The task is returned rather than spawned so that the caller owns it:
    /// `run()` spawns it beside the sessions and awaits it after they are
    /// gone, which is what makes a shutdown lose nothing -- the task returns
    /// only when the last [`StoreWriter`] has been dropped and everything
    /// that was queued has been committed.
    pub fn writer(&self) -> (StoreWriter, impl Future<Output = ()> + use<>) {
        let (events, rx) = mpsc::channel(CHANNEL_EVENTS);
        (StoreWriter { events }, write_events(rx, self.clone()))
    }

    /// Commits a batch of events in one transaction.
    ///
    /// An event whose statements fail is logged and skipped: SQLite leaves
    /// the transaction usable after a constraint violation, so the rest of
    /// the batch is still committed, and one bad row costs one row.
    fn write_batch(&self, batch: &[Event]) {
        let mut conn = self.conn();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(error) => {
                warn!(
                    target: TARGET_STORE,
                    events = batch.len(),
                    %error,
                    "the batch could not be started and was dropped",
                );
                return;
            }
        };
        for event in batch {
            if let Err(error) = apply(&tx, event) {
                warn!(
                    target: TARGET_STORE,
                    event = event.name(),
                    %error,
                    "the event was not written",
                );
            }
        }
        match tx.commit() {
            Ok(()) => {
                debug!(target: TARGET_STORE, events = batch.len(), "batch committed");
                #[cfg(test)]
                self.batches
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(batch.len());
            }
            Err(error) => warn!(
                target: TARGET_STORE,
                events = batch.len(),
                %error,
                "the batch could not be committed and was lost",
            ),
        }
    }

    /// The connection, recovering a mutex poisoned by a panicking caller.
    ///
    /// A panic in one of the direct queries says nothing about the SQLite
    /// handle, and a collector that stopped writing because a reader
    /// panicked would be the worse failure.
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The sizes of the batches the writer committed, in order.
    #[cfg(test)]
    fn committed_batches(&self) -> Vec<usize> {
        self.batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn query_servers(&self, sql: &str) -> Result<Vec<ServerRow>> {
        let conn = self.conn();
        let mut statement = conn.prepare(sql).context("preparing the server query")?;
        let rows = statement
            .query_map([], server_row)
            .context("running the server query")?
            .collect::<rusqlite::Result<Vec<ServerRow>>>()
            .context("reading a server row")?;
        Ok(rows)
    }
}

/// A handle on the event channel, one per session.
#[derive(Clone, Debug)]
pub struct StoreWriter {
    events: mpsc::Sender<Event>,
}

impl StoreWriter {
    /// Queues one event, waiting while the queue is full.
    ///
    /// The error says the writer task is gone, which only happens at
    /// shutdown or after it panicked; a session that sees it has nowhere to
    /// put what it observed and should stop.
    pub async fn send(&self, event: Event) -> Result<()> {
        self.events
            .send(event)
            .await
            .map_err(|_| anyhow::anyhow!("the store writer stopped before this event was written"))
    }
}

/// The writer task: batches of events, one transaction each.
///
/// A batch ends at [`BATCH_EVENTS`] events, after [`FLUSH_INTERVAL`], or when
/// the channel closes, whichever comes first. The last of those is the one
/// that matters for a shutdown: the loop drains what is queued and commits it
/// before it returns.
async fn write_events(mut events: mpsc::Receiver<Event>, store: Store) {
    let mut batch: Vec<Event> = Vec::with_capacity(BATCH_EVENTS);
    loop {
        // Nothing to commit until something arrives, so the idle writer waits
        // here rather than waking every FLUSH_INTERVAL to commit nothing.
        let Some(first) = events.recv().await else {
            break;
        };
        batch.push(first);

        let deadline = tokio::time::sleep(FLUSH_INTERVAL);
        tokio::pin!(deadline);
        let mut closed = false;
        while batch.len() < BATCH_EVENTS {
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => batch.push(event),
                    None => {
                        closed = true;
                        break;
                    }
                },
                () = &mut deadline => break,
            }
        }

        store.write_batch(&batch);
        batch.clear();
        if closed {
            break;
        }
    }
    debug!(target: TARGET_STORE, "the store writer stopped");
}

/// Writes one event's rows inside the batch transaction.
fn apply(tx: &Transaction<'_>, event: &Event) -> rusqlite::Result<()> {
    match event {
        Event::ConnectionStarted {
            id,
            server_id,
            session_index,
            started_at,
        } => {
            tx.execute(
                "INSERT INTO connections (id, server_id, session_index, started_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, server_id, session_index, started_at],
            )?;
        }
        Event::ConnectionEstablished {
            id,
            connected_at,
            remote_ip,
            tls,
            dns_id,
            server_version,
            protocol_version,
        } => {
            // The certificate is stored once per fingerprint and the
            // connection points at it, which is what turns "which hostnames
            // presented the same certificate" into a group by.
            let (cert_id, tls_version, tls_cipher) = match tls {
                None => (None, None, None),
                Some(tls) => (
                    Some(upsert_cert(tx, tls)?),
                    tls.tls_version.as_deref(),
                    tls.tls_cipher.as_deref(),
                ),
            };
            tx.execute(
                "UPDATE connections
                    SET connected_at = ?2, remote_ip = ?3, tls_cert_id = ?4, tls_version = ?5,
                        tls_cipher = ?6, dns_id = ?7, server_version = ?8, protocol_version = ?9
                  WHERE id = ?1",
                params![
                    id,
                    connected_at,
                    remote_ip,
                    cert_id,
                    tls_version,
                    tls_cipher,
                    dns_id,
                    server_version,
                    protocol_version,
                ],
            )?;
        }
        Event::ConnectionEnded {
            id,
            ended_at,
            end_reason,
        } => {
            tx.execute(
                "UPDATE connections SET ended_at = ?2, end_reason = ?3 WHERE id = ?1",
                params![id, ended_at, end_reason],
            )?;
        }
        Event::DnsResolved {
            id,
            server_id,
            at,
            addresses,
            error,
        } => {
            tx.execute(
                "INSERT INTO dns_resolutions (id, server_id, at, addresses, error)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, server_id, at, json_text(addresses), error],
            )?;
        }
        Event::Header {
            connection_id,
            server_id,
            at,
            kind,
            height,
            hash,
            prev_hash,
            header_hex,
            reorg,
        } => {
            tx.execute(
                "INSERT INTO header_events
                     (connection_id, server_id, at, kind, height, hash, prev_hash, header_hex,
                      reorg)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    connection_id,
                    server_id,
                    at,
                    kind.as_str(),
                    height,
                    hash,
                    prev_hash,
                    header_hex,
                    reorg,
                ],
            )?;
            // The block book keeps the earliest sighting and who it came
            // from: that pair is the "who was first with this block" the
            // whole exercise is about, so a later server must not overwrite
            // it. The guard is on the timestamp rather than on the existence
            // of the row, because events are committed in the order they
            // were observed but a batch can hold two servers' sightings of
            // one block.
            tx.execute(
                "INSERT INTO blocks
                     (hash, height, prev_hash, header_hex, first_seen_at, first_seen_server_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (hash) DO UPDATE
                    SET first_seen_at = excluded.first_seen_at,
                        first_seen_server_id = excluded.first_seen_server_id
                  WHERE excluded.first_seen_at < blocks.first_seen_at",
                params![hash, height, prev_hash, header_hex, at, server_id],
            )?;
        }
        Event::TipCheck {
            server_id,
            connection_id,
            at,
            height,
            hash,
            rtt_us,
            error,
        } => {
            tx.execute(
                "INSERT INTO tip_checks
                     (server_id, connection_id, at, height, hash, rtt_us, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![server_id, connection_id, at, height, hash, rtt_us, error],
            )?;
        }
        Event::Ping {
            connection_id,
            at,
            rtt_us,
        } => {
            tx.execute(
                "INSERT INTO pings (connection_id, at, rtt_us) VALUES (?1, ?2, ?3)",
                params![connection_id, at, rtt_us],
            )?;
        }
        Event::Probe {
            id,
            connection_id,
            server_id,
            kind,
            params: probe_params,
            sent_at,
            recv_at,
            rtt_us,
            result,
            error,
        } => {
            let result_blob = match result {
                None => None,
                Some(result) => Some(store_blob(tx, result)?),
            };
            tx.execute(
                "INSERT INTO probes
                     (id, connection_id, server_id, kind, params, sent_at, recv_at, rtt_us,
                      result_blob, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    id,
                    connection_id,
                    server_id,
                    kind,
                    json_text(probe_params),
                    sent_at,
                    recv_at,
                    rtt_us,
                    result_blob,
                    error.as_ref().map(json_text),
                ],
            )?;
        }
        Event::PeerEdges {
            probe_id,
            from_server_id,
            edges,
        } => {
            let mut statement = tx.prepare_cached(
                "INSERT INTO peer_edges (probe_id, from_server_id, peer_host, peer_ip, features)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for edge in edges {
                statement.execute(params![
                    probe_id,
                    from_server_id,
                    edge.peer_host,
                    edge.peer_ip,
                    json_text(&edge.features),
                ])?;
            }
        }
    }
    Ok(())
}

/// Stores a probe result by content and returns its address.
///
/// Insert-or-ignore: the same fee histogram from forty servers is one row,
/// and the equality of two `result_blob` values is then the whole "did these
/// two answer the same thing" query. The hash is of the serialised text and
/// not of the value, so that what is hashed is exactly what is stored;
/// `serde_json` orders object keys, so two servers that answered the same
/// thing in a different field order still collapse.
fn store_blob(tx: &Transaction<'_>, result: &Value) -> rusqlite::Result<String> {
    let json = json_text(result);
    let sha256 = sha256_hex(json.as_bytes());
    tx.execute(
        "INSERT OR IGNORE INTO blobs (sha256, json) VALUES (?1, ?2)",
        params![sha256, json],
    )?;
    Ok(sha256)
}

/// Inserts a certificate if its fingerprint is new, and returns its id.
///
/// The id is read back inside the same transaction rather than taken from
/// `last_insert_rowid`, because the insert is ignored when the certificate is
/// already there -- which is the normal case, a server presenting the same
/// certificate on every reconnection for months.
fn upsert_cert(tx: &Transaction<'_>, tls: &TlsInfo) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT OR IGNORE INTO tls_certs
             (sha256, subject, issuer, sans, not_before, not_after, der)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            tls.sha256,
            tls.subject,
            tls.issuer,
            json_text(&tls.sans),
            tls.not_before,
            tls.not_after,
            tls.der,
        ],
    )?;
    tx.query_row(
        "SELECT id FROM tls_certs WHERE sha256 = ?1",
        params![tls.sha256],
        |row| row.get(0),
    )
}

/// A value as the text that goes into a JSON column.
///
/// Serialisation cannot fail for the values this crate stores -- they are
/// arrays of strings and whatever a server answered, which arrived as JSON --
/// so a failure is rendered as `null` rather than losing the row it was part
/// of.
fn json_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// The columns of [`ServerRow`], in the order [`server_row`] reads them.
const SELECT_SERVER: &str = "SELECT id, host, port, transport, source, added_at, enabled,
                                    disabled_reason
                               FROM servers";

/// One `servers` row, with its endpoint reassembled from its columns.
fn server_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServerRow> {
    let id: i64 = row.get(0)?;
    let host: String = row.get(1)?;
    let port: i64 = row.get(2)?;
    let transport: String = row.get(3)?;
    let text = format!("{transport}://{host}:{port}");
    let endpoint = text.parse::<Endpoint>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ServerRow {
        id,
        endpoint,
        source: row.get(4)?,
        added_at: row.get(5)?,
        enabled: row.get(6)?,
        disabled_reason: row.get(7)?,
    })
}

/// The pragmas every connection to this database is opened with.
///
/// WAL because a reader with `sqlite3` or DuckDB attached to the live
/// database is the normal way this data is looked at, and it must not block
/// the collector. `synchronous = NORMAL` is the documented companion of WAL:
/// a crash can lose the last commits, which for this daemon is a second of
/// observations, and the alternative is an fsync per batch on a write-heavy
/// file. Foreign keys because every id in this schema points at a row that
/// should exist, and SQLite only enforces that when asked, per connection.
fn configure(conn: &Connection) -> Result<()> {
    // Returns a row ("wal", or "memory" for an in-memory database, which
    // cannot have a write-ahead log and does not need one), so it is a query
    // rather than an execute.
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .context("setting journal_mode")?;
    debug!(target: TARGET_STORE, mode, "journal mode");
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("enabling foreign keys")?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .context("setting the busy timeout")?;
    Ok(())
}

/// Brings the database up to [`SCHEMA_VERSION`], one transaction per step.
fn migrate(conn: &mut Connection) -> Result<()> {
    let version = schema_version(conn)?;
    if version > SCHEMA_VERSION {
        bail!(
            "the database is at schema version {version} and this build understands {SCHEMA_VERSION}: \
             it was written by a newer electrum-observer"
        );
    }
    let applied = usize::try_from(version).unwrap_or(0);
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied) {
        let next = index as i64 + 1;
        let tx = conn
            .transaction()
            .with_context(|| format!("beginning migration {next}"))?;
        tx.execute_batch(migration)
            .with_context(|| format!("applying migration {next}"))?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![next.to_string()],
        )
        .with_context(|| format!("recording schema version {next}"))?;
        tx.commit()
            .with_context(|| format!("committing migration {next}"))?;
        debug!(target: TARGET_STORE, version = next, "migration applied");
    }
    Ok(())
}

/// The version in `meta`, or 0 for a database that has no `meta` table yet,
/// which is what an empty file looks like.
fn schema_version(conn: &Connection) -> Result<i64> {
    let has_meta: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .context("looking for the meta table")?;
    if has_meta == 0 {
        return Ok(0);
    }
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("reading the schema version")?;
    match version {
        None => Ok(0),
        Some(text) => text
            .parse()
            .with_context(|| format!("the schema version {text:?} is not a number")),
    }
}

/// One `blocks` row as [`crate::headers::Tracker`] takes it, or `None` when
/// the row is not one a header could have produced.
///
/// The three ways that can happen are a hash that is not 32 bytes of
/// hexadecimal, a missing `prev_hash` -- the column is nullable and a header
/// always has a parent, so a null is a row from somewhere else -- and a
/// negative height. None of them is reachable through [`Event::Header`];
/// they are the shapes the schema allows and this crate does not write.
fn known_block(
    hash: &str,
    height: i64,
    prev_hash: Option<&str>,
    first_seen_at: Micros,
    first_seen_server_id: i64,
) -> Option<KnownBlock> {
    Some(KnownBlock {
        hash: hash.parse().ok()?,
        height: u64::try_from(height).ok()?,
        prev_hash: prev_hash?.parse().ok()?,
        first_seen_at,
        first_seen_server_id,
    })
}

/// The largest id in a table, or 0 when it is empty: what the counter for
/// that table starts from.
fn max_id(conn: &Connection, table: &str) -> Result<i64> {
    let sql = format!("SELECT coalesce(max(id), 0) FROM {table}");
    conn.query_row(&sql, [], |row| row.get(0))
        .with_context(|| format!("reading the highest id of {table}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    /// A store on a real file, because WAL, the busy timeout and reopening
    /// are all things `:memory:` cannot show.
    fn temp_store() -> (TempDir, Store) {
        let dir = TempDir::new().expect("a temporary directory");
        let store = Store::open(dir.path().join("observer.sqlite")).expect("the database opens");
        (dir, store)
    }

    fn endpoint(text: &str) -> Endpoint {
        text.parse().expect("an endpoint")
    }

    /// Runs the writer task over a batch of events and waits for it to
    /// finish.
    ///
    /// The handle is dropped before the task is awaited, so every assertion
    /// made after one of these is about rows that only the flush on channel
    /// close can have committed: nothing here reaches [`BATCH_EVENTS`] or
    /// waits [`FLUSH_INTERVAL`].
    async fn write(store: &Store, events: Vec<Event>) {
        let (writer, task) = store.writer();
        let task = tokio::spawn(task);
        for event in events {
            writer.send(event).await.expect("the event is queued");
        }
        drop(writer);
        task.await.expect("the writer task ends");
    }

    /// One scalar from the database, for an assertion about a column.
    fn one<T: FromSql>(store: &Store, sql: &str) -> T {
        store
            .conn()
            .query_row(sql, [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
    }

    fn count(store: &Store, table: &str) -> i64 {
        one(store, &format!("SELECT count(*) FROM {table}"))
    }

    /// The names of the tables or indexes the schema created, sorted.
    fn names(store: &Store, kind: &str) -> Vec<String> {
        let conn = store.conn();
        let mut statement = conn
            .prepare(
                "SELECT name FROM sqlite_master
                  WHERE type = ?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("the catalogue query prepares");
        statement
            .query_map([kind], |row| row.get(0))
            .expect("the catalogue query runs")
            .collect::<rusqlite::Result<Vec<String>>>()
            .expect("a catalogue row")
    }

    /// A server and a started connection to it, which every other row needs
    /// to exist before its foreign keys resolve.
    async fn server_and_connection(store: &Store) -> (i64, i64) {
        let server = store
            .upsert_server(&endpoint("ssl://tool.sh:50002"), "config", None)
            .expect("the server is inserted");
        let connection_id = store.next_connection_id();
        write(
            store,
            vec![Event::ConnectionStarted {
                id: connection_id,
                server_id: server.id,
                session_index: 0,
                started_at: Micros(1_000),
            }],
        )
        .await;
        (server.id, connection_id)
    }

    fn tls() -> TlsInfo {
        TlsInfo {
            sha256: "aa".repeat(32),
            subject: Some("CN=tool.sh".to_string()),
            issuer: Some("CN=Let's Encrypt".to_string()),
            sans: vec!["tool.sh".to_string(), "www.tool.sh".to_string()],
            not_before: Some(Micros(10)),
            not_after: Some(Micros(20)),
            der: vec![0x30, 0x82, 0x01],
            tls_version: Some("TLSv1.3".to_string()),
            tls_cipher: Some("TLS13_AES_256_GCM_SHA384".to_string()),
        }
    }

    /// A run of pings, for the tests about the batching rather than about
    /// what a ping is.
    fn pings(connection_id: i64, count: usize) -> Vec<Event> {
        (0..count)
            .map(|index| {
                let index = i64::try_from(index).expect("the index fits");
                Event::Ping {
                    connection_id,
                    at: Micros(index),
                    rtt_us: index,
                }
            })
            .collect()
    }

    fn probe(id: i64, connection_id: i64, server_id: i64, result: Option<Value>) -> Event {
        Event::Probe {
            id,
            connection_id,
            server_id,
            kind: "fees".to_string(),
            params: json!([1, 2, 6]),
            sent_at: Micros(5_000),
            recv_at: Some(Micros(5_120)),
            rtt_us: Some(120),
            result,
            error: None,
        }
    }

    // -- the schema and the pragmas

    #[test]
    fn the_schema_applies_to_an_empty_file() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        std::fs::File::create(&path).expect("an empty file");

        let store = Store::open(&path).expect("the database opens");

        assert_eq!(
            names(&store, "table"),
            vec![
                "blobs",
                "blocks",
                "connections",
                "dns_resolutions",
                "header_events",
                "meta",
                "peer_edges",
                "pings",
                "probes",
                "servers",
                "tip_checks",
                "tls_certs",
            ],
            "every table of the data model, and nothing else",
        );
        assert_eq!(
            names(&store, "index"),
            vec![
                "idx_blocks_height",
                "idx_connections_server_started",
                "idx_header_events_hash",
                "idx_header_events_server_at",
                "idx_pings_connection_at",
                "idx_probes_result_blob",
                "idx_probes_server_kind_sent",
                "idx_tip_checks_height_at",
            ],
        );
        assert_eq!(
            store.get_meta("schema_version").expect("meta reads"),
            Some("1".to_string()),
        );
    }

    #[test]
    fn the_version_is_the_number_of_migrations() {
        assert_eq!(SCHEMA_VERSION, MIGRATIONS.len() as i64);
    }

    #[test]
    fn reopening_changes_nothing() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let first = Store::open(&path).expect("the database opens");
        first
            .upsert_server(&endpoint("ssl://tool.sh:50002"), "config", None)
            .expect("the server is inserted");
        let tables = names(&first, "table");
        drop(first);

        let second = Store::open(&path).expect("the database opens again");

        assert_eq!(names(&second, "table"), tables, "no migration reapplied");
        assert_eq!(count(&second, "servers"), 1, "the rows are still there");
        assert_eq!(
            second.get_meta("schema_version").expect("meta reads"),
            Some("1".to_string()),
        );
    }

    #[test]
    fn the_pragmas_are_in_effect() {
        let (_dir, store) = temp_store();

        assert_eq!(
            one::<String>(&store, "PRAGMA journal_mode"),
            "wal",
            "a reader attached to the live database must not block the writer",
        );
        assert_eq!(one::<i64>(&store, "PRAGMA foreign_keys"), 1);
        assert_eq!(one::<i64>(&store, "PRAGMA synchronous"), 1, "NORMAL");
        assert_eq!(
            one::<i64>(&store, "PRAGMA busy_timeout"),
            i64::try_from(BUSY_TIMEOUT.as_millis()).expect("milliseconds fit"),
        );
    }

    /// An in-memory database has no write-ahead log and cannot have one, so
    /// opening one must not be an error: the tests that do not need a file
    /// use it, and so does anything that wants a scratch database.
    #[test]
    fn an_in_memory_database_opens() {
        let store = Store::open(":memory:").expect("the in-memory database opens");

        assert_eq!(one::<String>(&store, "PRAGMA journal_mode"), "memory");
        assert_eq!(count(&store, "servers"), 0);
    }

    #[test]
    fn a_newer_schema_version_is_refused() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let store = Store::open(&path).expect("the database opens");
        store
            .set_meta("schema_version", "2")
            .expect("the version is written");
        drop(store);

        let error = Store::open(&path).expect_err("a newer schema is refused");

        let text = format!("{error:#}");
        assert!(
            text.contains("schema version 2") && text.contains("understands 1"),
            "the error names both versions, got {text:?}",
        );
    }

    /// A `meta` table with no version in it is not a database of ours.
    /// Migration 1 is attempted and fails on the table that is already
    /// there, which is louder and safer than adopting a file whose other
    /// tables are a stranger's.
    #[test]
    fn a_meta_table_without_a_version_is_not_adopted() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("stranger.sqlite");
        let foreign = Connection::open(&path).expect("the file is created");
        foreign
            .execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .expect("the stranger's table is created");
        drop(foreign);

        let error = Store::open(&path).expect_err("the stranger's database is refused");

        assert!(
            format!("{error:#}").contains("applying migration 1"),
            "{error:#}",
        );
    }

    #[test]
    fn an_unreadable_schema_version_is_refused() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let store = Store::open(&path).expect("the database opens");
        store
            .set_meta("schema_version", "one")
            .expect("the version is written");
        drop(store);

        let error = Store::open(&path).expect_err("a nonsense version is refused");

        assert!(
            format!("{error:#}").contains("\"one\" is not a number"),
            "{error:#}",
        );
    }

    // -- meta

    #[test]
    fn meta_round_trips_and_replaces() {
        let (_dir, store) = temp_store();

        assert_eq!(store.get_meta("config_sha256").expect("meta reads"), None);
        store
            .set_meta("config_sha256", "abc")
            .expect("meta is written");
        store
            .set_meta("config_sha256", "def")
            .expect("meta is replaced");

        assert_eq!(
            store.get_meta("config_sha256").expect("meta reads"),
            Some("def".to_string()),
        );
        assert_eq!(count(&store, "meta WHERE key = 'config_sha256'"), 1);
    }

    #[test]
    fn opening_records_when_the_collection_started() {
        let before = Micros::now();
        let (_dir, store) = temp_store();

        let started: i64 = store
            .get_meta("started_at")
            .expect("meta reads")
            .expect("started_at is written on open")
            .parse()
            .expect("started_at is a number");

        assert!(
            started >= before.as_i64() && started <= Micros::now().as_i64(),
            "started_at is the moment of the open",
        );
    }

    // -- servers

    #[test]
    fn a_server_is_inserted_once_and_read_back() {
        let (_dir, store) = temp_store();
        let endpoint = endpoint("ssl://tool.sh:50002");

        let first = store
            .upsert_server(&endpoint, "config", None)
            .expect("the server is inserted");
        let second = store
            .upsert_server(&endpoint, "peers:7", None)
            .expect("the server is read back");

        assert_eq!(first.id, 1);
        assert_eq!(first.endpoint, endpoint);
        assert_eq!(first.source, "config");
        assert!(first.enabled);
        assert_eq!(first.disabled_reason, None);
        assert_eq!(
            second, first,
            "a second sighting does not change the source or the id",
        );
        assert_eq!(count(&store, "servers"), 1);
        assert_eq!(
            one::<String>(&store, "SELECT network FROM servers WHERE id = 1"),
            "clearnet",
        );
        assert_eq!(
            one::<i64>(&store, "SELECT port FROM servers WHERE id = 1"),
            50002
        );
        assert_eq!(
            one::<String>(&store, "SELECT transport FROM servers WHERE id = 1"),
            "ssl",
        );
        assert_eq!(
            one::<Micros>(&store, "SELECT added_at FROM servers WHERE id = 1"),
            first.added_at,
        );
    }

    /// The host kind survives the round trip through the columns, which is
    /// what the supervisor needs: an onion endpoint read back as a name
    /// would be dialed without Tor.
    #[test]
    fn every_host_kind_round_trips_through_the_columns() {
        let (_dir, store) = temp_store();
        let endpoints = [
            "ssl://tool.sh:50002",
            "tcp://127.0.0.1:50001",
            "ssl://[2001:db8::1]:50002",
            "tcp://p5xkmesyt4ahycg6s5ssmilxonnlqgsrahx3lbdhb6nqusdr4pmzeyqd.onion:50001",
        ]
        .map(endpoint);
        for endpoint in &endpoints {
            store
                .upsert_server(endpoint, "config", None)
                .expect("the server is inserted");
        }

        let read: Vec<Endpoint> = store
            .servers()
            .expect("the servers are read")
            .into_iter()
            .map(|row| row.endpoint)
            .collect();

        assert_eq!(read, endpoints.to_vec());
        assert_eq!(
            one::<String>(&store, "SELECT network FROM servers WHERE id = 4"),
            "onion",
        );
    }

    #[test]
    fn the_cap_disables_the_server_that_does_not_fit() {
        let (_dir, store) = temp_store();

        for port in 0..2u16 {
            store
                .upsert_server(
                    &endpoint(&format!("ssl://tool.sh:{}", 50000 + port)),
                    "config",
                    Some(2),
                )
                .expect("the server is inserted");
        }
        let past = store
            .upsert_server(&endpoint("ssl://tool.sh:50002"), "peers:1", Some(2))
            .expect("the server past the cap is still inserted");

        assert!(!past.enabled);
        assert_eq!(past.disabled_reason.as_deref(), Some(REASON_CAP));
        assert_eq!(count(&store, "servers"), 3, "the advertisement is kept");
        assert_eq!(
            one::<i64>(&store, "SELECT enabled FROM servers WHERE id = 3"),
            0,
        );
        assert_eq!(
            store.enabled_servers().expect("the enabled servers").len(),
            2,
        );
    }

    /// A disabled server frees its place: the cap counts what is connected
    /// to, not what is known.
    #[test]
    fn disabling_a_server_makes_room_under_the_cap() {
        let (_dir, store) = temp_store();
        store
            .upsert_server(&endpoint("ssl://one.example:50002"), "config", Some(1))
            .expect("the first server");
        store
            .disable_server(1, "genesis_mismatch")
            .expect("the server is disabled");

        let second = store
            .upsert_server(&endpoint("ssl://two.example:50002"), "config", Some(1))
            .expect("the second server");

        assert!(second.enabled);
        assert_eq!(
            one::<String>(&store, "SELECT disabled_reason FROM servers WHERE id = 1"),
            "genesis_mismatch",
        );
        assert_eq!(
            store
                .enabled_servers()
                .expect("the enabled servers")
                .iter()
                .map(|row| row.id)
                .collect::<Vec<i64>>(),
            vec![2],
        );
        assert_eq!(store.servers().expect("every server").len(), 2);
    }

    /// Without a cap nothing is counted and nothing is disabled: that is the
    /// config file and the imports, which are what the operator asked for.
    #[test]
    fn without_a_cap_every_server_is_enabled() {
        let (_dir, store) = temp_store();

        for port in 0..5u16 {
            let row = store
                .upsert_server(
                    &endpoint(&format!("ssl://tool.sh:{}", 50000 + port)),
                    "config",
                    None,
                )
                .expect("the server is inserted");
            assert!(row.enabled);
        }

        assert_eq!(
            store.enabled_servers().expect("the enabled servers").len(),
            5
        );
    }

    /// A row that is not an endpoint -- a hand-edited database, or one from
    /// a future that allows something this build does not -- is an error
    /// rather than a server quietly missing from the supervisor's list.
    #[test]
    fn a_server_row_that_is_not_an_endpoint_is_an_error() {
        let store = Store::open(":memory:").expect("the in-memory database opens");
        store
            .conn()
            .execute(
                "INSERT INTO servers
                     (host, port, transport, network, source, added_at, enabled)
                 VALUES ('tool.sh', 0, 'ssl', 'clearnet', 'config', 0, 1)",
                [],
            )
            .expect("the row is written");

        let error = store.servers().expect_err("the row does not parse");

        assert!(
            format!("{error:#}").contains("the port is zero"),
            "{error:#}"
        );
    }

    // -- the ids

    #[test]
    fn the_counters_continue_where_the_last_run_stopped() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let store = Store::open(&path).expect("the database opens");
        let server = store
            .upsert_server(&endpoint("ssl://tool.sh:50002"), "config", None)
            .expect("the server is inserted");
        assert_eq!(store.next_connection_id(), 1);
        assert_eq!(store.next_connection_id(), 2);
        assert_eq!(store.next_probe_id(), 1);
        assert_eq!(store.next_dns_id(), 1);
        let events = vec![
            Event::DnsResolved {
                id: 1,
                server_id: server.id,
                at: Micros(1),
                addresses: vec![],
                error: None,
            },
            Event::ConnectionStarted {
                id: 2,
                server_id: server.id,
                session_index: 0,
                started_at: Micros(2),
            },
            probe(1, 2, server.id, None),
        ];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(write(&store, events));
        drop(store);

        let store = Store::open(&path).expect("the database opens again");

        assert_eq!(store.next_connection_id(), 3, "max(id) was 2");
        assert_eq!(store.next_probe_id(), 2);
        assert_eq!(store.next_dns_id(), 2);
    }

    // -- the events

    #[tokio::test]
    async fn a_connection_is_started_established_and_ended() {
        let (_dir, store) = temp_store();
        let (server_id, id) = server_and_connection(&store).await;
        let dns_id = store.next_dns_id();

        write(
            &store,
            vec![
                Event::DnsResolved {
                    id: dns_id,
                    server_id,
                    at: Micros(900),
                    addresses: vec!["1.2.3.4".to_string(), "2001:db8::1".to_string()],
                    error: None,
                },
                Event::ConnectionEstablished {
                    id,
                    connected_at: Micros(2_000),
                    remote_ip: Some("1.2.3.4".to_string()),
                    tls: Some(tls()),
                    dns_id: Some(dns_id),
                    server_version: Some("Fulcrum 1.9.1".to_string()),
                    protocol_version: Some("1.4".to_string()),
                },
                Event::ConnectionEnded {
                    id,
                    ended_at: Micros(9_000),
                    end_reason: "eof".to_string(),
                },
            ],
        )
        .await;

        // Two halves because a tuple of thirteen has no `Debug`: the dial
        // and what it ended as, then what the handshake said.
        let dial = store.conn().query_row(
            "SELECT server_id, session_index, started_at, connected_at, ended_at, end_reason,
                    remote_ip
               FROM connections WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Micros>(2)?,
                    row.get::<_, Micros>(3)?,
                    row.get::<_, Micros>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        );
        assert_eq!(
            dial.expect("the connection row"),
            (
                server_id,
                0,
                Micros(1_000),
                Micros(2_000),
                Micros(9_000),
                "eof".to_string(),
                "1.2.3.4".to_string(),
            ),
        );

        let handshake = store.conn().query_row(
            "SELECT tls_cert_id, tls_version, tls_cipher, dns_id, server_version,
                    protocol_version
               FROM connections WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        );
        assert_eq!(
            handshake.expect("the connection row"),
            (
                1,
                "TLSv1.3".to_string(),
                "TLS13_AES_256_GCM_SHA384".to_string(),
                dns_id,
                "Fulcrum 1.9.1".to_string(),
                "1.4".to_string(),
            ),
        );
        assert_eq!(
            one::<String>(&store, "SELECT addresses FROM dns_resolutions WHERE id = 1"),
            r#"["1.2.3.4","2001:db8::1"]"#,
        );
    }

    #[tokio::test]
    async fn a_failed_resolution_is_a_row_too() {
        let (_dir, store) = temp_store();
        let server = store
            .upsert_server(&endpoint("ssl://tool.sh:50002"), "config", None)
            .expect("the server is inserted");

        write(
            &store,
            vec![Event::DnsResolved {
                id: store.next_dns_id(),
                server_id: server.id,
                at: Micros(42),
                addresses: vec![],
                error: Some("no record found".to_string()),
            }],
        )
        .await;

        assert_eq!(
            one::<String>(&store, "SELECT addresses FROM dns_resolutions"),
            "[]",
        );
        assert_eq!(
            one::<String>(&store, "SELECT error FROM dns_resolutions"),
            "no record found",
        );
        assert_eq!(
            one::<Micros>(&store, "SELECT at FROM dns_resolutions"),
            Micros(42)
        );
    }

    /// A connection without TLS leaves the certificate columns null rather
    /// than pointing at someone else's certificate.
    #[tokio::test]
    async fn a_plain_connection_stores_no_certificate() {
        let (_dir, store) = temp_store();
        let (_server_id, id) = server_and_connection(&store).await;

        write(
            &store,
            vec![Event::ConnectionEstablished {
                id,
                connected_at: Micros(2_000),
                remote_ip: None,
                tls: None,
                dns_id: None,
                server_version: None,
                protocol_version: None,
            }],
        )
        .await;

        assert_eq!(count(&store, "tls_certs"), 0);
        assert_eq!(
            count(
                &store,
                "connections WHERE tls_cert_id IS NULL AND tls_version IS NULL"
            ),
            1,
        );
    }

    /// The same certificate on two connections is one `tls_certs` row, which
    /// is what makes "which hostnames presented this certificate" a join.
    #[tokio::test]
    async fn one_certificate_is_stored_once_for_every_connection_that_shows_it() {
        let (_dir, store) = temp_store();
        let (server_id, first) = server_and_connection(&store).await;
        let second = store.next_connection_id();

        write(
            &store,
            vec![
                Event::ConnectionStarted {
                    id: second,
                    server_id,
                    session_index: 1,
                    started_at: Micros(1_500),
                },
                Event::ConnectionEstablished {
                    id: first,
                    connected_at: Micros(2_000),
                    remote_ip: None,
                    tls: Some(tls()),
                    dns_id: None,
                    server_version: None,
                    protocol_version: None,
                },
                Event::ConnectionEstablished {
                    id: second,
                    connected_at: Micros(2_100),
                    remote_ip: None,
                    tls: Some(tls()),
                    dns_id: None,
                    server_version: None,
                    protocol_version: None,
                },
            ],
        )
        .await;

        assert_eq!(count(&store, "tls_certs"), 1);
        assert_eq!(
            count(&store, "connections WHERE tls_cert_id = 1"),
            2,
            "both connections point at the one row",
        );
        assert_eq!(
            one::<String>(&store, "SELECT sans FROM tls_certs WHERE id = 1"),
            r#"["tool.sh","www.tool.sh"]"#,
        );
        assert_eq!(
            one::<Vec<u8>>(&store, "SELECT der FROM tls_certs WHERE id = 1"),
            vec![0x30, 0x82, 0x01],
        );
        assert_eq!(
            one::<String>(&store, "SELECT subject FROM tls_certs WHERE id = 1"),
            "CN=tool.sh",
        );
        assert_eq!(
            one::<String>(&store, "SELECT issuer FROM tls_certs WHERE id = 1"),
            "CN=Let's Encrypt",
        );
        assert_eq!(
            one::<Micros>(&store, "SELECT not_before FROM tls_certs WHERE id = 1"),
            Micros(10),
        );
        assert_eq!(
            one::<Micros>(&store, "SELECT not_after FROM tls_certs WHERE id = 1"),
            Micros(20),
        );
    }

    #[tokio::test]
    async fn a_header_is_an_event_and_a_block() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;

        write(
            &store,
            vec![Event::Header {
                connection_id,
                server_id,
                at: Micros(3_000),
                kind: HeaderKind::Notification,
                height: 880_000,
                hash: "00beef".to_string(),
                prev_hash: Some("00cafe".to_string()),
                header_hex: "aabb".to_string(),
                reorg: true,
            }],
        )
        .await;

        let event = store.conn().query_row(
            "SELECT connection_id, server_id, at, kind, height, hash, prev_hash, header_hex, reorg
               FROM header_events",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Micros>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, bool>(8)?,
                ))
            },
        );
        assert_eq!(
            event.expect("the header event"),
            (
                connection_id,
                server_id,
                Micros(3_000),
                "notification".to_string(),
                880_000,
                "00beef".to_string(),
                "00cafe".to_string(),
                "aabb".to_string(),
                true,
            ),
        );

        let block = store.conn().query_row(
            "SELECT height, prev_hash, header_hex, first_seen_at, first_seen_server_id
               FROM blocks WHERE hash = '00beef'",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Micros>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        );
        assert_eq!(
            block.expect("the block"),
            (
                880_000,
                "00cafe".to_string(),
                "aabb".to_string(),
                Micros(3_000),
                server_id,
            ),
        );
    }

    #[tokio::test]
    async fn the_subscribe_reply_is_a_header_event_of_its_own_kind() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;

        write(
            &store,
            vec![Event::Header {
                connection_id,
                server_id,
                at: Micros(3_000),
                kind: HeaderKind::Subscribe,
                height: 1,
                hash: "00beef".to_string(),
                prev_hash: None,
                header_hex: "aabb".to_string(),
                reorg: false,
            }],
        )
        .await;

        assert_eq!(
            one::<String>(&store, "SELECT kind FROM header_events"),
            "subscribe"
        );
        assert!(!one::<bool>(&store, "SELECT reorg FROM header_events"));
        assert_eq!(count(&store, "header_events WHERE prev_hash IS NULL"), 1);
    }

    /// Who was first with a block is the measurement; a later server
    /// announcing it must not overwrite that, whichever order the rows are
    /// written in.
    #[tokio::test]
    async fn a_block_keeps_the_earliest_sighting_and_the_server_that_had_it() {
        let (_dir, store) = temp_store();
        let (first_server, connection_id) = server_and_connection(&store).await;
        let second_server = store
            .upsert_server(&endpoint("ssl://other.example:50002"), "config", None)
            .expect("a second server")
            .id;
        let header = |server_id: i64, at: i64| Event::Header {
            connection_id,
            server_id,
            at: Micros(at),
            kind: HeaderKind::Notification,
            height: 880_000,
            hash: "00beef".to_string(),
            prev_hash: Some("00cafe".to_string()),
            header_hex: "aabb".to_string(),
            reorg: false,
        };

        // The later sighting is written first, so that what is asserted is
        // the comparison and not the order.
        write(
            &store,
            vec![
                header(second_server, 3_400),
                header(first_server, 3_000),
                header(second_server, 3_900),
            ],
        )
        .await;

        assert_eq!(count(&store, "header_events"), 3, "every sighting is kept");
        assert_eq!(count(&store, "blocks"), 1);
        assert_eq!(
            one::<Micros>(&store, "SELECT first_seen_at FROM blocks"),
            Micros(3_000),
        );
        assert_eq!(
            one::<i64>(&store, "SELECT first_seen_server_id FROM blocks"),
            first_server,
        );
    }

    /// A hash of one repeated byte, in the 64 hexadecimal characters a real
    /// one has: `recent_blocks` parses what it reads, so a test about it
    /// cannot use the short strings the other tests here write.
    fn block_hash(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// The seed the tracker takes at startup: the highest rows, highest
    /// first, cut to the limit, and without the rows no header could have
    /// written.
    ///
    /// The ordering is the point of the limit -- what is worth seeding is
    /// the blocks near the tip -- and the two skipped rows are the shapes
    /// `blocks` allows and this crate never writes, which must cost a count
    /// rather than the startup.
    #[tokio::test]
    async fn the_recent_blocks_are_the_highest_ones_a_header_could_have_written() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;
        let header = |height: i64, hash: String, prev_hash: Option<String>| Event::Header {
            connection_id,
            server_id,
            at: Micros(height),
            kind: HeaderKind::Notification,
            height,
            hash,
            prev_hash,
            header_hex: "aabb".to_string(),
            reorg: false,
        };

        write(
            &store,
            vec![
                header(100, block_hash(1), Some(block_hash(0))),
                header(102, block_hash(3), Some(block_hash(2))),
                header(101, block_hash(2), Some(block_hash(1))),
                // Not a hash, and a header with no parent: both are rows
                // the schema takes and the collector cannot produce. Below
                // the readable ones, so that the limit is what the first
                // assertion is about and the skipping is what the second is.
                header(99, "00beef".to_string(), Some(block_hash(0))),
                header(98, block_hash(5), None),
            ],
        )
        .await;

        let recent = store.recent_blocks(2).expect("the block book reads back");
        assert_eq!(
            recent,
            vec![
                KnownBlock {
                    hash: block_hash(3).parse().expect("a hash"),
                    height: 102,
                    prev_hash: block_hash(2).parse().expect("a hash"),
                    first_seen_at: Micros(102),
                    first_seen_server_id: server_id,
                },
                KnownBlock {
                    hash: block_hash(2).parse().expect("a hash"),
                    height: 101,
                    prev_hash: block_hash(1).parse().expect("a hash"),
                    first_seen_at: Micros(101),
                    first_seen_server_id: server_id,
                },
            ],
            "the two highest readable blocks, highest first",
        );

        let heights: Vec<u64> = store
            .recent_blocks(100)
            .expect("the block book reads back")
            .into_iter()
            .map(|block| block.height)
            .collect();
        assert_eq!(
            heights,
            vec![102, 101, 100],
            "the unreadable rows are left out rather than failing the read",
        );
        assert!(
            store
                .recent_blocks(0)
                .expect("the block book reads back")
                .is_empty(),
            "a limit of nothing seeds nothing",
        );
    }

    #[tokio::test]
    async fn a_tip_check_and_a_ping_land_with_their_round_trips() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;

        write(
            &store,
            vec![
                Event::TipCheck {
                    server_id,
                    connection_id,
                    at: Micros(4_000),
                    height: Some(880_001),
                    hash: Some("00beef".to_string()),
                    rtt_us: Some(31_000),
                    error: None,
                },
                Event::TipCheck {
                    server_id,
                    connection_id,
                    at: Micros(4_010),
                    height: None,
                    hash: None,
                    rtt_us: None,
                    error: Some("timeout".to_string()),
                },
                Event::Ping {
                    connection_id,
                    at: Micros(4_100),
                    rtt_us: 12_345,
                },
            ],
        )
        .await;

        let check = store.conn().query_row(
            "SELECT server_id, connection_id, at, height, hash, rtt_us
               FROM tip_checks WHERE error IS NULL",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Micros>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        );
        assert_eq!(
            check.expect("the tip check"),
            (
                server_id,
                connection_id,
                Micros(4_000),
                880_001,
                "00beef".to_string(),
                31_000,
            ),
        );
        assert_eq!(
            one::<String>(&store, "SELECT error FROM tip_checks WHERE height IS NULL"),
            "timeout",
        );
        assert_eq!(
            one::<i64>(&store, "SELECT rtt_us FROM pings WHERE connection_id = 1"),
            12_345,
        );
        assert_eq!(one::<Micros>(&store, "SELECT at FROM pings"), Micros(4_100));
    }

    #[tokio::test]
    async fn a_probe_stores_its_result_by_content() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;
        let result = json!({"b": 2, "a": [1, 2]});

        write(
            &store,
            vec![probe(
                store.next_probe_id(),
                connection_id,
                server_id,
                Some(result.clone()),
            )],
        )
        .await;

        let json = serde_json::to_string(&result).expect("the result serialises");
        assert_eq!(
            one::<String>(&store, "SELECT json FROM blobs"),
            r#"{"a":[1,2],"b":2}"#,
            "object keys are ordered, so two servers that answered the same \
             thing in a different order collapse to one blob",
        );
        assert_eq!(
            one::<String>(&store, "SELECT result_blob FROM probes"),
            sha256_hex(json.as_bytes()),
        );
        let row = store.conn().query_row(
            "SELECT connection_id, server_id, kind, params, sent_at, recv_at, rtt_us, error
               FROM probes WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Micros>(4)?,
                    row.get::<_, Micros>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        );
        assert_eq!(
            row.expect("the probe row"),
            (
                connection_id,
                server_id,
                "fees".to_string(),
                "[1,2,6]".to_string(),
                Micros(5_000),
                Micros(5_120),
                120,
                None,
            ),
        );
    }

    /// The point of the blob table: forty servers answering the same fee
    /// histogram are one row, and the comparison is an equality of two
    /// addresses rather than of two documents.
    #[tokio::test]
    async fn identical_results_share_one_blob() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;
        let same = json!([[1.0, 2000], [2.0, 3000]]);

        write(
            &store,
            vec![
                probe(1, connection_id, server_id, Some(same.clone())),
                probe(2, connection_id, server_id, Some(same)),
                probe(3, connection_id, server_id, Some(json!([[9.0, 1]]))),
            ],
        )
        .await;

        assert_eq!(count(&store, "blobs"), 2);
        assert_eq!(
            one::<i64>(
                &store,
                "SELECT count(DISTINCT result_blob) FROM probes WHERE id IN (1, 2)",
            ),
            1,
            "the two probes carry the same address",
        );
        assert_ne!(
            one::<String>(&store, "SELECT result_blob FROM probes WHERE id = 1"),
            one::<String>(&store, "SELECT result_blob FROM probes WHERE id = 3"),
        );
    }

    /// A probe that failed has no result and no blob: its error is the
    /// measurement, and it is stored beside the row rather than by content.
    #[tokio::test]
    async fn a_failed_probe_stores_its_error_and_no_blob() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;

        write(
            &store,
            vec![Event::Probe {
                id: 1,
                connection_id,
                server_id,
                kind: "fingerprint".to_string(),
                params: json!([-1]),
                sent_at: Micros(5_000),
                recv_at: Some(Micros(5_050)),
                rtt_us: Some(50),
                result: None,
                error: Some(json!({"code": -32601, "message": "unknown method"})),
            }],
        )
        .await;

        assert_eq!(count(&store, "blobs"), 0);
        assert_eq!(count(&store, "probes WHERE result_blob IS NULL"), 1);
        assert_eq!(
            one::<String>(&store, "SELECT error FROM probes"),
            r#"{"code":-32601,"message":"unknown method"}"#,
        );
    }

    /// `peer_edges.probe_id` names a probe written in the same transaction,
    /// which is the reason probe ids are handed out before the row exists.
    #[tokio::test]
    async fn peer_edges_reference_a_probe_from_the_same_batch() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;
        let probe_id = store.next_probe_id();

        write(
            &store,
            vec![
                probe(probe_id, connection_id, server_id, Some(json!([]))),
                Event::PeerEdges {
                    probe_id,
                    from_server_id: server_id,
                    edges: vec![
                        PeerEdge {
                            peer_host: "fulcrum.grey.pw".to_string(),
                            peer_ip: Some("1.2.3.4".to_string()),
                            features: vec!["v1.4".to_string(), "s50002".to_string()],
                        },
                        PeerEdge {
                            peer_host: "onion.example.onion".to_string(),
                            peer_ip: None,
                            features: vec![],
                        },
                    ],
                },
            ],
        )
        .await;

        let edges = {
            let conn = store.conn();
            let mut statement = conn
                .prepare(
                    "SELECT probe_id, from_server_id, peer_host, peer_ip, features
                       FROM peer_edges ORDER BY peer_host",
                )
                .expect("the query prepares");
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .expect("the query runs")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("an edge row")
        };

        assert_eq!(
            edges,
            vec![
                (
                    probe_id,
                    server_id,
                    "fulcrum.grey.pw".to_string(),
                    Some("1.2.3.4".to_string()),
                    r#"["v1.4","s50002"]"#.to_string(),
                ),
                (
                    probe_id,
                    server_id,
                    "onion.example.onion".to_string(),
                    None,
                    "[]".to_string(),
                ),
            ],
        );
    }

    // -- the writer task

    /// One bad row costs one row. The header below names a connection that
    /// does not exist, which the foreign key refuses; what follows it in the
    /// same batch is still committed, because a collector that stopped at
    /// the first constraint violation would lose everything after it.
    #[tokio::test]
    async fn a_refused_event_does_not_take_the_batch_with_it() {
        let (_dir, store) = temp_store();
        let (server_id, connection_id) = server_and_connection(&store).await;

        write(
            &store,
            vec![
                Event::Header {
                    connection_id: 9_999,
                    server_id,
                    at: Micros(3_000),
                    kind: HeaderKind::Notification,
                    height: 880_000,
                    hash: "00beef".to_string(),
                    prev_hash: None,
                    header_hex: "aabb".to_string(),
                    reorg: false,
                },
                Event::Ping {
                    connection_id,
                    at: Micros(3_100),
                    rtt_us: 7,
                },
            ],
        )
        .await;

        assert_eq!(
            count(&store, "header_events"),
            0,
            "the foreign key refused it"
        );
        assert_eq!(count(&store, "blocks"), 0, "and its block was not booked");
        assert_eq!(count(&store, "pings"), 1, "the rest of the batch survived");
    }

    /// More events than fit in one batch: the full batch is committed and
    /// the rest follow it, rather than one transaction growing without a
    /// bound while the queue has anything in it.
    #[tokio::test]
    async fn a_full_batch_is_committed_and_the_rest_follow() {
        let (_dir, store) = temp_store();
        let (_server_id, connection_id) = server_and_connection(&store).await;
        let events = pings(connection_id, BATCH_EVENTS + 10);

        write(&store, events).await;

        assert_eq!(
            count(&store, "pings"),
            i64::try_from(BATCH_EVENTS + 10).expect("the count fits"),
        );
        assert_eq!(
            store.committed_batches(),
            vec![1, BATCH_EVENTS, 10],
            "the connection of the setup, then a full batch and the rest",
        );
    }

    /// What is queued is committed together, which is the point of the
    /// channel: 450 sessions' observations cost a commit a batch rather than
    /// a commit each.
    #[tokio::test]
    async fn everything_queued_is_committed_as_one_transaction() {
        let (_dir, store) = temp_store();
        let (_server_id, connection_id) = server_and_connection(&store).await;
        let events = pings(connection_id, 50);

        write(&store, events).await;

        assert_eq!(count(&store, "pings"), 50);
        assert_eq!(
            store.committed_batches(),
            vec![1, 50],
            "the connection of the setup, then fifty pings in one transaction",
        );
    }

    /// A partial batch does not wait for company for ever: the timer commits
    /// it, which is the bound on how long an observation sits in memory and
    /// so on what a crash costs.
    #[tokio::test(start_paused = true)]
    async fn a_partial_batch_is_committed_after_the_flush_interval() {
        let (_dir, store) = temp_store();
        let (_server_id, connection_id) = server_and_connection(&store).await;
        let (writer, task) = store.writer();
        let task = tokio::spawn(task);

        writer
            .send(Event::Ping {
                connection_id,
                at: Micros(1),
                rtt_us: 1,
            })
            .await
            .expect("the event is queued");
        tokio::time::sleep(FLUSH_INTERVAL * 3).await;

        assert_eq!(
            count(&store, "pings"),
            1,
            "committed while the channel is still open",
        );
        drop(writer);
        task.await.expect("the writer task ends");
    }

    #[tokio::test]
    async fn sending_after_the_writer_stopped_is_an_error() {
        let (_dir, store) = temp_store();
        let (writer, task) = store.writer();
        drop(task);

        let error = writer
            .send(Event::Ping {
                connection_id: 1,
                at: Micros(1),
                rtt_us: 1,
            })
            .await
            .expect_err("the writer is gone");

        assert!(
            error.to_string().contains("store writer stopped"),
            "{error}"
        );
    }

    #[test]
    fn every_event_names_itself_for_the_log() {
        let names: Vec<&str> = [
            Event::ConnectionStarted {
                id: 1,
                server_id: 1,
                session_index: 0,
                started_at: Micros(0),
            },
            Event::ConnectionEstablished {
                id: 1,
                connected_at: Micros(0),
                remote_ip: None,
                tls: None,
                dns_id: None,
                server_version: None,
                protocol_version: None,
            },
            Event::ConnectionEnded {
                id: 1,
                ended_at: Micros(0),
                end_reason: String::new(),
            },
            Event::DnsResolved {
                id: 1,
                server_id: 1,
                at: Micros(0),
                addresses: vec![],
                error: None,
            },
            Event::Header {
                connection_id: 1,
                server_id: 1,
                at: Micros(0),
                kind: HeaderKind::Subscribe,
                height: 0,
                hash: String::new(),
                prev_hash: None,
                header_hex: String::new(),
                reorg: false,
            },
            Event::TipCheck {
                server_id: 1,
                connection_id: 1,
                at: Micros(0),
                height: None,
                hash: None,
                rtt_us: None,
                error: None,
            },
            Event::Ping {
                connection_id: 1,
                at: Micros(0),
                rtt_us: 0,
            },
            probe(1, 1, 1, None),
            Event::PeerEdges {
                probe_id: 1,
                from_server_id: 1,
                edges: vec![],
            },
        ]
        .iter()
        .map(Event::name)
        .collect();

        assert_eq!(
            names,
            vec![
                "ConnectionStarted",
                "ConnectionEstablished",
                "ConnectionEnded",
                "DnsResolved",
                "Header",
                "TipCheck",
                "Ping",
                "Probe",
                "PeerEdges",
            ],
        );
    }

    // -- Micros

    #[test]
    fn micros_round_trips_through_system_time() {
        let now = SystemTime::now();
        let micros = Micros::from(now);

        // The microsecond the conversion keeps, not the nanoseconds it does
        // not: a SystemTime is finer than the column.
        let truncated = UNIX_EPOCH
            + Duration::from_micros(
                now.duration_since(UNIX_EPOCH)
                    .expect("after the epoch")
                    .as_micros() as u64,
            );
        assert_eq!(micros.to_system_time(), truncated);
        assert_eq!(Micros::from(micros.to_system_time()), micros);
        assert_eq!(micros.as_i64(), micros.0);
    }

    #[test]
    fn micros_round_trips_through_sql() {
        let store = Store::open(":memory:").expect("the in-memory database opens");
        let values = [Micros(0), Micros(1_762_000_000_123_456), Micros(-1_000_000)];

        for (index, value) in values.iter().enumerate() {
            store
                .conn()
                .execute(
                    "INSERT INTO servers
                         (host, port, transport, network, source, added_at, enabled)
                     VALUES (?1, 50002, 'ssl', 'clearnet', 'config', ?2, 1)",
                    params![format!("host{index}.example"), value],
                )
                .expect("the row is written");
        }

        let read: Vec<Micros> = store
            .servers()
            .expect("the servers are read")
            .into_iter()
            .map(|row| row.added_at)
            .collect();
        assert_eq!(read, values.to_vec());
    }

    /// A clock before the epoch is a broken host, not a panic.
    #[test]
    fn a_time_before_the_epoch_is_negative() {
        let before = UNIX_EPOCH - Duration::from_micros(1_500_000);

        let micros = Micros::from(before);

        assert_eq!(micros, Micros(-1_500_000));
        assert_eq!(micros.to_system_time(), before);
    }

    #[test]
    fn now_is_after_the_epoch() {
        assert!(Micros::now().as_i64() > 1_700_000_000_000_000);
    }

    #[test]
    fn the_empty_hash_is_the_known_one() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }
}
