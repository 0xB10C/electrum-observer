//! The collector: everything between the configuration and the shutdown.
//!
//! The modules below this one each do one thing to one server. This is the
//! one place that knows the order in which they have to be built, and every
//! step of that order is here for a reason:
//!
//! 1. **The database first.** Nothing else can be recorded before it is
//!    open, and `meta` gets the two facts about this run -- which
//!    configuration produced it and when it started -- before a single
//!    socket does anything that would be explained by them.
//! 2. **`servers_file` next.** It is the operator's own list, so it is in
//!    `servers` before the enabled set is read, and a session is opened to
//!    it on this run rather than on the next one.
//! 3. **Tor before the dialer**, because the dialer is built once and the
//!    onion seam is installed into it. A failed bootstrap is a warning and a
//!    clearnet-only run -- except under `tor.route_clearnet`, where it is
//!    the end of the run: carrying on would dial every
//!    watched server from this host's own address, which is what switching
//!    the setting on asked us not to do.
//! 4. **The tracker before the sessions**, seeded from `blocks`, so that a
//!    restart during a split does not arm a divergence window over hashes
//!    the database already holds.
//! 5. **The writer before anything that observes**, so no event is dropped
//!    for want of a reader.
//! 6. **The sessions last**, one per enabled server times its session count.
//!
//! What runs after that is a loop over three things: peer lists becoming
//! servers and their sessions, a status line, and the
//! stop flag. It is a loop rather than three tasks because the
//! [`JoinSet`] of sessions is what discovery adds to and what the shutdown
//! waits for, and a `JoinSet` has one owner.
//!
//! **The shutdown is the reason this is a function and not a `main`.** It
//! has an order too, and every step of it exists to lose nothing:
//!
//! 1. the flag flips, which every session is watching;
//! 2. every session task is awaited, so that the last `ConnectionEnded` of
//!    each is queued before anything else happens;
//! 3. the [`SessionContext`] is dropped, which drops the last
//!    [`crate::store::StoreWriter`] and so closes the event channel;
//! 4. the writer task is awaited, and it returns when it has committed what
//!    the closing left in the queue.
//!
//! Reversing any two of those costs data: dropping the writer first would
//! strand the events the sessions have not sent yet, and awaiting the writer
//! before the sessions would wait forever on a channel they still hold.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tracing::{debug, info, warn};

use crate::TARGET_RUN as TARGET;
use crate::dial::Dialer;
use crate::discovery::Discovery;
use crate::endpoint::Network;
use crate::headers::Tracker;
use crate::session::{SessionContext, run_session};
use crate::settings::Settings;
use crate::shutdown::Shutdown;
use crate::store::{Micros, ServerRow, Store};
use crate::{seeds, tor};

/// How many of the `blocks` rows the tracker is seeded with.
///
/// A retarget period, which is the window the tracker prunes to anyway and
/// far more than a split can be deep: what the seed has to cover is "is this
/// hash news", and a hash from two weeks ago being treated as news costs one
/// divergence window that closes on its own.
const KNOWN_BLOCKS: usize = 2016;

/// How many peer lists may be waiting to be turned into servers.
///
/// A session sends one per `server.peers.subscribe`, so the queue only
/// builds up when six hundred identity sets land in the same second as an
/// insert that is waiting on the disk. Past it a session waits, which costs
/// that session's next probe rather than the measurement -- the peer list
/// has already been stored by then, and its `peer_edges` with it.
const CHANNEL_PEERS: usize = 256;

/// How often the status line is logged.
///
/// Not a configuration key: it is one line a minute whose purpose is to make
/// a log that is otherwise silent for hours say that the process is still
/// collecting, and a key for it would be a key nobody has a reason to set.
const STATUS_INTERVAL: Duration = Duration::from_secs(60);

/// Collect until `shutdown` is raised.
///
/// The whole daemon, minus what only a process can do: the configuration is
/// already loaded and validated, the subscriber is already installed, the
/// descriptor limit is already raised and the signal handlers are already
/// armed (see `main.rs`). Everything else is here, so that the end-to-end
/// test drives exactly what the binary drives.
///
/// Returns `Ok(())` once every session has ended and everything they
/// observed has been committed. The errors are the four things that make a
/// collection impossible rather than incomplete: a database that cannot be
/// opened or migrated, a `servers_file` that is not a list of endpoints, a
/// dialer that cannot be built, and a missing Tor under
/// `tor.route_clearnet`.
pub async fn run(settings: Settings, shutdown: Shutdown) -> Result<()> {
    let settings = Arc::new(settings);
    let store = Store::open(&settings.database)?;
    record_run(&store, &settings)?;
    import_servers_file(&store, &settings)?;

    // The Tor seam, in the one order that works: the bootstrap is bounded,
    // its failure is ordinarily a clearnet-only run, `tor.route_clearnet` is
    // the one setting under which it is not, and the onion and the routed
    // clearnet dialer differ in their stream preferences so that an onion
    // name can never reach an exit.
    let tor = tor::bootstrap(&settings.tor, &settings.tor_state_dir()).await;
    if let Some(reason) = tor.required_by(&settings.tor) {
        bail!(reason);
    }
    let mut dialer = Dialer::new(&settings)?;
    if let Some(handle) = tor.handle() {
        dialer = dialer.with_onion(handle.onion_dialer());
        if settings.tor.route_clearnet {
            dialer = dialer.with_clearnet_via(handle.clearnet_dialer());
        }
    }
    let tor_ready = tor.handle().is_some();

    let tracker = Tracker::with_known_blocks(
        settings.divergence.window(),
        store
            .recent_blocks(KNOWN_BLOCKS)
            .context("reading the known blocks")?,
    );
    let known_blocks = tracker.block_count();

    let (writer, writer_task) = store.writer();
    let writer_task = tokio::spawn(writer_task);
    let (peers_tx, mut peers_rx) = mpsc::channel(CHANNEL_PEERS);

    // Every session gets a clone of this, and every one of them gets the
    // peer channel. What an advertisement becomes is `Discovery`'s decision
    // and not a session's: the `peer_edges` rows are written either way,
    // because the advertisement graph is data whether or not anything is
    // dialed because of it.
    let ctx = SessionContext {
        settings: Arc::clone(&settings),
        dialer: Arc::new(dialer),
        store: store.clone(),
        writer,
        tracker: Arc::new(Mutex::new(tracker)),
        peers_tx: Some(peers_tx),
    };
    let discovery = Discovery::new(store.clone(), &settings.discovery, tor_ready);
    let mut supervisor = Supervisor::new(ctx, &settings, tor_ready, shutdown.watcher());

    let enabled = store
        .enabled_servers()
        .context("reading the enabled servers")?;
    for server in &enabled {
        supervisor.open(server);
    }
    // The session count comes from the `JoinSet` rather than from a counter
    // of what `open` said: what the line is read as is "this many
    // connections are being held open", and the set is the only thing that
    // knows that.
    info!(
        target: TARGET,
        servers = enabled.len(),
        sessions = supervisor.sessions.len(),
        skipped_onion = supervisor.skipped_onion,
        tor = tor.as_str(),
        known_blocks,
        "collecting",
    );

    // Immediately after the startup line would be the same numbers twice, so
    // the first status line is a whole interval out.
    let mut status = interval_at(Instant::now() + STATUS_INTERVAL, STATUS_INTERVAL);
    status.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut stop = shutdown.watcher();
    while !*stop.borrow_and_update() {
        tokio::select! {
            // Nothing to do but leave the loop; the condition above is what
            // reads the flag, so that a flag already raised when this
            // function was called is not waited on.
            _ = stop.changed() => {}
            Some((server_id, peers)) = peers_rx.recv() => {
                for server in &discovery.ingest(server_id, &peers).newly_enabled {
                    supervisor.open(server);
                }
            }
            _ = status.tick() => {
                // The block book's size is the one store counter that costs
                // nothing to read -- a map length under a lock every session
                // takes around a map insert -- so it is the one this line
                // carries. Everything else a minute's collection produced is
                // a count over a growing table, which is a query for a
                // reader and not for a log line.
                let blocks = supervisor
                    .ctx
                    .tracker
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .block_count();
                info!(
                    target: TARGET,
                    sessions = supervisor.sessions.len(),
                    blocks,
                    "still collecting",
                );
            }
            // A session only returns on its own when the server turned out
            // to be on another chain, and then it is reaped here so that the
            // status line counts what is actually open.
            Some(joined) = supervisor.sessions.join_next(), if !supervisor.sessions.is_empty() => {
                if let Err(error) = joined {
                    warn!(target: TARGET, %error, "a session task did not finish cleanly");
                }
            }
        }
    }

    info!(
        target: TARGET,
        sessions = supervisor.sessions.len(),
        "stopping: waiting for the sessions to end their connections",
    );
    supervisor.join().await;
    // The sessions are gone, so this drops the last `StoreWriter` and the
    // event channel closes; the writer task commits what is queued and
    // returns.
    drop(supervisor);
    if let Err(error) = writer_task.await {
        warn!(target: TARGET, %error, "the store writer did not finish cleanly");
    }
    info!(target: TARGET, "stopped");
    Ok(())
}

/// Writes the two `meta` rows that describe this run.
///
/// `started_at` is written here and not only by [`Store::open`], which
/// stamps it for every subcommand: an `import` run yesterday would otherwise
/// be what a reader of the column sees, and what the column is read as is
/// "the collection that produced the newest rows began here".
fn record_run(store: &Store, settings: &Settings) -> Result<()> {
    if let Some(sha256) = &settings.config_sha256 {
        store
            .set_meta("config_sha256", sha256)
            .context("recording the configuration hash")?;
    }
    store
        .set_meta("started_at", &Micros::now().as_i64().to_string())
        .context("recording the start of the run")
}

/// Puts `servers_file`, when there is one, into `servers`.
///
/// Uncapped and as `source = 'config'`, exactly as the `import file`
/// subcommand does and for its reason: `discovery.max_servers` is about peer
/// lists, which are unbounded and partly stale, while this list is what the
/// operator asked to be watched. A line that is not an endpoint fails the
/// run rather than being skipped, because a collector quietly watching a
/// shorter list than its file names is a database that looks complete.
fn import_servers_file(store: &Store, settings: &Settings) -> Result<()> {
    let Some(file) = &settings.servers_file else {
        return Ok(());
    };
    let endpoints = seeds::from_file(file)?;
    for endpoint in &endpoints {
        store
            .upsert_server(endpoint, seeds::SOURCE_FILE, None)
            .with_context(|| format!("adding {endpoint}"))?;
    }
    debug!(
        target: TARGET,
        file = %file.display(),
        endpoints = endpoints.len(),
        "the configured server list was read",
    );
    Ok(())
}

/// The sessions, and what it takes to open another one.
///
/// A struct rather than a handful of locals because two places open
/// sessions -- the enabled set at startup and every peer list afterwards --
/// and the rules are the same for both: the session count from `overrides`
/// or `sessions_per_server`, and no session at all to an onion address while
/// Tor is not up.
struct Supervisor {
    /// What every session is handed a clone of, and the owner of the last
    /// [`crate::store::StoreWriter`] once the sessions have ended.
    ctx: SessionContext,
    /// One task per session.
    sessions: JoinSet<()>,
    /// `overrides`, by canonical endpoint string.
    ///
    /// By the string rather than by the [`crate::Endpoint`] because that
    /// string is the identity the config file, the log and the `servers`
    /// listing all use, and a map of them is one lookup per server rather
    /// than a scan of the overrides per server.
    overrides: HashMap<String, usize>,
    /// What a server not named in `overrides` gets.
    sessions_per_server: usize,
    /// Whether an onion endpoint can be dialed at all.
    tor_ready: bool,
    /// Handed to every session, so one flag ends all of them.
    stop: watch::Receiver<bool>,
    /// How many servers got no session because they are onion addresses and
    /// Tor is not up.
    skipped_onion: usize,
}

impl Supervisor {
    fn new(
        ctx: SessionContext,
        settings: &Settings,
        tor_ready: bool,
        stop: watch::Receiver<bool>,
    ) -> Self {
        Supervisor {
            ctx,
            sessions: JoinSet::new(),
            overrides: settings
                .overrides
                .iter()
                .map(|over| (over.endpoint.to_string(), over.sessions))
                .collect(),
            sessions_per_server: settings.sessions_per_server,
            tor_ready,
            stop,
            skipped_onion: 0,
        }
    }

    /// How many connections this server is owed.
    fn sessions_for(&self, server: &ServerRow) -> usize {
        self.overrides
            .get(&server.endpoint.to_string())
            .copied()
            .unwrap_or(self.sessions_per_server)
    }

    /// Opens a server's sessions, and says how many that was.
    ///
    /// Zero for an onion server while Tor is not up: a session to it would
    /// be a dial that fails as [`crate::dial::DialError::TorUnavailable`],
    /// a `connections` row saying so, and a backoff that repeats both for
    /// the life of the process. The servers are left enabled, because what
    /// is missing is Tor and not the server, and the next run with a working
    /// bootstrap watches them without an operator doing anything.
    fn open(&mut self, server: &ServerRow) -> usize {
        if server.endpoint.network() == Network::Onion && !self.tor_ready {
            self.skipped_onion += 1;
            return 0;
        }
        let sessions = self.sessions_for(server);
        for session_index in 0..sessions {
            self.sessions.spawn(run_session(
                self.ctx.clone(),
                server.clone(),
                session_index,
                self.stop.clone(),
            ));
        }
        debug!(
            target: TARGET,
            server_id = server.id,
            endpoint = %server.endpoint,
            sessions,
            "sessions opened",
        );
        sessions
    }

    /// Waits for every session to return.
    ///
    /// Unbounded on purpose. A session returns when it next looks at the
    /// stop flag, which it does in the same select as its timers and its
    /// socket, and the longest it can be between two of those is
    /// `timeouts.request_secs`. A deadline here would mean abandoning
    /// sessions whose `ConnectionEnded` has not been queued yet, which is
    /// the one row that makes the uptime of a connection readable.
    async fn join(&mut self) {
        while let Some(joined) = self.sessions.join_next().await {
            if let Err(error) = joined {
                warn!(target: TARGET, %error, "a session task did not finish cleanly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::Override;

    fn settings() -> Settings {
        Settings {
            database: PathBuf::from("observer.sqlite"),
            ..Settings::default()
        }
    }

    fn server(id: i64, endpoint: &str) -> ServerRow {
        ServerRow {
            id,
            endpoint: endpoint.parse().expect("an endpoint"),
            source: "config".to_string(),
            added_at: Micros(0),
            enabled: true,
            disabled_reason: None,
        }
    }

    /// A supervisor whose sessions are born stopped.
    ///
    /// What is under test here is the session count and the onion gate, both
    /// decided before anything is spawned, and a session handed a raised
    /// flag returns before it dials: these tests are about the supervisor's
    /// arithmetic and must not open a socket to anything.
    ///
    /// The temporary directory is dropped before the function returns, so
    /// the database file is gone and the handle on it is all that is left --
    /// which is enough, because nothing here writes.
    fn supervisor(settings: &Settings, tor_ready: bool) -> Supervisor {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(dir.path().join("observer.sqlite")).expect("the database opens");
        let (writer, _task) = store.writer();
        let ctx = SessionContext {
            settings: Arc::new(settings.clone()),
            dialer: Arc::new(Dialer::new(settings).expect("a dialer")),
            store: store.clone(),
            writer,
            tracker: Arc::new(Mutex::new(Tracker::new(settings.divergence.window()))),
            peers_tx: None,
        };
        Supervisor::new(ctx, settings, tor_ready, watch::channel(true).1)
    }

    /// `overrides` is read by the canonical endpoint string, so the spelling
    /// in the file does not have to be the spelling in the database.
    #[tokio::test]
    async fn an_override_names_an_endpoint_however_it_is_spelled() {
        let settings = Settings {
            sessions_per_server: 2,
            overrides: vec![
                Override {
                    endpoint: "tool.sh:50002:s".parse().expect("an endpoint"),
                    sessions: 5,
                },
                Override {
                    endpoint: "tcp://Fulcrum.Grey.PW:50001".parse().expect("an endpoint"),
                    sessions: 3,
                },
            ],
            ..settings()
        };
        let supervisor = supervisor(&settings, false);

        assert_eq!(
            supervisor.sessions_for(&server(1, "ssl://tool.sh:50002")),
            5,
            "the override, whichever spelling the file used",
        );
        assert_eq!(
            supervisor.sessions_for(&server(2, "tcp://fulcrum.grey.pw:50001")),
            3,
            "the host is canonicalised on both sides",
        );
        assert_eq!(
            supervisor.sessions_for(&server(3, "ssl://fulcrum.grey.pw:50002")),
            2,
            "another port of an overridden host is not the overridden endpoint",
        );
        assert_eq!(
            supervisor.sessions_for(&server(4, "ssl://other.example:50002")),
            2,
            "everything else takes sessions_per_server",
        );
    }

    /// An onion server gets no session while Tor is not up, and is counted
    /// so that the startup line can say how many were left alone.
    #[tokio::test]
    async fn onion_servers_are_skipped_until_tor_is_ready() {
        const ONION: &str =
            "ssl://sdmzuu6ktcrw4b5kcveqgpvmqv2ppkqpxdvtmyjwlsv7nw7weqgqjrqd.onion:50002";
        let settings = settings();

        let mut without = supervisor(&settings, false);
        assert_eq!(without.open(&server(1, ONION)), 0, "no session, no dial");
        assert_eq!(without.skipped_onion, 1);
        assert_eq!(
            without.open(&server(2, "ssl://tool.sh:50002")),
            1,
            "a clearnet server is not waiting for Tor",
        );
        assert_eq!(without.skipped_onion, 1);

        let mut with = supervisor(&settings, true);
        assert_eq!(
            with.open(&server(1, ONION)),
            1,
            "and with Tor up it is a server like any other",
        );
        assert_eq!(with.skipped_onion, 0);
    }

    /// Every session of a server is spawned, numbered from zero: index 0 is
    /// the one that probes and the rest are the floor two connections to one
    /// endpoint put under every cross-server delta.
    #[tokio::test]
    async fn a_server_gets_one_session_per_index() {
        let settings = Settings {
            sessions_per_server: 3,
            ..settings()
        };
        let mut supervisor = supervisor(&settings, false);

        assert_eq!(supervisor.open(&server(1, "ssl://tool.sh:50002")), 3);
        assert_eq!(supervisor.sessions.len(), 3, "one task each");
        assert_eq!(
            supervisor.open(&server(2, "ssl://other.example:50002")),
            3,
            "and three more for the next server",
        );
        assert_eq!(supervisor.sessions.len(), 6);

        // They were handed a flag that is already raised, so every one of
        // them returns rather than dialing anything.
        supervisor.join().await;
        assert_eq!(supervisor.sessions.len(), 0, "every session was awaited");
    }
}
