//! The in-process Tor client, and the two dialers it lends to [`crate::dial`].
//!
//! Adapted from crawler's `dial.rs` -- `bootstrap_tor`, `arti_config`,
//! `onion_prefs` and `TorState`. What is kept is the shape: one bounded wait
//! at startup, a failure that is a reason rather than an error, and arti
//! reached through a boxed closure so that nothing in this crate has to name
//! the runtime type `arti-client` does not re-export. What is dropped is the
//! client pool and the circuit knobs, which belong to a crawler that opens a
//! connection per relay and throws it away: this collector holds one
//! connection per server open for the lifetime of the process, so one client
//! with one guard set is both enough and the quieter thing to be. What is
//! added is [`TorHandle::clearnet_dialer`], for `tor.route_clearnet`.
//!
//! **A failed bootstrap is not a failed run** (DESIGN.md section 9). Onion
//! sessions wait for Tor; clearnet sessions do not and start immediately, so
//! a host that cannot reach the Tor network still collects everything the
//! clearnet servers say. The reason is kept and logged rather than returned,
//! which is why [`bootstrap`] has no `Result`: there is nothing a caller
//! could usefully do with it that is not "carry on without onion servers".
//!
//! The exception is `tor.route_clearnet`. That setting exists so that the
//! servers being watched cannot trivially identify the observer, and a run
//! that quietly fell back to dialing them from our own address when the
//! bootstrap failed would break exactly the promise it was switched on for.
//! A caller that sets it must treat [`TorState::Failed`] as fatal; see
//! [`TorState::required_by`].
//!
//! What this logs goes under `dial` rather than a target of its own. The
//! bootstrap is the first half of what `dial: debug` is turned up for -- an
//! operator asking why an onion server is not being reached wants the reason
//! Tor did not come up in the same stream as the dials that then failed, and
//! a second target would split one story in two.
//!
//! Bootstrapping happens once per process. [`TorHandle`] is cheap to clone a
//! dialer out of -- arti's `TorClient` is itself a handle -- and the dialers
//! are `Send + Sync`, so the 450 sessions of a run share one client and one
//! set of guards rather than negotiating a directory each.

use std::fmt;
use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::{BoolOrAuto, CfgPath, ConfigBuildError};
use arti_client::{StreamPrefs, TorClient, TorClientConfig};

use crate::TARGET_DIAL as TARGET;
use crate::dial::{BoxStream, OnionDialer, OpeningStream};
use crate::settings::TorSettings;

/// Which kind of target a stream is being opened to.
///
/// The two differ only in their [`StreamPrefs`], but they differ in the one
/// way that matters: an onion dial asks arti for a rendezvous and a clearnet
/// dial asks an exit for a TCP connection, and a preference set that allowed
/// both would let `tor.route_clearnet` send an onion name to an exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// A `.onion` name, resolved and reached by Tor itself.
    Onion,
    /// A name or address on the ordinary internet, reached through an exit.
    Clearnet,
}

/// Whatever opens a stream through Tor: the whole of what [`TorHandle`] is.
///
/// A boxed closure for crawler's two reasons. `TorClient` is generic over its
/// runtime and the runtime arti picks for us is not re-exported by
/// `arti-client`, so writing the type in a field would mean depending on one
/// more of arti's crates, while inside a closure it is inferred and never
/// written. And a handle whose whole content is "open a stream" can be stood
/// in for by a closure that refuses or stalls on command, which no real
/// client can be asked to do without a Tor network to refuse on.
type Connect = Arc<dyn Fn(String, u16, Route) -> OpeningStream + Send + Sync>;

/// A bootstrapped Tor client, as far as this crate wants one.
///
/// Cloned from, not cloned: [`onion_dialer`](Self::onion_dialer) and
/// [`clearnet_dialer`](Self::clearnet_dialer) each hand out a boxed closure
/// over the same client, and arti's client is itself an `Arc` inside, so a
/// dialer costs a pointer and not a circuit.
pub struct TorHandle {
    connect: Connect,
}

impl fmt::Debug for TorHandle {
    /// There is nothing to print: the handle is one closure, and what a
    /// reader of a log wants to know -- whether Tor is up -- is
    /// [`TorState`]'s.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TorHandle")
    }
}

impl TorHandle {
    /// A handle over whatever opens a stream.
    ///
    /// [`bootstrap`] builds the real one over an arti client; this is the
    /// seam a test stands in for it with, which is the only way the
    /// [`crate::dial::Dialer`] side of this can be exercised without a Tor
    /// network to be refused by.
    pub fn new(
        connect: impl Fn(String, u16, Route) -> OpeningStream + Send + Sync + 'static,
    ) -> Self {
        Self {
            connect: Arc::new(connect),
        }
    }

    /// The dialer [`crate::dial::Dialer::with_onion`] takes.
    pub fn onion_dialer(&self) -> OnionDialer {
        self.dialer(Route::Onion)
    }

    /// The dialer [`crate::dial::Dialer::with_clearnet_via`] takes, for
    /// `tor.route_clearnet`.
    ///
    /// The same shape as the onion one, and deliberately: a clearnet dial
    /// routed through Tor learns no more about the far end than an onion dial
    /// does. The exit does the connecting and, for a hostname, the resolving,
    /// so the `connections` row has no `remote_ip` and there is no
    /// `dns_resolutions` row at all -- which is why the setting costs
    /// something besides latency and is off by default (DESIGN.md section 9).
    pub fn clearnet_dialer(&self) -> OnionDialer {
        self.dialer(Route::Clearnet)
    }

    /// One dialer, bound to the preferences of one route.
    fn dialer(&self, route: Route) -> OnionDialer {
        let connect = Arc::clone(&self.connect);
        Box::new(move |host, port| connect(host, port, route))
    }
}

/// Whether this run has Tor, and if not, why not.
///
/// Three states and not two, because "the operator switched it off" and "it
/// would not start" are different things to find in a log and different
/// things for `tor.route_clearnet` to do about (see
/// [`required_by`](Self::required_by)).
#[derive(Debug)]
pub enum TorState {
    /// `tor.enabled` is false. Onion endpoints are never dialed, and nothing
    /// was written to the state directory.
    Disabled,
    /// arti is up and has a directory.
    Ready(TorHandle),
    /// arti did not come up, in its own words or ours. Onion endpoints fail
    /// as [`crate::dial::DialError::TorUnavailable`] and the clearnet
    /// collection is unaffected.
    Failed(String),
}

impl TorState {
    /// The handle to install on a [`crate::dial::Dialer`], or `None`.
    pub fn handle(&self) -> Option<&TorHandle> {
        match self {
            Self::Ready(handle) => Some(handle),
            Self::Disabled | Self::Failed(_) => None,
        }
    }

    /// Why there is no Tor, for the log and for the operator.
    ///
    /// `None` for a run that has it, and for one that was told not to want
    /// it: a disabled Tor has no failure to report.
    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason),
            Self::Ready(_) | Self::Disabled => None,
        }
    }

    /// The word for this state in a log line or a status column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Ready(_) => "ready",
            Self::Failed(_) => "failed",
        }
    }

    /// Whether these settings make a run without Tor a run that must not
    /// start, and the reason it must not.
    ///
    /// Only `tor.route_clearnet` does. It is switched on so that the servers
    /// being watched cannot trivially identify the observer, and a run that
    /// carried on after a failed bootstrap would dial every one of them from
    /// our own address -- the one thing the setting was there to prevent. So
    /// this is the one Tor failure a caller turns into an exit rather than a
    /// warning; everything else is "carry on, clearnet only".
    pub fn required_by(&self, settings: &TorSettings) -> Option<String> {
        if !settings.route_clearnet || self.handle().is_some() {
            return None;
        }
        Some(format!(
            "tor.route_clearnet is set and tor is {}{}: every clearnet dial \
             would go out from this host's own address, which is what the \
             setting is for",
            self.as_str(),
            match self.failure() {
                Some(reason) => format!(" ({reason})"),
                None => String::new(),
            }
        ))
    }
}

/// Start arti and wait, bounded, for it to have a directory.
///
/// The wait is bounded because a host that cannot reach the Tor network must
/// still collect from the clearnet servers: on expiry Tor is switched off for
/// the run rather than the run failing (DESIGN.md section 9,
/// `tor.bootstrap_timeout_secs`). Every way this can go wrong -- a state
/// directory that cannot be made, a configuration arti refuses, a lock it
/// cannot take, a directory it cannot fetch -- ends the same way, with the
/// reason kept for the log.
///
/// Called once per process. Two clients would mean two guard sets and two
/// directory fetches for a daemon whose onion connections are opened once and
/// then held, which is the opposite trade from the one crawler's pool makes.
pub async fn bootstrap(settings: &TorSettings, state_dir: &Path) -> TorState {
    if !settings.enabled {
        tracing::debug!(
            target: TARGET,
            "tor is disabled: onion endpoints will not be dialed",
        );
        return TorState::Disabled;
    }
    let state = bounded(settings.bootstrap_timeout(), start(state_dir)).await;
    match &state {
        TorState::Ready(_) => tracing::info!(
            target: TARGET,
            state_dir = %state_dir.display(),
            "arti bootstrapped",
        ),
        TorState::Failed(reason) => tracing::warn!(
            target: TARGET,
            %reason,
            "tor is not available: onion endpoints will not be dialed",
        ),
        // `bounded` never returns it. Spelled out rather than caught by a
        // wildcard, so that a state added later has to be given a log line
        // here instead of silently getting none.
        TorState::Disabled => {}
    }
    state
}

/// The deadline around a start, and the failure it becomes.
///
/// Separate from [`bootstrap`] so that the expiry can be tested without a Tor
/// network: what is bounded is a future, and a future that never finishes is
/// a thing a test can write. The whole start is under the one deadline and
/// not just arti's own `bootstrap()`, which is where crawler puts it --
/// taking the lock on the state directory can wait on another process for as
/// long as fetching a directory can wait on the network, and
/// `tor.bootstrap_timeout_secs` is documented as how long the bootstrap may
/// take, not how long one of its three steps may.
async fn bounded<F>(timeout: Duration, starting: F) -> TorState
where
    F: Future<Output = Result<TorHandle, String>>,
{
    match tokio::time::timeout(timeout, starting).await {
        Ok(Ok(handle)) => TorState::Ready(handle),
        Ok(Err(reason)) => TorState::Failed(reason),
        Err(_) => TorState::Failed(format!(
            "arti did not bootstrap within {} s",
            timeout.as_secs()
        )),
    }
}

/// The three steps of starting the client, each of whose failures is a
/// reason rather than an error: nothing above this cares which one it was,
/// only what to put in the log.
///
/// Nothing here chooses a TLS provider for arti, and that is not an
/// oversight: arti builds its client configuration from rustls's
/// process-wide default provider rather than from one passed in, and rustls
/// installs that from its own crate features when exactly one provider
/// feature is on. `ring` is the only one anything in this graph turns on --
/// see `Cargo.toml` -- so arti gets `ring`, the same provider
/// [`crate::dial`] hands its own configuration explicitly. A dependency that
/// switched aws-lc-rs on would turn that into a panic at the first client,
/// which is the reason the comment in `Cargo.toml` is there.
async fn start(state_dir: &Path) -> Result<TorHandle, String> {
    let layout = Layout::under(state_dir);
    layout
        .create()
        .map_err(|err| format!("the tor state directory {} is unusable: {err}", layout))?;
    let config =
        arti_config(&layout).map_err(|err| format!("arti refused the configuration: {err}"))?;
    let client = TorClient::builder()
        .config(config)
        // The async form: the state directory is locked against other arti
        // instances, and the blocking form would hold a runtime thread while
        // it waited for the lock.
        .create_unbootstrapped_async()
        .await
        .map_err(|err| format!("arti could not start: {err}"))?;
    client
        .bootstrap()
        .await
        .map_err(|err| format!("arti could not bootstrap: {err}"))?;

    // Built once: the preferences are the same for every connect of a kind,
    // and cloning one is cheaper than building it per dial.
    let (onion, clearnet) = (onion_prefs(), clearnet_prefs());
    Ok(TorHandle::new(move |host, port, route| {
        // Both are handles: arti's client is an `Arc` inside, and a dial that
        // held a borrow of it would make the returned future borrow the
        // handle, which the seam's `'static` future cannot.
        let client = client.clone();
        let prefs = match route {
            Route::Onion => onion.clone(),
            Route::Clearnet => clearnet.clone(),
        };
        Box::pin(async move {
            let stream = client
                .connect_with_prefs((host, port), &prefs)
                .await
                // arti's error kinds are its own taxonomy and a mapping of
                // ours would be a second one to keep in step with it; the
                // message is what tells a descriptor that could not be
                // fetched from a rendezvous that failed, and it is what
                // `connections.error` stores.
                .map_err(|err| err.to_string())?;
            Ok(Box::new(stream) as BoxStream)
        })
    }))
}

/// Where arti keeps what it must not lose between runs.
///
/// Two directories under the one `tor.state_dir` of the configuration file,
/// so that the daemon's whole arti footprint is the one path an operator
/// named and a NixOS `StateDirectory` covers it (DESIGN.md section 8).
struct Layout {
    /// `tor.state_dir` itself, kept rather than derived from the two below:
    /// it is what the operator wrote and so what a failure has to name, and
    /// a parent taken back off a path has a "what if there is none" case
    /// that no state directory can ever reach.
    root: PathBuf,
    /// Guards and keys. Losing this means a new guard set, which is a new
    /// set of relays that can see this observer connect.
    state: PathBuf,
    /// The directory cache, which is a SQLite database. Losing it means one
    /// slow bootstrap and nothing else.
    cache: PathBuf,
}

impl Layout {
    /// The layout under one state directory.
    fn under(state_dir: &Path) -> Self {
        Self {
            root: state_dir.to_path_buf(),
            state: state_dir.join("state"),
            cache: state_dir.join("cache"),
        }
    }

    /// Both directories, created if they are not there.
    ///
    /// arti would create them itself; doing it here is what turns "the path
    /// in the configuration file is not writable" into a reason at startup
    /// rather than an arti error whose wording is about a lock file.
    fn create(&self) -> io::Result<()> {
        fs::create_dir_all(&self.state)?;
        fs::create_dir_all(&self.cache)
    }
}

impl fmt::Display for Layout {
    /// The directory the two live under, which is what the operator wrote.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.root.display())
    }
}

/// arti's configuration, as far as this crate has opinions about it.
///
/// Only the two paths. Crawler also sets the circuit timings and a consensus
/// parameter, because a crawler leans on one guard set with thousands of
/// attempts; this daemon opens a handful of onion connections and holds them,
/// so arti's own defaults are the right ones and a number of ours would be a
/// number to keep in step with arti for no gain.
fn arti_config(layout: &Layout) -> Result<TorClientConfig, ConfigBuildError> {
    let mut builder = TorClientConfig::builder();
    builder
        .storage()
        // Literal paths: `CfgPath::new` would expand `${ARTI_CACHE}` and the
        // like out of a string that came from our own configuration file,
        // where no such expansion is documented.
        .state_dir(CfgPath::new_literal(layout.state.clone()))
        .cache_dir(CfgPath::new_literal(layout.cache.clone()));
    builder.build()
}

/// The preferences every onion connect uses.
///
/// Onion services explicitly rather than by arti's default, which is to
/// follow `address_filter.allow_onion_addrs`: a daemon whose onion endpoints
/// are the reason arti is linked in at all should not be able to have them
/// switched off underneath it by a default of arti's changing.
fn onion_prefs() -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    prefs
}

/// The preferences every `tor.route_clearnet` connect uses.
///
/// The mirror image: onion services explicitly off, so that a bug that sent
/// an onion endpoint down the clearnet dialer fails loudly instead of
/// quietly working with the wrong isolation. Everything else is arti's
/// default, which is an exit of its choosing.
fn clearnet_prefs() -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(false));
    prefs
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use std::sync::Mutex;

    use tokio::io::AsyncReadExt;

    use crate::Settings;
    use crate::dial::{DialError, Dialer};
    use crate::endpoint::Endpoint;

    /// The Tor Project's own onion service, which is the address `dial.rs`'s
    /// tests already use: a real v3 address, so the endpoint parser accepts
    /// it, and one that really exists, so the ignored test below can reach
    /// it.
    const ONION: &str = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";

    /// Settings with Tor on and a bootstrap timeout that would be noticed.
    fn enabled(state_dir: Option<PathBuf>) -> TorSettings {
        TorSettings {
            enabled: true,
            bootstrap_timeout_secs: 1,
            state_dir,
            route_clearnet: false,
        }
    }

    /// A handle that records what it was asked for and hands back a stream
    /// that says which route it came by.
    fn recording(seen: Arc<Mutex<Vec<(String, u16, Route)>>>) -> TorHandle {
        TorHandle::new(move |host, port, route| {
            seen.lock().expect("not poisoned").push((host, port, route));
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut theirs = theirs;
                    tokio::io::AsyncWriteExt::write_all(&mut theirs, b"tor")
                        .await
                        .expect("the write lands");
                });
                Ok(Box::new(ours) as BoxStream)
            })
        })
    }

    fn dialer() -> Dialer {
        Dialer::new(&Settings::default()).expect("the system resolver configuration is readable")
    }

    fn endpoint(text: &str) -> Endpoint {
        Endpoint::from_str(text).expect("the test endpoint parses")
    }

    /// Tor switched off is `Disabled` and nothing else: no directory is made,
    /// no lock is taken, and the path in the configuration file is not even
    /// looked at. A daemon told not to use Tor should leave no trace of arti
    /// on the disk.
    #[tokio::test]
    async fn tor_switched_off_touches_nothing() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let state_dir = dir.path().join("arti");

        let settings = TorSettings {
            enabled: false,
            ..enabled(None)
        };
        let state = bootstrap(&settings, &state_dir).await;

        assert!(matches!(state, TorState::Disabled), "{state:?}");
        assert_eq!(state.as_str(), "disabled");
        assert!(state.handle().is_none());
        assert!(state.failure().is_none());
        assert!(!state_dir.exists(), "a disabled tor wrote to the disk");
    }

    /// A state directory that cannot be made is a reason and not a panic, and
    /// the reason names the directory -- which is the one thing an operator
    /// can do something about.
    ///
    /// The unmakeable directory is one under a regular file, which no
    /// platform will turn into a parent.
    #[tokio::test]
    async fn a_state_directory_that_cannot_be_made_is_the_reason() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"").expect("the file is written");
        let state_dir = file.join("arti");

        let state = bootstrap(&enabled(None), &state_dir).await;

        let reason = state.failure().expect("the directory is unusable");
        assert_eq!(state.as_str(), "failed");
        assert!(state.handle().is_none());
        assert!(
            reason.contains(&state_dir.display().to_string()),
            "the reason does not name the directory: {reason}"
        );
    }

    /// The bootstrap that does not finish in time is reported with the
    /// configured number of seconds in it, so that a log line says which
    /// setting to raise.
    ///
    /// `start_paused` rather than a real wait: the deadline is the thing
    /// under test and a test that took the timeout to run would be a test
    /// nobody runs.
    #[tokio::test(start_paused = true)]
    async fn a_bootstrap_that_runs_long_is_a_failure_naming_the_timeout() {
        let state = bounded(Duration::from_secs(300), std::future::pending()).await;

        let reason = state.failure().expect("the deadline ran out");
        assert_eq!(reason, "arti did not bootstrap within 300 s");
        assert!(state.handle().is_none());
    }

    /// A start that finishes in time is `Ready`, with the handle it made.
    ///
    /// The `Debug` is asserted here rather than left to a failing assertion
    /// to print: a handle is a closure with nothing to show, and a derived
    /// `Debug` over it would not compile, so what it prints is written by
    /// hand and is worth pinning.
    #[tokio::test(start_paused = true)]
    async fn a_start_that_finishes_in_time_is_ready() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let state = bounded(Duration::from_secs(300), async {
            Ok(recording(Arc::clone(&seen)))
        })
        .await;

        assert_eq!(state.as_str(), "ready");
        assert!(state.handle().is_some());
        assert!(state.failure().is_none());
        assert_eq!(format!("{state:?}"), "Ready(TorHandle)");
    }

    /// A start that fails keeps its own words rather than the deadline's.
    #[tokio::test(start_paused = true)]
    async fn a_start_that_refuses_keeps_its_reason() {
        let state = bounded(Duration::from_secs(300), async {
            Err("arti could not start: no keys".to_owned())
        })
        .await;

        assert_eq!(state.failure(), Some("arti could not start: no keys"));
    }

    /// The state directory is `<tor.state_dir>/state` and the cache
    /// `<tor.state_dir>/cache`, both made if missing, so that one path in the
    /// configuration file is arti's whole footprint (DESIGN.md section 8).
    #[test]
    fn the_layout_is_state_and_cache_under_the_one_directory() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let state_dir = dir.path().join("arti");
        let layout = Layout::under(&state_dir);

        assert_eq!(layout.state, state_dir.join("state"));
        assert_eq!(layout.cache, state_dir.join("cache"));
        assert_eq!(layout.to_string(), state_dir.display().to_string());

        layout.create().expect("the directories are made");
        assert!(layout.state.is_dir());
        assert!(layout.cache.is_dir());

        // Again, over directories that are already there.
        layout.create().expect("a second create is a no-op");
        assert!(layout.state.is_dir());
    }

    /// arti accepts the configuration this builds, and the configuration it
    /// accepted is the one with our directories in it.
    ///
    /// Neither half is a tautology. The builder validates, so a path kind or
    /// a field name that stopped being what arti wants fails here rather
    /// than at the first onion dial of a deployment; and a configuration
    /// that built but carried arti's default directories would put the
    /// guards somewhere no `StateDirectory` covers, which is a bug no test
    /// of the paths alone would see.
    #[test]
    fn the_configuration_arti_is_given_builds_with_our_directories() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let layout = Layout::under(dir.path());

        let config = arti_config(&layout).expect("arti accepts the configuration");

        // Through `Debug`, because arti's accessors for these are private
        // and the question is only whether the paths reached the value.
        let described = format!("{config:?}");
        for path in [&layout.state, &layout.cache] {
            assert!(
                described.contains(&path.display().to_string()),
                "{} is not in the configuration: {described}",
                path.display(),
            );
        }
    }

    /// The two preference sets differ in the one way that matters, and
    /// neither leaves it to arti's default.
    #[test]
    fn the_two_routes_differ_in_whether_onion_services_are_allowed() {
        let onion = format!("{:?}", onion_prefs());
        let clearnet = format!("{:?}", clearnet_prefs());

        assert_ne!(onion, clearnet);
        assert!(onion.contains("Explicit(true)"), "{onion}");
        assert!(clearnet.contains("Explicit(false)"), "{clearnet}");
    }

    /// The handle's two dialers are the seam [`crate::dial`] takes, and each
    /// carries its own route to the client.
    #[tokio::test]
    async fn each_dialer_asks_for_its_own_route() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = recording(Arc::clone(&seen));

        let onion: OnionDialer = handle.onion_dialer();
        let clearnet: OnionDialer = handle.clearnet_dialer();
        onion(ONION.to_owned(), 50001).await.expect("it opens");
        clearnet("example.com".to_owned(), 50002)
            .await
            .expect("it opens");

        assert_eq!(
            *seen.lock().expect("not poisoned"),
            vec![
                (ONION.to_owned(), 50001, Route::Onion),
                ("example.com".to_owned(), 50002, Route::Clearnet),
            ]
        );
    }

    /// The dialers are `Send + Sync` and may be called from several tasks at
    /// once: one client serves every session, which is the whole reason the
    /// bootstrap happens once.
    #[tokio::test]
    async fn one_handle_serves_concurrent_dials() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let dial = Arc::new(recording(Arc::clone(&seen)).onion_dialer());

        let mut tasks = Vec::new();
        for port in 0..8u16 {
            let dial = Arc::clone(&dial);
            tasks.push(tokio::spawn(async move {
                dial(ONION.to_owned(), 50_000 + port)
                    .await
                    .expect("it opens")
            }));
        }
        for task in tasks {
            task.await.expect("the task does not panic");
        }

        assert_eq!(seen.lock().expect("not poisoned").len(), 8);
    }

    /// The onion dialer, installed on a `Dialer`, is what an onion endpoint
    /// goes through.
    #[tokio::test]
    async fn an_onion_endpoint_goes_through_the_handle() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = recording(Arc::clone(&seen));

        let mut dialed = dialer()
            .with_onion(handle.onion_dialer())
            .dial(&endpoint(&format!("tcp://{ONION}:50001")))
            .await
            .expect("the handle opens the stream");

        assert_eq!(
            *seen.lock().expect("not poisoned"),
            vec![(ONION.to_owned(), 50001, Route::Onion)]
        );
        assert_eq!(dialed.remote_ip, None);
        assert_eq!(dialed.dns, None);
        let mut said = [0u8; 3];
        dialed.stream.read_exact(&mut said).await.expect("it reads");
        assert_eq!(&said, b"tor");
    }

    /// A client that will not open the stream reaches the caller as `tor`
    /// with arti's own words in it, which is the `connections.end_reason` a
    /// rendezvous that could not be made is recorded under.
    #[tokio::test]
    async fn a_client_that_refuses_is_a_tor_failure() {
        let handle = TorHandle::new(|_, _, _| {
            Box::pin(async { Err("Onion service not found: no descriptor".to_owned()) })
        });

        let error = dialer()
            .with_onion(handle.onion_dialer())
            .dial(&endpoint(&format!("tcp://{ONION}:50001")))
            .await
            .err()
            .expect("the client refused");

        assert!(matches!(error, DialError::Tor(_)), "{error}");
        assert_eq!(error.as_str(), "tor");
        assert!(error.to_string().contains("no descriptor"), "{error}");
    }

    /// `tor.route_clearnet` is the one Tor failure that must stop a run:
    /// carrying on would dial every watched server from this host's own
    /// address, which is what the setting is there to prevent.
    #[test]
    fn route_clearnet_makes_a_missing_tor_fatal() {
        let off = TorSettings {
            route_clearnet: false,
            ..enabled(None)
        };
        let on = TorSettings {
            route_clearnet: true,
            ..enabled(None)
        };
        let failed = TorState::Failed("no directory".to_owned());

        assert_eq!(failed.required_by(&off), None, "it is not on");
        assert_eq!(
            TorState::Ready(TorHandle::new(|_, _, _| Box::pin(async {
                Err(String::new())
            })))
            .required_by(&on),
            None,
            "tor is there",
        );

        let fatal = failed.required_by(&on).expect("a failed tor is fatal");
        assert!(fatal.contains("failed"), "{fatal}");
        assert!(fatal.contains("no directory"), "{fatal}");

        let disabled = TorState::Disabled
            .required_by(&on)
            .expect("a disabled tor is fatal too");
        assert!(disabled.contains("disabled"), "{disabled}");
        assert!(!disabled.contains('('), "no reason to quote: {disabled}");
    }

    /// Really bootstraps arti and really opens a circuit to an onion service.
    ///
    /// Needs the Tor network and a few minutes; run it by hand with
    /// `cargo test --all-features -- --ignored --nocapture tor_really`.
    /// Never in the per-commit checklist: a test that fails when the host is
    /// offline is a test that gets switched off while it is right.
    ///
    /// The target is the Tor Project's own onion service and not an Electrum
    /// server, because no onion Electrum address is in this tree yet -- the
    /// 1209k list arrives with its fixture in step 13 of PLAN.md, and an
    /// address typed in from memory is a test that fails for the wrong
    /// reason. What this module has to prove is that the bootstrap, the
    /// descriptor fetch and the rendezvous really work and that the stream
    /// that comes back is the seam's; which Electrum server is at the far end
    /// is the session tests' business. Point it at one by editing the
    /// endpoint when the fixture lands.
    #[tokio::test]
    #[ignore = "needs the tor network, run by hand with --ignored"]
    async fn tor_really_bootstraps_and_opens_a_circuit() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let settings = TorSettings {
            bootstrap_timeout_secs: 300,
            ..enabled(None)
        };

        let state = bootstrap(&settings, dir.path()).await;
        let handle = state
            .handle()
            .unwrap_or_else(|| panic!("arti did not bootstrap: {:?}", state.failure()));
        assert!(dir.path().join("state").is_dir());
        assert!(dir.path().join("cache").is_dir());

        let dialed = dialer()
            .with_onion(handle.onion_dialer())
            .dial(&endpoint(&format!("tcp://{ONION}:80")))
            .await
            .expect("the onion service answers");

        assert_eq!(dialed.remote_ip, None, "a circuit has no address");
        assert_eq!(dialed.dns, None, "tor resolved the name, not us");
    }
}
