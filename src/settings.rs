//! The configuration file: every key, its default, and what makes it valid.
//!
//! A YAML file read with serde_yaml, following crawler. One struct per block
//! of `config-example.yaml`, nested the way the file is, so that a key's home
//! in the file and its home in the code are the same place and a reader of
//! one can navigate the other. Every struct carries `#[serde(default)]`, so
//! an absent key takes the value of [`Default`] and the example file is
//! [`Settings::default`] written out: a test loads the example and compares
//! the two, which is what keeps the documented defaults honest.
//!
//! `deny_unknown_fields` throughout. A key the daemon does not know is almost
//! always a typo or a key from a newer version, and ignoring it silently
//! means a run that does not do what its file says -- which for a collector
//! is worse than for most daemons, because the result is a database that
//! looks complete and was gathered under settings nobody chose.
//!
//! Nothing here reads the environment. The file is the configuration (and
//! `RUST_LOG` is not read either, see [`crate::logging`]), so a database can
//! be explained by the file that produced it.
//!
//! Two things are kept apart, as in crawler. The *shape* of the file is this
//! module's structs, which accept whatever the YAML parser accepts; whether
//! the values make a daemon that can work is [`Settings::validate`], which
//! answers with one error per broken rule and names the key in it. So a
//! nonsensical cadence is a message about that cadence rather than a type
//! error halfway through a parse, and the rest of the crate can be written as
//! if the settings were already known good.
//!
//! Durations are integers of seconds in the file and [`Duration`] in the
//! code: the conversion happens here, once, so that nothing downstream
//! multiplies by a thousand and nothing stores a bare number whose unit has
//! to be remembered.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use serde::Deserialize;

use crate::endpoint::Endpoint;
use crate::store::sha256_hex;

/// The chain being observed.
///
/// One daemon watches one chain, because the `blocks` book is a book of one
/// chain's blocks: a server on another chain announcing its own height 870000
/// would collide with ours. The names are the ones the config file uses,
/// which is why the renaming is spelled out rather than left to the variant
/// names -- a file written against one version has to keep loading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    /// The bitcoin crate's name for this chain.
    pub fn network(self) -> bitcoin::Network {
        match self {
            Chain::Mainnet => bitcoin::Network::Bitcoin,
            Chain::Testnet3 => bitcoin::Network::Testnet,
            Chain::Testnet4 => bitcoin::Network::Testnet4,
            Chain::Signet => bitcoin::Network::Signet,
            Chain::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// The hash of this chain's genesis block.
    ///
    /// What `server.features` is checked against on every connection. A
    /// server that answers with another chain's genesis is disabled rather
    /// than merely ignored, because its headers would otherwise go into
    /// `blocks` and the cross-server book would be a book of two chains.
    ///
    /// Computed from the bitcoin crate rather than written out here, so that
    /// the constant this crate compares against is the same one the rest of
    /// the ecosystem derives its chain from. It is a handful of hashes per
    /// connection attempt, which is nothing next to the connection.
    pub fn genesis_hash(self) -> BlockHash {
        genesis_block(self.network()).block_hash()
    }
}

/// The whole configuration file.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Which chain the servers are expected to be on.
    pub chain: Chain,

    /// The SQLite database everything is written to.
    pub database: PathBuf,

    /// An optional file of endpoints, one per line, read at startup.
    ///
    /// `None` is the ordinary case: the server list comes from the `import`
    /// subcommand and from discovery, both of which write to the database,
    /// and a file is for the endpoints an operator wants watched whatever
    /// the peer lists say.
    pub servers_file: Option<PathBuf>,

    /// How many connections are opened to each server.
    ///
    /// More than one is the noise-floor experiment: two connections to one
    /// server announcing the same block N milliseconds apart is the
    /// resolution limit of the whole method. Raising it here raises it for
    /// all of them, which is a lot of sockets; `overrides` is the way to
    /// raise it for the few endpoints an experiment is about.
    pub sessions_per_server: usize,

    /// Per-endpoint session counts, overriding `sessions_per_server`.
    pub overrides: Vec<Override>,

    pub timeouts: TimeoutSettings,
    pub reconnect: ReconnectSettings,
    pub cadence: CadenceSettings,
    pub divergence: DivergenceSettings,
    pub discovery: DiscoverySettings,
    pub dns: DnsSettings,
    pub tor: TorSettings,
    pub log: LogSettings,

    /// The sha256 of the configuration file's text, as `meta.config_sha256`
    /// keeps it.
    ///
    /// Not a key of the file: `#[serde(skip)]`, so a file that names it is
    /// the unknown-key error every other typo is, and [`Settings::load`]
    /// stamps it from the bytes it just read. It travels on the settings
    /// rather than as a second argument to [`crate::run::run`] because it is
    /// a fact about the configuration and the collector already takes the
    /// configuration. `None` is a `Settings` that came from nowhere -- a
    /// test's, or the defaults -- and then nothing is written, because a
    /// `meta` row would claim a run was configured by a file.
    #[serde(skip)]
    pub config_sha256: Option<String>,
}

/// One entry of `overrides`: an endpoint and how many sessions it gets.
///
/// The only struct here without `#[serde(default)]`, because neither field
/// has a default worth having: an override with no endpoint names nothing,
/// and one with no count says nothing. Both are required, and the endpoint is
/// parsed by [`Endpoint`] as the file is read, so a misspelled address is an
/// error about that address rather than a server that is silently never
/// found.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// The endpoint, in either spelling; `ssl://host:port` is canonical.
    pub endpoint: Endpoint,
    /// How many sessions this endpoint gets, instead of the global count.
    pub sessions: usize,
}

/// `timeouts`: what bounds a dial and what bounds a request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutSettings {
    /// From the start of the dial to a usable connection.
    pub connect_secs: u64,
    /// How long one request may go unanswered.
    ///
    /// Bounds a probe and not the connection: a server that never answers
    /// one request keeps its subscription and is recorded as having failed
    /// that probe, because a server that is slow about `estimatefee` is still
    /// telling us when it saw the last block.
    pub request_secs: u64,
}

/// `reconnect`: the exponential backoff a dropped session comes back on.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconnectSettings {
    /// The first wait after a session ends.
    pub min_secs: u64,
    /// The ceiling the doubling stops at.
    pub max_secs: u64,
}

/// `cadence`: how often each probe set goes out.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CadenceSettings {
    /// `server.ping`, which keeps the connection from being dropped as idle
    /// and whose round trip is the baseline every header delta is read
    /// against.
    pub ping_secs: u64,
    /// The fee set: histogram, estimates and their edge cases.
    pub fees_secs: u64,
    /// The identity set: features, banner, donation address, peers.
    pub identity_secs: u64,
    /// The fingerprint set, which is deliberately malformed requests and is
    /// rare because ElectrumX charges a connection for what it asks.
    pub fingerprint_secs: u64,
}

/// `divergence`: the polling that is armed when the chain splits.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DivergenceSettings {
    /// How long the window stays open after two hashes are seen at one
    /// height.
    pub window_secs: u64,
    /// How often each server is asked for the header at that height while
    /// the window is open. This is the measurement thread #167 wished it
    /// had: a subscription says when a server *announces* a tip, and only
    /// polling says when it *switches*.
    pub poll_secs: u64,
}

/// `discovery`: what is done with the peers servers advertise.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoverySettings {
    /// Whether `server.peers.subscribe` results become servers of our own.
    ///
    /// Off still records the advertisements: `peer_edges` is written either
    /// way, because who advertises whom is data in its own right.
    pub enabled: bool,
    /// The ceiling on enabled servers, first come first served.
    ///
    /// Peer lists are unbounded and partly stale, and every enabled server
    /// costs a descriptor, a connection and its share of the write rate.
    pub max_servers: usize,
}

/// `dns`: how hostnames are resolved.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsSettings {
    /// The resolver hickory sends to; `None` uses the system configuration.
    pub upstream: Option<String>,
}

/// `tor`: the in-process arti client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TorSettings {
    /// Whether onion servers are dialed at all.
    pub enabled: bool,
    /// How long the bootstrap may take before Tor is given up on.
    pub bootstrap_timeout_secs: u64,
    /// Where arti keeps its guards and its directory cache.
    ///
    /// `None` puts it next to the database, at `<database dir>/arti`: the
    /// two are the daemon's only state, they are backed up and wiped
    /// together, and a NixOS `StateDirectory` is one directory rather than
    /// two. See [`Settings::tor_state_dir`].
    pub state_dir: Option<PathBuf>,
    /// Whether clearnet connections go through Tor as well.
    ///
    /// Off by default, and the default matters more here than most: a
    /// circuit's latency and jitter land on every timing this daemon
    /// collects, and the measurement this daemon takes is tens of
    /// milliseconds wide.
    pub route_clearnet: bool,
}

/// `log`: the level everything runs at, and the exceptions.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSettings {
    /// The level every target runs at unless `targets` says otherwise.
    pub level: String,
    /// Per-target overrides, by the tracing target names of `lib.rs`.
    pub targets: BTreeMap<String, String>,
}

impl LogSettings {
    /// The `EnvFilter` directives these settings describe.
    ///
    /// The level first, then one `target=level` directive per override,
    /// which is how `EnvFilter` spells "everything at info except the
    /// sessions at trace". Ordered, because a `BTreeMap` is, so the same
    /// settings always produce the same filter and the string is worth
    /// logging.
    pub fn to_filter_string(&self) -> String {
        let mut directives = String::from(&self.level);
        for (target, level) in &self.targets {
            directives.push(',');
            directives.push_str(target);
            directives.push('=');
            directives.push_str(level);
        }
        directives
    }
}

impl TimeoutSettings {
    /// How long a dial may take.
    pub fn connect(&self) -> Duration {
        Duration::from_secs(self.connect_secs)
    }

    /// How long one request may go unanswered.
    pub fn request(&self) -> Duration {
        Duration::from_secs(self.request_secs)
    }
}

impl ReconnectSettings {
    /// The first wait after a session ends.
    pub fn min(&self) -> Duration {
        Duration::from_secs(self.min_secs)
    }

    /// The ceiling the doubling stops at.
    pub fn max(&self) -> Duration {
        Duration::from_secs(self.max_secs)
    }
}

impl CadenceSettings {
    /// Between two `server.ping`s.
    pub fn ping(&self) -> Duration {
        Duration::from_secs(self.ping_secs)
    }

    /// Between two fee sets.
    pub fn fees(&self) -> Duration {
        Duration::from_secs(self.fees_secs)
    }

    /// Between two identity sets.
    pub fn identity(&self) -> Duration {
        Duration::from_secs(self.identity_secs)
    }

    /// Between two fingerprint sets.
    pub fn fingerprint(&self) -> Duration {
        Duration::from_secs(self.fingerprint_secs)
    }
}

impl DivergenceSettings {
    /// How long a divergence window stays open.
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }

    /// Between two tip checks while it is open.
    pub fn poll(&self) -> Duration {
        Duration::from_secs(self.poll_secs)
    }
}

impl TorSettings {
    /// How long the arti bootstrap may take.
    pub fn bootstrap_timeout(&self) -> Duration {
        Duration::from_secs(self.bootstrap_timeout_secs)
    }
}

impl Settings {
    /// Reads, parses and checks the file at `path`.
    ///
    /// A file that is empty, or that is nothing but comments, is the
    /// defaults: every key has one, so there is nothing a reader of such a
    /// file could have meant other than "all of them". A file that is not
    /// there is an error, because the alternative is a daemon that writes to
    /// the default database path on a host where someone meant to point it
    /// somewhere else.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut settings =
            Self::from_yaml(&text).with_context(|| format!("parsing {}", path.display()))?;
        settings
            .validate()
            .with_context(|| format!("checking {}", path.display()))?;
        // The text as it was read rather than the settings as they were
        // parsed: `meta.config_sha256` is there to say which file produced a
        // database, and two files that differ only in a comment are two
        // files.
        settings.config_sha256 = Some(sha256_hex(text.as_bytes()));
        Ok(settings)
    }

    /// The parse alone, without the file or the checking.
    ///
    /// `Option` and not `Settings`: an empty document is YAML's null, which
    /// deserialises into no settings at all rather than into every default,
    /// and a config file that has been commented out line by line is a file
    /// someone is debugging with.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let parsed: Option<Self> = serde_yaml::from_str(text)?;
        Ok(parsed.unwrap_or_default())
    }

    /// Every rule the daemon depends on, checked before anything is opened.
    ///
    /// One error per rule, naming the key and what is wrong with its value:
    /// these are read by whoever wrote the file, and a message that does not
    /// name the key sends them searching. The rules are the ones a run cannot
    /// recover from -- a zero cadence whose timer fires forever, a backoff
    /// that counts downwards -- and not matters of taste. The endpoints
    /// themselves are not checked here: [`Endpoint`] parsed them as the file
    /// was read, so a bad address never reaches this far.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.sessions_per_server >= 1,
            "sessions_per_server is zero: no server would be connected to at all"
        );
        for (index, over) in self.overrides.iter().enumerate() {
            ensure!(
                over.sessions >= 1,
                "overrides[{index}].sessions is zero for {}: remove the entry rather than \
                 overriding it to nothing",
                over.endpoint
            );
        }

        // A zero timeout has expired before the thing it bounds has begun,
        // and a zero interval is a timer that fires as fast as the runtime
        // can poll it -- which against six hundred servers is a flood sent
        // on our behalf.
        positive("timeouts.connect_secs", self.timeouts.connect_secs)?;
        positive("timeouts.request_secs", self.timeouts.request_secs)?;
        positive("reconnect.min_secs", self.reconnect.min_secs)?;
        positive("reconnect.max_secs", self.reconnect.max_secs)?;
        ensure!(
            self.reconnect.min_secs <= self.reconnect.max_secs,
            "reconnect.min_secs ({}) is above reconnect.max_secs ({}): the backoff would \
             start past its own ceiling",
            self.reconnect.min_secs,
            self.reconnect.max_secs
        );
        positive("cadence.ping_secs", self.cadence.ping_secs)?;
        positive("cadence.fees_secs", self.cadence.fees_secs)?;
        positive("cadence.identity_secs", self.cadence.identity_secs)?;
        positive("cadence.fingerprint_secs", self.cadence.fingerprint_secs)?;
        positive("divergence.window_secs", self.divergence.window_secs)?;
        positive("divergence.poll_secs", self.divergence.poll_secs)?;
        positive(
            "tor.bootstrap_timeout_secs",
            self.tor.bootstrap_timeout_secs,
        )?;

        ensure!(
            self.discovery.max_servers >= 1,
            "discovery.max_servers is zero: not even a configured server would be enabled, \
             set discovery.enabled to false to stop taking new ones"
        );

        // Read at startup, so a path that is not there is reported now
        // rather than after the descriptors have been raised and the
        // database opened.
        if let Some(file) = &self.servers_file {
            ensure!(
                file.is_file(),
                "servers_file: {} is not a file",
                file.display()
            );
        }

        // Each level on its own first. `EnvFilter` would take `chatty` for a
        // *target* named chatty rather than a level that does not exist, and
        // a file that said `level: chatty` would then silence every line the
        // daemon writes -- which looks exactly like a daemon that is not
        // doing anything.
        level("log.level", &self.log.level)?;
        for (target, value) in &self.log.targets {
            level(&format!("log.targets.{target}"), value)?;
        }

        // And the assembled filter, which is what is installed: a target
        // name that is not one is caught here.
        let filter = self.log.to_filter_string();
        tracing_subscriber::EnvFilter::try_new(&filter)
            .with_context(|| format!("log: {filter:?} is not a set of log levels"))?;

        Ok(())
    }

    /// Where arti keeps its state, defaulted next to the database.
    ///
    /// `tor.state_dir` left unset is `<database dir>/arti`, so that the
    /// daemon has one state directory rather than two and a NixOS
    /// `StateDirectory` covers both. A database with no directory part --
    /// `observer.sqlite`, run from a checkout -- puts it in the working
    /// directory for the same reason.
    pub fn tor_state_dir(&self) -> PathBuf {
        if let Some(dir) = &self.tor.state_dir {
            return dir.clone();
        }
        self.database
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join("arti")
    }

    /// How many sessions the descriptor limit has to cover.
    ///
    /// `discovery.max_servers` times `sessions_per_server`, which is what
    /// [`crate::fdlimit::prepare`] is given. The handful of extra sessions
    /// the `overrides` ask for are not counted: they are a few connections
    /// against a cap of hundreds, and `fdlimit` keeps a reserve an order of
    /// magnitude larger than that for everything else the process opens.
    pub fn max_sessions(&self) -> usize {
        self.discovery
            .max_servers
            .saturating_mul(self.sessions_per_server)
    }
}

/// A log level that has to be one.
fn level(key: &str, value: &str) -> Result<()> {
    value
        .parse::<tracing_subscriber::filter::LevelFilter>()
        .with_context(|| format!("{key}: {value:?} is not a log level"))?;
    Ok(())
}

/// An interval or a timeout that has to be one.
fn positive(key: &str, secs: u64) -> Result<()> {
    ensure!(
        secs > 0,
        "{key} is zero: a timer that has already expired fires as fast as it can be polled"
    );
    Ok(())
}

impl Default for Settings {
    /// The values in `config-example.yaml`, which a test compares against:
    /// the example is the documentation of these defaults, and a default
    /// that differs from it is a lie in the file people read.
    fn default() -> Self {
        Self {
            chain: Chain::Mainnet,
            database: PathBuf::from("/var/lib/electrum-observer/observer.sqlite"),
            servers_file: None,
            sessions_per_server: 1,
            overrides: Vec::new(),
            timeouts: TimeoutSettings::default(),
            reconnect: ReconnectSettings::default(),
            cadence: CadenceSettings::default(),
            divergence: DivergenceSettings::default(),
            discovery: DiscoverySettings::default(),
            dns: DnsSettings::default(),
            tor: TorSettings::default(),
            log: LogSettings::default(),
            config_sha256: None,
        }
    }
}

impl Default for TimeoutSettings {
    fn default() -> Self {
        Self {
            connect_secs: 20,
            request_secs: 30,
        }
    }
}

impl Default for ReconnectSettings {
    /// Ten seconds to an hour.
    fn default() -> Self {
        Self {
            min_secs: 10,
            max_secs: 3600,
        }
    }
}

impl Default for CadenceSettings {
    /// Two minutes, five minutes, an hour, a day.
    fn default() -> Self {
        Self {
            ping_secs: 120,
            fees_secs: 300,
            identity_secs: 3600,
            fingerprint_secs: 86400,
        }
    }
}

impl Default for DivergenceSettings {
    /// Half an hour of window, ten seconds of polling.
    fn default() -> Self {
        Self {
            window_secs: 1800,
            poll_secs: 10,
        }
    }
}

impl Default for DiscoverySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_servers: 600,
        }
    }
}

impl Default for TorSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            bootstrap_timeout_secs: 300,
            state_dir: None,
            route_clearnet: false,
        }
    }
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            targets: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example file that ships with the daemon.
    fn example() -> Settings {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/config-example.yaml"));
        Settings::load(path).expect("the example file in the repository root loads")
    }

    /// The message a broken rule produces, for a test to look inside.
    fn rejected(settings: &Settings) -> String {
        format!(
            "{:#}",
            settings
                .validate()
                .expect_err("the rule should refuse this")
        )
    }

    /// `config-example.yaml` is the documentation of the defaults, so it has
    /// to parse and it has to say what [`Settings::default`] says.
    ///
    /// Compared whole rather than key by key: a key added to one and not the
    /// other is exactly the mistake this catches.
    #[test]
    fn the_example_file_is_exactly_the_defaults() {
        let loaded = example();
        assert_eq!(
            loaded.config_sha256,
            Some(sha256_hex(
                std::fs::read_to_string(Path::new(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/config-example.yaml"
                )))
                .expect("the example file reads")
                .as_bytes()
            )),
            "loading stamps the hash of the text it read",
        );
        // Everything else whole, with the one field the file cannot name
        // taken back off: a key added to the example and not to `Default`,
        // or the other way round, is exactly what this catches.
        assert_eq!(
            Settings {
                config_sha256: None,
                ..loaded
            },
            Settings::default(),
        );
    }

    /// And the defaults are a configuration the daemon would run with, which
    /// is not a given: every rule below is a rule the defaults satisfy.
    #[test]
    fn the_defaults_pass_validation() {
        Settings::default()
            .validate()
            .expect("the defaults are a working configuration");
    }

    /// A file that names nothing is every default, and a file that names one
    /// key is that key and every other default.
    #[test]
    fn an_absent_key_takes_its_default() {
        for empty in ["", "   \n", "# nothing but a comment\n", "---\n"] {
            assert_eq!(
                Settings::from_yaml(empty).expect("an empty file is a valid file"),
                Settings::default(),
                "{empty:?}"
            );
        }

        let settings = Settings::from_yaml("chain: testnet4\ncadence:\n  ping_secs: 30\n")
            .expect("a partial file is a valid file");
        assert_eq!(settings.chain, Chain::Testnet4);
        assert_eq!(settings.cadence.ping_secs, 30);
        assert_eq!(
            settings.cadence.fees_secs,
            CadenceSettings::default().fees_secs,
            "a sibling key of one that was named still defaults"
        );
        assert_eq!(settings.timeouts, TimeoutSettings::default());
        settings.validate().expect("a partial file is still valid");
    }

    /// A key the daemon does not know is an error that names the key.
    ///
    /// Almost always a typo, and a typo that is ignored is a daemon running
    /// on a setting nobody chose while its file says otherwise.
    #[test]
    fn an_unknown_key_is_refused_by_name() {
        for (yaml, key) in [
            ("sessions_per_sever: 2\n", "sessions_per_sever"),
            ("cadence:\n  ping_sec: 30\n", "ping_sec"),
            ("tor:\n  enable: false\n", "enable"),
            (
                "overrides:\n  - endpoint: ssl://a.example:50002\n    session: 3\n",
                "session",
            ),
        ] {
            let error = format!(
                "{:#}",
                Settings::from_yaml(yaml).expect_err("an unknown key is an error")
            );
            assert!(error.contains(key), "{yaml:?}: {error}");
        }
    }

    /// The chain names are the ones the file uses, and each chain is its own
    /// chain as far as the genesis check is concerned.
    #[test]
    fn every_chain_has_its_own_genesis() {
        let chains = [
            ("mainnet", Chain::Mainnet),
            ("testnet3", Chain::Testnet3),
            ("testnet4", Chain::Testnet4),
            ("signet", Chain::Signet),
            ("regtest", Chain::Regtest),
        ];

        let mut hashes = Vec::new();
        for (name, chain) in chains {
            let settings =
                Settings::from_yaml(&format!("chain: {name}\n")).expect("a chain name parses");
            assert_eq!(settings.chain, chain, "{name}");
            hashes.push(chain.genesis_hash());
        }
        hashes.sort_unstable();
        let before = hashes.len();
        hashes.dedup();
        assert_eq!(hashes.len(), before, "two chains share a genesis hash");

        // The one value worth writing out: mainnet's genesis, which is what
        // every `server.features` on a mainnet run is compared against.
        assert_eq!(
            Chain::Mainnet.genesis_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );

        let error = format!(
            "{:#}",
            Settings::from_yaml("chain: testnet9\n").expect_err("not a chain")
        );
        assert!(error.contains("testnet9"), "{error}");
    }

    /// The seconds in the file are durations in the code, and every one of
    /// them is converted.
    ///
    /// One test over all of them because the mistake they guard against is a
    /// copied accessor that returns the neighbouring key.
    #[test]
    fn the_seconds_in_the_file_are_durations_in_the_code() {
        let settings = Settings::default();
        for (name, got, want) in [
            ("timeouts.connect", settings.timeouts.connect(), 20),
            ("timeouts.request", settings.timeouts.request(), 30),
            ("reconnect.min", settings.reconnect.min(), 10),
            ("reconnect.max", settings.reconnect.max(), 3600),
            ("cadence.ping", settings.cadence.ping(), 120),
            ("cadence.fees", settings.cadence.fees(), 300),
            ("cadence.identity", settings.cadence.identity(), 3600),
            ("cadence.fingerprint", settings.cadence.fingerprint(), 86400),
            ("divergence.window", settings.divergence.window(), 1800),
            ("divergence.poll", settings.divergence.poll(), 10),
            ("tor.bootstrap", settings.tor.bootstrap_timeout(), 300),
        ] {
            assert_eq!(got, Duration::from_secs(want), "{name}");
        }
    }

    /// The descriptor limit is asked for the whole cap, because every
    /// session holds its connection open for the life of the process.
    #[test]
    fn the_session_cap_is_the_server_cap_times_the_sessions() {
        assert_eq!(Settings::default().max_sessions(), 600);

        let settings =
            Settings::from_yaml("sessions_per_server: 3\ndiscovery:\n  max_servers: 7\n")
                .expect("a file parses");
        assert_eq!(settings.max_sessions(), 21);

        // A cap that would overflow is a cap, not a panic: it is refused by
        // the descriptor limit rather than by the multiplication.
        let settings =
            Settings::from_yaml(&format!("sessions_per_server: {}\n", usize::MAX)).expect("parses");
        assert_eq!(settings.max_sessions(), usize::MAX);
    }

    /// arti's state sits next to the database unless the file says where.
    ///
    /// The default is `<database dir>/arti`, so that the daemon has one state
    /// directory and a NixOS `StateDirectory` covers both.
    #[test]
    fn the_tor_state_directory_defaults_next_to_the_database() {
        assert_eq!(
            Settings::default().tor_state_dir(),
            PathBuf::from("/var/lib/electrum-observer/arti")
        );

        let named = Settings::from_yaml("tor:\n  state_dir: /srv/arti\n").expect("a file parses");
        assert_eq!(named.tor_state_dir(), PathBuf::from("/srv/arti"));

        // A database with no directory part is a checkout being run from,
        // and the state belongs beside it there too.
        let bare = Settings::from_yaml("database: observer.sqlite\n").expect("a file parses");
        assert_eq!(bare.tor_state_dir(), PathBuf::from("./arti"));
    }

    /// Every rule of [`Settings::validate`], each naming its key.
    #[test]
    fn a_broken_rule_names_its_key() {
        let mut settings = Settings {
            sessions_per_server: 0,
            ..Settings::default()
        };
        assert!(
            rejected(&settings).contains("sessions_per_server"),
            "{}",
            rejected(&settings)
        );
        settings.sessions_per_server = 1;
        settings.validate().expect("one session is a session");

        for (key, break_it) in [
            (
                "timeouts.connect_secs",
                (|s: &mut Settings| s.timeouts.connect_secs = 0) as fn(&mut Settings),
            ),
            ("timeouts.request_secs", |s| s.timeouts.request_secs = 0),
            ("reconnect.min_secs", |s| s.reconnect.min_secs = 0),
            ("reconnect.max_secs", |s| s.reconnect.max_secs = 0),
            ("cadence.ping_secs", |s| s.cadence.ping_secs = 0),
            ("cadence.fees_secs", |s| s.cadence.fees_secs = 0),
            ("cadence.identity_secs", |s| s.cadence.identity_secs = 0),
            ("cadence.fingerprint_secs", |s| {
                s.cadence.fingerprint_secs = 0
            }),
            ("divergence.window_secs", |s| s.divergence.window_secs = 0),
            ("divergence.poll_secs", |s| s.divergence.poll_secs = 0),
            ("tor.bootstrap_timeout_secs", |s| {
                s.tor.bootstrap_timeout_secs = 0
            }),
            ("discovery.max_servers", |s| s.discovery.max_servers = 0),
        ] {
            let mut settings = Settings::default();
            break_it(&mut settings);
            let message = rejected(&settings);
            assert!(message.contains(key), "{key}: {message}");
        }
    }

    /// The backoff counts upwards, and a range of one value is a range.
    #[test]
    fn the_backoff_cannot_start_past_its_ceiling() {
        let mut settings = Settings::default();
        settings.reconnect.min_secs = 3600;
        settings.reconnect.max_secs = 10;
        let message = rejected(&settings);
        assert!(message.contains("reconnect.min_secs"), "{message}");
        assert!(message.contains("reconnect.max_secs"), "{message}");

        // Equal is a valid configuration: it is a fixed delay, which is what
        // someone reconnecting to a server they control would want.
        settings.reconnect.min_secs = 10;
        settings.reconnect.max_secs = 10;
        settings
            .validate()
            .expect("a fixed delay is a valid backoff");
    }

    /// An override is an endpoint and a count, and both have to mean
    /// something.
    #[test]
    fn an_override_names_an_endpoint_and_a_count() {
        let settings = Settings::from_yaml(
            "overrides:\n  - endpoint: tool.sh:50002:s\n    sessions: 3\n  - endpoint: \
             ssl://fulcrum.grey.pw:50002\n    sessions: 1\n",
        )
        .expect("a file parses");
        assert_eq!(
            settings.overrides,
            vec![
                Override {
                    // Electrum's spelling on the way in, canonical in the
                    // value: the override and the `servers` row are the same
                    // key.
                    endpoint: "ssl://tool.sh:50002".parse().expect("an endpoint"),
                    sessions: 3,
                },
                Override {
                    endpoint: "ssl://fulcrum.grey.pw:50002".parse().expect("an endpoint"),
                    sessions: 1,
                },
            ]
        );
        settings.validate().expect("both overrides are sensible");

        let zero = Settings::from_yaml(
            "overrides:\n  - endpoint: ssl://a.example:50002\n    sessions: 1\n  - endpoint: \
             ssl://b.example:50002\n    sessions: 0\n",
        )
        .expect("a file parses");
        let message = rejected(&zero);
        assert!(message.contains("overrides[1].sessions"), "{message}");
        assert!(message.contains("ssl://b.example:50002"), "{message}");

        // An endpoint that is not an endpoint is caught by the type as the
        // file is read, with the text that was refused in the message.
        let error = format!(
            "{:#}",
            Settings::from_yaml("overrides:\n  - endpoint: ssl://a.example:0\n    sessions: 1\n")
                .expect_err("a zero port")
        );
        assert!(error.contains("the port is zero"), "{error}");

        // And both fields are required, because neither has a meaning when
        // it is absent.
        for yaml in [
            "overrides:\n  - sessions: 3\n",
            "overrides:\n  - endpoint: ssl://a.example:50002\n",
        ] {
            Settings::from_yaml(yaml).expect_err("an override needs both of its keys");
        }
    }

    /// `servers_file` is read at startup, so it has to be there at startup.
    #[test]
    fn a_servers_file_that_is_named_has_to_exist() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("servers.txt");
        std::fs::write(&file, "ssl://electrum.example:50002\n").expect("writing the file");

        let mut settings = Settings {
            servers_file: Some(file),
            ..Settings::default()
        };
        settings.validate().expect("the file is there");

        settings.servers_file = Some(dir.path().join("absent.txt"));
        let message = rejected(&settings);
        assert!(message.contains("servers_file"), "{message}");
        assert!(message.contains("absent.txt"), "{message}");

        // A directory is not a server list either.
        settings.servers_file = Some(dir.path().to_path_buf());
        assert!(rejected(&settings).contains("is not a file"));
    }

    /// The log filter is the level and the overrides, in order.
    #[test]
    fn the_filter_string_is_the_level_and_the_overrides() {
        let mut log = LogSettings::default();
        assert_eq!(log.to_filter_string(), "info");

        log.targets.insert("session".to_string(), "trace".into());
        log.targets.insert("main".to_string(), "debug".into());
        // Sorted, because the map is: the same settings always produce the
        // same filter.
        assert_eq!(log.to_filter_string(), "info,main=debug,session=trace");
    }

    /// A level that is not a level is an error rather than a target that
    /// quietly stays at the default.
    #[test]
    fn a_level_that_is_not_a_level_is_refused() {
        // `EnvFilter` would read a bare `chatty` as a target named chatty,
        // leaving a daemon that writes nothing at all, so the level is
        // checked on its own before the filter is assembled.
        let mut settings = Settings::default();
        settings.log.level = "chatty".to_string();
        let message = rejected(&settings);
        assert!(message.contains("log.level"), "{message}");
        assert!(message.contains("chatty"), "{message}");

        let mut settings = Settings::default();
        settings
            .log
            .targets
            .insert("session".to_string(), "loud".to_string());
        let message = rejected(&settings);
        assert!(message.contains("log.targets.session"), "{message}");
        assert!(message.contains("loud"), "{message}");

        // And the assembled filter, for a target name that cannot be one:
        // `main=debug` as a key is the shape of the whole directive written
        // into half of it, which is a plausible way to fill `targets` in.
        let mut settings = Settings::default();
        settings
            .log
            .targets
            .insert("main=debug".to_string(), "debug".to_string());
        let message = rejected(&settings);
        assert!(message.contains("info,main=debug=debug"), "{message}");
    }

    /// Loading is reading, parsing and checking: a file that parses but
    /// cannot be run with is an error from `load`, and so is one that is not
    /// there.
    #[test]
    fn loading_checks_the_file_it_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");

        let good = dir.path().join("good.yaml");
        std::fs::write(&good, "chain: signet\ncadence:\n  ping_secs: 60\n").expect("writing");
        let settings = Settings::load(&good).expect("a valid file loads");
        assert_eq!(settings.chain, Chain::Signet);
        assert_eq!(settings.cadence.ping(), Duration::from_secs(60));

        let bad = dir.path().join("bad.yaml");
        std::fs::write(&bad, "cadence:\n  ping_secs: 0\n").expect("writing");
        let error = format!("{:#}", Settings::load(&bad).expect_err("a zero cadence"));
        assert!(error.contains("cadence.ping_secs"), "{error}");
        assert!(error.contains("bad.yaml"), "{error}");

        let unparseable = dir.path().join("unparseable.yaml");
        std::fs::write(&unparseable, "chain: [mainnet]\n").expect("writing");
        let error = format!(
            "{:#}",
            Settings::load(&unparseable).expect_err("not a chain")
        );
        assert!(error.contains("unparseable.yaml"), "{error}");

        let error = format!(
            "{:#}",
            Settings::load(&dir.path().join("absent.yaml")).expect_err("there is no such file")
        );
        assert!(error.contains("absent.yaml"), "{error}");
    }
}
