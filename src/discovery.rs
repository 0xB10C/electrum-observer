//! What the servers say about each other, and which of it is monitored.
//!
//! `server.peers.subscribe` is how an Electrum server names the servers it
//! knows, and it is two things at once for this crate. It is a graph --
//! who advertises whom, recorded in `peer_edges` whatever else happens to it
//! -- and it is the way the list of monitored servers grows without anybody
//! maintaining one: a peer that is new becomes a `servers` row with
//! `source = 'peers:<id>'` and, if there is room under the cap, a session of
//! its own (DESIGN.md section 7).
//!
//! The reply is an array of three-element rows, `[ip, host, [features]]`,
//! as the protocol documentation's example has it:
//!
//! ```text
//! ["107.150.45.210", "e.anonyhost.org", ["v1.0", "p10000", "t", "s995"]]
//! ```
//!
//! The feature strings are letter-prefixed: `v` is the highest protocol
//! version the server speaks, `p` its pruning limit, and `s` and `t` are the
//! TLS and plain ports. A letter with no digits after it means the default
//! port for that transport, which the protocol documentation leaves to the
//! network and ElectrumX takes from its coin class; here that is
//! [`DEFAULT_SSL_PORT`] and [`DEFAULT_TCP_PORT`], Bitcoin mainnet's 50002
//! and 50001. A server on another chain advertising a bare `s` is then read
//! as mainnet's port and will not connect -- which is a wrong address in the
//! database rather than a wrong number in a measurement, and it is already
//! disabled by the genesis check of DESIGN.md section 5 step 3.
//!
//! Two decisions from DESIGN.md section 7 are worth repeating because they
//! look like oversights otherwise:
//!
//! - **Both ports of one host are kept.** The TCP and the SSL port of one
//!   hostname are certainly one backend, so whatever first-seen delta they
//!   show is the floor every other pair has to beat. They are the positive
//!   control, not a duplicate.
//! - **Nothing here is trusted.** A peer list is a stranger's list of
//!   strangers: rows are malformed, hosts are dead, ports are stale, and a
//!   row can be junk of any shape at all. Every row that cannot be read is
//!   counted and dropped, never a panic and never an error that ends a
//!   session, because the session that handed this over is in the middle of
//!   a measurement that matters more than the peer list does.
//!
//! The cap itself is not enforced here. [`Store::upsert_server`] counts the
//! enabled servers and inserts in one transaction, so two sessions ingesting
//! the same new peer at the same moment cannot both see the last slot; this
//! module only passes `discovery.max_servers` down and reads back what the
//! store decided.

use std::net::IpAddr;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::TARGET_DISCOVERY;
use crate::endpoint::{Endpoint, Transport};
use crate::settings::DiscoverySettings;
use crate::store::{Micros, ServerRow, Store};

/// The port a bare `t` feature means: Electrum's plain port on mainnet.
pub const DEFAULT_TCP_PORT: u16 = 50001;

/// The port a bare `s` feature means: Electrum's TLS port on mainnet.
pub const DEFAULT_SSL_PORT: u16 = 50002;

/// One row of a `server.peers.subscribe` reply, as it was advertised.
///
/// Kept close to the wire -- the features are the strings the server sent,
/// not a parsed set -- because this is also what `peer_edges` stores
/// (DESIGN.md section 4): what one server said about another is the datum,
/// and a normalised version of it would answer a different question later.
/// The `ip` is `None` when the field was absent, empty or not an address,
/// which is the ordinary case for an onion peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedPeer {
    /// The address the advertising server has for this peer, when it gave a
    /// usable one.
    pub ip: Option<IpAddr>,
    /// The hostname as advertised, lowercased by [`Endpoint`] later rather
    /// than here, so `peer_edges` keeps the spelling that was sent.
    pub host: String,
    /// The feature strings, verbatim, in the order they arrived.
    pub features: Vec<String>,
}

impl AdvertisedPeer {
    /// Reads a whole `server.peers.subscribe` result, skipping what it
    /// cannot read.
    ///
    /// Returns the rows it understood and says nothing about the ones it
    /// did not beyond a count at debug level: a server that answers this
    /// method with nonsense is interesting, but it is interesting as a
    /// server, and the place to notice it is the probe row that recorded
    /// the answer verbatim, not a parser that refuses the other four
    /// hundred peers because of it.
    pub fn parse_list(value: &Value) -> Vec<Self> {
        let Some(rows) = value.as_array() else {
            debug!(
                target: TARGET_DISCOVERY,
                "peer list is not an array, nothing to ingest",
            );
            return Vec::new();
        };
        let mut peers = Vec::with_capacity(rows.len());
        for row in rows {
            match Self::parse_row(row) {
                Some(peer) => peers.push(peer),
                None => debug!(target: TARGET_DISCOVERY, row = %row, "peer row skipped"),
            }
        }
        // Both counts rather than the difference, so that nothing here
        // keeps a number of its own: what was skipped is `advertised -
        // kept`, and every skipped row has already said so by itself.
        debug!(
            target: TARGET_DISCOVERY,
            advertised = rows.len(),
            kept = peers.len(),
            "peer list parsed",
        );
        peers
    }

    /// One row, or `None` when it is not one.
    ///
    /// The shape has to be an array whose second element is a string and
    /// whose third is an array; everything else about it is tolerated.
    /// Longer rows are read as if they were three elements long, because a
    /// fourth field would be an extension of the protocol and dropping the
    /// three that are documented would be the wrong half to keep.
    fn parse_row(row: &Value) -> Option<Self> {
        let [ip, host, features, ..] = row.as_array()?.as_slice() else {
            return None;
        };
        let host = host.as_str()?.trim().to_string();
        // Non-string entries are dropped rather than failing the row: they
        // carry no port, so what they cost is nothing, and a server that
        // sends one still has peers worth knowing about.
        let features = features
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let ip = ip
            .as_str()
            .and_then(|text| text.trim().parse::<IpAddr>().ok());
        Some(Self { ip, host, features })
    }

    /// The endpoints this row advertises, one per `s` or `t` feature.
    ///
    /// Both transports of one host are returned when both are offered; see
    /// the module documentation for why that is the point rather than a
    /// duplicate. The address each endpoint is built from is the hostname
    /// when there is a usable one -- an IP literal there becomes an IP host
    /// -- and the `ip` field when the hostname is empty or is not an address
    /// at all, which is how a row whose host column is junk still yields the
    /// machine it was about.
    ///
    /// Onion hosts are returned only when Tor is enabled (DESIGN.md section
    /// 9), and never fall back to the `ip` field: whatever address a server
    /// prints beside an onion name, it is not a second way to reach that
    /// service. A v2 onion address is refused by [`Endpoint`] itself,
    /// because the Tor network stopped routing to v2 in 2021.
    pub fn endpoints(&self, tor_enabled: bool) -> Vec<Endpoint> {
        let hosts = self.hosts(tor_enabled);
        let mut endpoints: Vec<Endpoint> = Vec::new();
        for feature in &self.features {
            let Some((transport, port)) = port_feature(feature) else {
                continue;
            };
            let letter = match transport {
                Transport::Ssl => 's',
                Transport::Tcp => 't',
            };
            // Electrum's own spelling rather than the canonical one, so that
            // a bare IPv6 host needs no brackets added here: `Endpoint`
            // takes the letter and the port off the right-hand end first.
            let parsed = hosts.iter().find_map(|host| {
                match format!("{host}:{port}:{letter}").parse::<Endpoint>() {
                    Ok(endpoint) => Some(endpoint),
                    Err(error) => {
                        debug!(target: TARGET_DISCOVERY, %error, "advertised address skipped");
                        None
                    }
                }
            });
            // A host that advertises `t` and `t50001` has advertised one
            // server twice; the store would collapse them anyway, and the
            // counts an ingest reports should not say two.
            if let Some(endpoint) = parsed
                && !endpoints.contains(&endpoint)
            {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    /// The addresses to try for this peer, best first.
    ///
    /// At most two, and usually one: the hostname, then the `ip` field as
    /// the fallback. An onion name is on its own, or -- with Tor off -- the
    /// row has no address at all and is dropped here rather than after the
    /// endpoint is built, so that a dial that could never work is never a
    /// `servers` row.
    fn hosts(&self, tor_enabled: bool) -> Vec<String> {
        let host = self.host.to_ascii_lowercase();
        if host.ends_with(".onion") {
            if !tor_enabled {
                debug!(target: TARGET_DISCOVERY, host, "onion peer skipped, tor is off");
                return Vec::new();
            }
            return vec![host];
        }
        let mut hosts = Vec::new();
        if !host.is_empty() {
            hosts.push(host);
        }
        if let Some(ip) = self.ip {
            hosts.push(ip.to_string());
        }
        hosts
    }
}

/// A port feature -- `s`, `t`, `s50002`, `t50001` -- as a transport and a
/// port, or `None` for every other feature.
///
/// `v1.4` and `p10000` are the other two the protocol documents, and an
/// unknown letter is simply not a port: a future feature should be ignored
/// here and recorded verbatim in `peer_edges`, not guessed at.
fn port_feature(feature: &str) -> Option<(Transport, u16)> {
    let letter = feature.chars().next()?;
    let transport = match letter.to_ascii_lowercase() {
        's' => Transport::Ssl,
        't' => Transport::Tcp,
        _ => return None,
    };
    let digits = &feature[letter.len_utf8()..];
    if digits.is_empty() {
        return Some((transport, default_port(transport)));
    }
    // Not a number, or past 65535: the row said something about a port that
    // is not one, and there is no sensible repair.
    Some((transport, digits.parse::<u16>().ok()?))
}

/// The port a bare transport letter means.
fn default_port(transport: Transport) -> u16 {
    match transport {
        Transport::Ssl => DEFAULT_SSL_PORT,
        Transport::Tcp => DEFAULT_TCP_PORT,
    }
}

/// What one ingest did, for the run loop and for the log line.
///
/// `newly_enabled` carries the rows rather than their ids because the
/// supervisor needs the endpoint to open a session and the id to label
/// everything it writes, and both are already in hand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ingested {
    /// Servers inserted with `enabled = 1`: the ones a session is owed.
    pub newly_enabled: Vec<ServerRow>,
    /// Servers inserted past `discovery.max_servers`, with
    /// `disabled_reason = 'cap'`.
    pub newly_capped: usize,
    /// Endpoints that were already in `servers`, whatever their state.
    pub already_known: usize,
    /// Endpoints that were not written: discovery is off, or the insert
    /// failed.
    pub skipped: usize,
}

/// The owner of the peer-to-`servers` step.
///
/// Cheap to clone through its [`Store`], one per session or one for the
/// supervisor, as the run loop prefers: it holds no state of its own, which
/// is deliberate. The question "is there room under the cap" is answered by
/// the database inside one transaction, and a counter cached out here would
/// be a second answer that disagrees with it after a restart.
#[derive(Clone, Debug)]
pub struct Discovery {
    store: Store,
    enabled: bool,
    max_servers: usize,
    tor_enabled: bool,
}

impl Discovery {
    /// Takes the two settings that decide what discovery may keep:
    /// `discovery` (DESIGN.md section 8) and whether Tor is available for
    /// the onion peers.
    pub fn new(store: Store, discovery: &DiscoverySettings, tor_enabled: bool) -> Self {
        Self {
            store,
            enabled: discovery.enabled,
            max_servers: discovery.max_servers,
            tor_enabled,
        }
    }

    /// Turns the peers one server advertised into `servers` rows.
    ///
    /// `from_server_id` is the server that advertised them, which becomes
    /// `source = 'peers:<id>'` on every row inserted: the first server to
    /// name a peer keeps the credit for it, because `upsert_server` leaves
    /// an existing row alone.
    ///
    /// Returns counts rather than a `Result`, and never fails: a database
    /// error here is logged and counted as skipped, since the caller is a
    /// session whose subscription is worth more than this peer list. The
    /// `peer_edges` rows are written by the probe that collected the reply
    /// whether or not this wrote anything at all -- with
    /// `discovery.enabled` off, that is the whole point of still asking.
    pub fn ingest(&self, from_server_id: i64, peers: &[AdvertisedPeer]) -> Ingested {
        self.ingest_since(from_server_id, peers, Micros::now())
    }

    /// [`Discovery::ingest`], with the instant it began handed in.
    ///
    /// `upsert_server` returns the row whether it inserted it or found it,
    /// and the only column that tells the two apart is `added_at`, which it
    /// stamps inside the same call. A row older than `started` was there
    /// before this ingest began -- including one another session inserted a
    /// moment ago, which is the answer wanted: that session is already
    /// opening the connection to it. A row stamped at exactly `started`
    /// counts as this ingest's, because the stamp is taken after the lookup
    /// that would have found an older row.
    ///
    /// Separate from [`Discovery::ingest`] only so that a test can name
    /// that boundary; nothing else should read the clock for it.
    fn ingest_since(
        &self,
        from_server_id: i64,
        peers: &[AdvertisedPeer],
        started: Micros,
    ) -> Ingested {
        let source = format!("peers:{from_server_id}");
        let mut ingested = Ingested::default();
        for peer in peers {
            for endpoint in peer.endpoints(self.tor_enabled) {
                if !self.enabled {
                    ingested.skipped += 1;
                    continue;
                }
                match self
                    .store
                    .upsert_server(&endpoint, &source, Some(self.max_servers))
                {
                    Ok(row) if row.added_at < started => ingested.already_known += 1,
                    Ok(row) if row.enabled => ingested.newly_enabled.push(row),
                    Ok(_) => ingested.newly_capped += 1,
                    Err(error) => {
                        ingested.skipped += 1;
                        warn!(
                            target: TARGET_DISCOVERY,
                            %endpoint,
                            error = %error,
                            "advertised server not stored",
                        );
                    }
                }
            }
        }
        debug!(
            target: TARGET_DISCOVERY,
            from_server_id,
            peers = peers.len(),
            enabled = ingested.newly_enabled.len(),
            capped = ingested.newly_capped,
            known = ingested.already_known,
            skipped = ingested.skipped,
            "peers ingested",
        );
        if !ingested.newly_enabled.is_empty() {
            info!(
                target: TARGET_DISCOVERY,
                from_server_id,
                count = ingested.newly_enabled.len(),
                "new servers discovered",
            );
        }
        ingested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    use crate::store::REASON_CAP;

    /// A v3 onion address: 56 base32 characters.
    const V3: &str = "sdmzuu6ktcrw4b5kcveqgpvmqv2ppkqpxdvtmyjwlsv7nw7weqgqjrqd";

    /// A v2 address, which the Tor network stopped routing to in 2021.
    const V2: &str = "hsmithsxurybd7uh";

    /// The rows as they arrive: one JSON value, parsed the way a probe
    /// result would be.
    fn parse(rows: Value) -> Vec<AdvertisedPeer> {
        AdvertisedPeer::parse_list(&rows)
    }

    /// One row, which has to be understood for the test to be about
    /// anything else.
    fn peer(row: Value) -> AdvertisedPeer {
        let mut peers = parse(json!([row]));
        assert_eq!(peers.len(), 1, "the row was skipped");
        peers.remove(0)
    }

    fn printed(endpoints: &[Endpoint]) -> Vec<String> {
        endpoints.iter().map(ToString::to_string).collect()
    }

    /// A store on a real file, as `store`'s own tests use: the cap is a
    /// transaction and a transaction wants a database.
    fn temp_store() -> (TempDir, Store) {
        let dir = TempDir::new().expect("a temporary directory");
        let store = Store::open(dir.path().join("observer.sqlite")).expect("the database opens");
        (dir, store)
    }

    fn discovery(store: Store, enabled: bool, max_servers: usize, tor_enabled: bool) -> Discovery {
        Discovery::new(
            store,
            &DiscoverySettings {
                enabled,
                max_servers,
            },
            tor_enabled,
        )
    }

    /// The example in the protocol documentation, verbatim.
    #[test]
    fn the_documented_example_row_parses() {
        let peer = peer(json!([
            "107.150.45.210",
            "e.anonyhost.org",
            ["v1.0", "p10000", "t", "s995"]
        ]));
        assert_eq!(peer.ip, Some("107.150.45.210".parse::<IpAddr>().unwrap()));
        assert_eq!(peer.host, "e.anonyhost.org");
        assert_eq!(peer.features, ["v1.0", "p10000", "t", "s995"]);
        // The bare `t` is the default plain port; the `s995` is the one the
        // row named.
        assert_eq!(
            printed(&peer.endpoints(false)),
            ["tcp://e.anonyhost.org:50001", "ssl://e.anonyhost.org:995"]
        );
    }

    /// A list as a real server sends one: several rows, several shapes.
    #[test]
    fn a_realistic_list_yields_every_advertised_port() {
        let peers = parse(json!([
            [
                "18.195.224.155",
                "tool.sh",
                ["v1.4", "p10000", "s50002", "t50001"]
            ],
            ["95.217.73.31", "bitcoin.grey.pw", ["v1.4", "s50002"]],
            ["0.0.0.0", format!("{V3}.onion"), ["v1.4", "t50001"]],
            ["2001:db8::1", "2001:db8::1", ["v1.4", "s50002"]]
        ]));
        assert_eq!(peers.len(), 4);
        let endpoints: Vec<String> = peers
            .iter()
            .flat_map(|peer| printed(&peer.endpoints(false)))
            .collect();
        assert_eq!(
            endpoints,
            [
                // Both transports of one host: the positive control of
                // DESIGN.md section 7, kept on purpose.
                "ssl://tool.sh:50002",
                "tcp://tool.sh:50001",
                "ssl://bitcoin.grey.pw:50002",
                // The onion row is gone, Tor being off.
                "ssl://[2001:db8::1]:50002",
            ]
        );
    }

    /// Every way a feature can name a port, and what it comes out as.
    #[test]
    fn port_features_resolve_or_are_ignored() {
        let cases: &[(&str, Option<(Transport, u16)>)] = &[
            ("s", Some((Transport::Ssl, DEFAULT_SSL_PORT))),
            ("t", Some((Transport::Tcp, DEFAULT_TCP_PORT))),
            ("s50002", Some((Transport::Ssl, 50002))),
            ("t50001", Some((Transport::Tcp, 50001))),
            ("S50002", Some((Transport::Ssl, 50002))),
            // Not ports at all: the two other documented features, an
            // unknown letter, and an empty string.
            ("v1.4", None),
            ("p10000", None),
            ("x50002", None),
            ("", None),
            // A port that is not a number, or not one a server listens on.
            ("snonsense", None),
            ("t 50001", None),
            ("s99999", None),
            // A multi-byte first character, which must not panic.
            ("\u{1f600}50002", None),
        ];
        for (feature, expected) in cases {
            assert_eq!(port_feature(feature), *expected, "feature {feature:?}");
        }
    }

    /// Bare letters are the default ports, and a host advertising both the
    /// bare letter and the same port explicitly is one server.
    #[test]
    fn bare_letters_default_and_duplicates_collapse() {
        let peer = peer(json!([
            "1.2.3.4",
            "dual.example",
            ["s", "t", "t50001", "s443"]
        ]));
        assert_eq!(
            printed(&peer.endpoints(false)),
            [
                "ssl://dual.example:50002",
                "tcp://dual.example:50001",
                "ssl://dual.example:443",
            ]
        );
    }

    /// The host column decides, and the `ip` column is the fallback.
    #[test]
    fn an_unusable_host_falls_back_to_the_ip() {
        let empty = peer(json!(["18.195.224.155", "", ["t50001"]]));
        assert_eq!(
            printed(&empty.endpoints(false)),
            ["tcp://18.195.224.155:50001"]
        );

        let junk = peer(json!(["18.195.224.155", "not a hostname!", ["s50002"]]));
        assert_eq!(
            printed(&junk.endpoints(false)),
            ["ssl://18.195.224.155:50002"]
        );

        // Nothing usable in either column.
        let nothing = peer(json!(["", "not a hostname!", ["s50002"]]));
        assert!(nothing.endpoints(false).is_empty());
        assert_eq!(nothing.ip, None);

        // An IP literal in the host column is an IP host, not a name.
        let literal = peer(json!(["", "18.195.224.155", ["s50002"]]));
        assert_eq!(
            printed(&literal.endpoints(false)),
            ["ssl://18.195.224.155:50002"]
        );
    }

    /// Onion peers exist only when Tor does, and only as v3.
    #[test]
    fn onion_peers_need_tor_and_a_v3_address() {
        let v3 = peer(json!([
            "1.2.3.4",
            format!("{V3}.onion"),
            ["s50002", "t50001"]
        ]));
        assert_eq!(
            printed(&v3.endpoints(true)),
            [
                format!("ssl://{V3}.onion:50002"),
                format!("tcp://{V3}.onion:50001"),
            ]
        );
        // With Tor off the row is dropped rather than falling back to the
        // address beside it, which does not reach the same service.
        assert!(v3.endpoints(false).is_empty());

        // v2 is refused by `Endpoint` even with Tor on, and does not fall
        // back either.
        let v2 = peer(json!(["1.2.3.4", format!("{V2}.onion"), ["s50002"]]));
        assert!(v2.endpoints(true).is_empty());
        assert!(v2.endpoints(false).is_empty());

        // The case of a name is not part of its identity.
        let shouted = peer(json!(["", format!("{}.ONION", V3.to_uppercase()), ["s"]]));
        assert_eq!(
            printed(&shouted.endpoints(true)),
            [format!("ssl://{V3}.onion:50002")]
        );
    }

    /// Junk of every shape is skipped, and the good rows beside it survive.
    #[test]
    fn malformed_rows_are_skipped_without_panicking() {
        let peers = parse(json!([
            "nope",
            [1, 2],
            ["1.2.3.4", "host.example", "notalist"],
            ["1.2.3.4", "host.example"],
            [],
            null,
            42,
            {"host": "host.example"},
            [null, null, null],
            ["1.2.3.4", 50002, ["s"]],
            ["1.2.3.4", "good.example", ["s50002"]]
        ]));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].host, "good.example");

        // A result that is not an array at all, which is the same kind of
        // answer one step up.
        assert!(parse(json!({})).is_empty());
        assert!(parse(json!(null)).is_empty());
        assert!(parse(json!([])).is_empty());
    }

    /// The tolerated oddities: a longer row, non-string features, a missing
    /// `ip`, an `ip` that is not one, and a row with no ports at all.
    #[test]
    fn odd_but_readable_rows_are_kept() {
        let long = peer(json!(["1.2.3.4", "host.example", ["s50002"], "extra"]));
        assert_eq!(
            printed(&long.endpoints(false)),
            ["ssl://host.example:50002"]
        );

        let mixed = peer(json!([
            "1.2.3.4",
            "host.example",
            ["v1.4", 7, null, "s50002"]
        ]));
        assert_eq!(mixed.features, ["v1.4", "s50002"]);

        let no_ip = peer(json!([null, "host.example", ["s50002"]]));
        assert_eq!(no_ip.ip, None);
        assert_eq!(
            printed(&no_ip.endpoints(false)),
            ["ssl://host.example:50002"]
        );

        let bad_ip = peer(json!(["not an address", "host.example", ["s50002"]]));
        assert_eq!(bad_ip.ip, None);

        // Advertised, but reachable on nothing: a `peer_edges` row and no
        // server.
        let portless = peer(json!(["1.2.3.4", "host.example", ["v1.4", "p10000"]]));
        assert!(portless.endpoints(false).is_empty());
    }

    /// The whitespace a hand-maintained peer list picks up.
    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let peer = peer(json!([" 1.2.3.4 ", " host.example ", ["s50002"]]));
        assert_eq!(peer.ip, Some("1.2.3.4".parse::<IpAddr>().unwrap()));
        assert_eq!(
            printed(&peer.endpoints(false)),
            ["ssl://host.example:50002"]
        );
    }

    #[test]
    fn ingest_inserts_every_advertised_endpoint() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), true, 10, false);
        let peers = parse(json!([
            ["18.195.224.155", "tool.sh", ["v1.4", "s50002", "t50001"]],
            ["95.217.73.31", "bitcoin.grey.pw", ["v1.4", "s50002"]]
        ]));

        let ingested = discovery.ingest(7, &peers);
        assert_eq!(
            printed(
                &ingested
                    .newly_enabled
                    .iter()
                    .map(|row| row.endpoint.clone())
                    .collect::<Vec<_>>()
            ),
            [
                "ssl://tool.sh:50002",
                "tcp://tool.sh:50001",
                "ssl://bitcoin.grey.pw:50002",
            ]
        );
        assert_eq!(ingested.newly_capped, 0);
        assert_eq!(ingested.already_known, 0);
        assert_eq!(ingested.skipped, 0);

        let rows = store.servers().expect("the servers read back");
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row.source, "peers:7");
            assert!(row.enabled);
            assert_eq!(row.disabled_reason, None);
        }
    }

    /// The same list again is the ordinary case -- the identity set asks
    /// every hour -- and it has to be a no-op.
    #[test]
    fn ingesting_the_same_peers_again_is_a_no_op() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), true, 10, false);
        let peers = parse(json!([["18.195.224.155", "tool.sh", ["s50002", "t50001"]]]));

        assert_eq!(discovery.ingest(7, &peers).newly_enabled.len(), 2);

        let again = discovery.ingest(9, &peers);
        assert!(again.newly_enabled.is_empty());
        assert_eq!(again.already_known, 2);
        assert_eq!(again.newly_capped, 0);
        assert_eq!(again.skipped, 0);

        let rows = store.servers().expect("the servers read back");
        assert_eq!(rows.len(), 2);
        // The first server to name a peer keeps the credit for it.
        assert!(rows.iter().all(|row| row.source == "peers:7"));
    }

    /// A server already known from the config file is not rediscovered.
    #[test]
    fn a_server_from_another_source_counts_as_known() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), true, 10, false);
        let endpoint: Endpoint = "ssl://tool.sh:50002".parse().expect("the endpoint parses");
        store
            .upsert_server(&endpoint, "config", None)
            .expect("the server is inserted");

        let ingested = discovery.ingest(7, &parse(json!([["", "tool.sh", ["s50002"]]])));
        assert!(ingested.newly_enabled.is_empty());
        assert_eq!(ingested.already_known, 1);
        assert_eq!(
            store.servers().expect("the servers read back")[0].source,
            "config"
        );
    }

    /// Past the cap a peer is still a row, disabled with the documented
    /// reason, and the ingest says how many.
    #[test]
    fn the_cap_disables_what_it_does_not_fit() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), true, 2, false);
        let peers = parse(json!([
            ["18.195.224.155", "tool.sh", ["s50002", "t50001"]],
            ["95.217.73.31", "bitcoin.grey.pw", ["s50002", "t50001"]]
        ]));

        let ingested = discovery.ingest(7, &peers);
        assert_eq!(ingested.newly_enabled.len(), 2);
        assert_eq!(ingested.newly_capped, 2);
        assert_eq!(ingested.already_known, 0);
        assert_eq!(ingested.skipped, 0);

        let rows = store.servers().expect("the servers read back");
        assert_eq!(rows.len(), 4);
        let capped: Vec<&ServerRow> = rows.iter().filter(|row| !row.enabled).collect();
        assert_eq!(capped.len(), 2);
        for row in capped {
            assert_eq!(row.disabled_reason.as_deref(), Some(REASON_CAP));
            assert_eq!(row.source, "peers:7");
        }
    }

    /// With discovery off nothing is written at all; the advertisement is
    /// still recorded, but by the probe that collected it.
    #[test]
    fn discovery_off_writes_nothing() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), false, 600, false);
        let peers = parse(json!([["18.195.224.155", "tool.sh", ["s50002", "t50001"]]]));

        let ingested = discovery.ingest(7, &peers);
        assert_eq!(
            ingested,
            Ingested {
                newly_enabled: Vec::new(),
                newly_capped: 0,
                already_known: 0,
                skipped: 2,
            }
        );
        assert!(store.servers().expect("the servers read back").is_empty());
    }

    /// The instant an ingest began is the boundary between what it inserted
    /// and what was already there, and a row stamped at exactly that
    /// instant is this ingest's: the stamp is taken after the lookup that
    /// would have found an older row.
    #[test]
    fn the_start_of_the_ingest_is_the_boundary() {
        let (_dir, store) = temp_store();
        let discovery = discovery(store.clone(), true, 10, false);
        let peers = parse(json!([["", "tool.sh", ["s50002"]]]));
        let endpoint: Endpoint = "ssl://tool.sh:50002".parse().expect("the endpoint parses");
        let row = store
            .upsert_server(&endpoint, "config", None)
            .expect("the server is inserted");

        // A microsecond later, the row is older than the ingest.
        let after = discovery.ingest_since(7, &peers, Micros(row.added_at.0 + 1));
        assert_eq!(after.already_known, 1);
        assert!(after.newly_enabled.is_empty());

        // At the instant itself, it is the ingest's own.
        let at = discovery.ingest_since(7, &peers, row.added_at);
        assert_eq!(at.already_known, 0);
        assert_eq!(at.newly_enabled.len(), 1);
    }

    /// A database that cannot answer is counted and logged rather than
    /// panicked at: the session that handed this peer list over has a
    /// subscription that matters more than the list does.
    #[test]
    fn a_store_that_refuses_counts_as_skipped() {
        let dir = TempDir::new().expect("a temporary directory");
        let path = dir.path().join("observer.sqlite");
        let store = Store::open(&path).expect("the database opens");
        let discovery = discovery(store.clone(), true, 10, false);
        // Through a second connection, so the store keeps its own open the
        // way a running daemon would.
        rusqlite::Connection::open(&path)
            .expect("a second connection")
            .execute("DROP TABLE servers", [])
            .expect("the table is dropped");

        let peers = parse(json!([["18.195.224.155", "tool.sh", ["s50002", "t50001"]]]));
        let ingested = discovery.ingest(7, &peers);
        assert_eq!(
            ingested,
            Ingested {
                newly_enabled: Vec::new(),
                newly_capped: 0,
                already_known: 0,
                skipped: 2,
            }
        );
    }

    /// Tor decides whether an onion peer reaches the database at all.
    #[test]
    fn onion_peers_reach_the_store_only_with_tor() {
        let (_dir, store) = temp_store();
        let peers = parse(json!([["", format!("{V3}.onion"), ["s50002"]]]));

        let without = discovery(store.clone(), true, 10, false).ingest(7, &peers);
        assert_eq!(without, Ingested::default());
        assert!(store.servers().expect("the servers read back").is_empty());

        let with = discovery(store.clone(), true, 10, true).ingest(7, &peers);
        assert_eq!(with.newly_enabled.len(), 1);
        assert_eq!(
            with.newly_enabled[0].endpoint.to_string(),
            format!("ssl://{V3}.onion:50002")
        );
    }
}
