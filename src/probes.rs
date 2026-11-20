//! What a server is asked all at once, and what one row is made of the
//! answers.
//!
//! DESIGN.md section 6 groups the questions into *sets*: a handful of
//! requests that go out together, because what is compared across servers is
//! a set asked at one moment, and because one row per set keeps `probes` an
//! order of magnitude smaller than one row per request. This module is that
//! list of sets, the requests in each of them, and the encoding of a set's
//! answers into the single [`Event::Probe`] the writer task expects.
//!
//! It owns no clock beyond the stamps the client hands back, no socket of
//! its own and no timer: [`run`] is given a connected [`Client`] and the ids
//! the session already chose, and the cadences that decide *when* a set runs
//! belong to the session (DESIGN.md section 5 step 5). What it does own is
//! the question of what a probe row means, which is the part an analysis
//! query a year from now has to be able to trust.
//!
//! # The encoding
//!
//! One set is one row, and the row's three JSON columns are aligned by
//! index:
//!
//! - **`params`** is always an array with one element per request of the
//!   set, in the order [`ProbeSpec`] lists them -- so a single-request kind
//!   stores a one-element array rather than a bare value, and nothing has to
//!   know which kinds have one request to read the column. The element is
//!   that request's parameters ([`ProbeRequest::params`]); for the batch of
//!   the fingerprint set, whose request is two requests in one line, it is
//!   the array of its members' parameters.
//! - **`result`** is the bare answer for a set of one request -- so that
//!   `blobs` equality across servers compares a `server.features` object
//!   with a `server.features` object, which is the comparison DESIGN.md
//!   section 4 keeps the blob table for -- and, for a set of several
//!   ([`ProbeKind::Estimatefee`] and [`ProbeKind::Fingerprint`]), an array
//!   aligned with `params` in which a request that did not answer is
//!   `null`. A single-request set whose one request failed has no result at
//!   all and so no blob.
//! - **`error`** is `null` when every request answered, and otherwise an
//!   array aligned with `params` holding `null` where a request succeeded
//!   and, where one did not, either the server's `error` object *verbatim*
//!   -- the verbatim string is the whole point of the fingerprint set -- or
//!   `{"transport": "<reason>"}` when there was no answer at all.
//!
//! The requests of a set are sent concurrently and the row carries the
//! earliest `sent_at` and the latest `received_at` of them, with `rtt_us`
//! the difference: the row says when the set was asked and when the slowest
//! member of it came back, which is what "asked at one moment" has to mean
//! once the set is more than one request. A set in which nothing was
//! answered keeps its `sent_at` (taken as the set was dispatched) and has no
//! `recv_at` and no `rtt_us`.
//!
//! A `params` array identifies its requests by position and not by name, so
//! the position is the contract: [`ProbeSpec`] is the key to it, the order
//! of the estimatefee targets and of the nine fingerprint requests is fixed
//! here, and a request may be appended to a set but not reordered without
//! making old rows mean something else.
//!
//! # What is not here
//!
//! The *initial* set of DESIGN.md section 5 step 3 is not a [`ProbeSet`]: it
//! is the identity kinds plus [`ProbeKind::Relayfee`] and
//! [`ProbeKind::MempoolInfo`], run once by the session when a connection
//! comes up, and giving it a name here would only invite a second list to
//! drift from this one. [`ProbeKind::CoinbaseTxid`] is in no set either --
//! the session fires it once per branch while a divergence window is open
//! (section 5 step 6), with the height it saw the split at.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::SystemTime;

use serde_json::{Value, json};
use tracing::debug;

use crate::TARGET_PROBES;
use crate::jsonrpc::{Client, Error, RawCall, Response};
// The two strings the fingerprint set's second `server.version` repeats are
// the ones the handshake already sent (DESIGN.md section 5 step 2): the probe
// is about the server's objection to being told twice, so they are taken from
// the session rather than spelled out again here.
use crate::session::{CLIENT_NAME, PROTOCOL_VERSION};
use crate::store::{Event, Micros, PeerEdge};

/// The confirmation targets every fee set asks `blockchain.estimatefee`
/// about (DESIGN.md section 6).
///
/// The comparison data: two servers in front of one `bitcoind` return the
/// same numbers from the same `estimatesmartfee`, and two that do not are
/// either on different nodes or on different software.
pub const ESTIMATEFEE_TARGETS: &[i64] = &[1, 2, 3, 6, 25, 144, 1008];

/// The targets that are not answers but fingerprints: zero, one past the
/// longest horizon `bitcoind` estimates for, and an absurd one.
///
/// This is where implementations differ -- one errors, one clamps, one
/// answers `-1` -- which is why they are asked in the same breath as the
/// ordinary targets and recorded in the same row.
pub const ESTIMATEFEE_EDGE_TARGETS: &[i64] = &[0, 1009, 100_000];

/// The target the `mode` variants are asked at.
///
/// One target rather than all of them: the mode is what is being compared,
/// and ElectrumX counts and costs requests per connection (DESIGN.md section
/// 6), so the set pays for two extra requests and not for fourteen.
pub const ESTIMATEFEE_MODE_TARGET: i64 = 6;

/// The `mode` strings the fee set asks for.
///
/// `blockchain.estimatefee(number, mode)` gained its second parameter in
/// protocol 1.6, which documents it only as a string to pass to the
/// `bitcoind` `estimatesmartfee` RPC as its `estimate_mode`; these are the
/// two that `estimatesmartfee` itself documents, and a server that predates
/// 1.6 refuses them, which makes the refusal as much of a fingerprint as the
/// number is a comparison.
pub const ESTIMATEFEE_MODES: &[&str] = &["ECONOMICAL", "CONSERVATIVE"];

/// The position of the coinbase transaction in its block, which is the
/// definition of a coinbase and not a parameter anyone may change.
const COINBASE_POSITION: i64 = 0;

/// The method the fingerprint set asks for and no server implements.
const UNKNOWN_METHOD: &str = "server.no_such_method";

/// The `id` of the fingerprint set's odd-id request: a string, where the
/// protocol has only ever used numbers.
const ODD_ID: &str = "electrum-observer";

/// The `pong_len` the fingerprint set passes to `server.ping`, which the
/// protocol documents and most servers do not accept.
const PONG_LEN: i64 = 8;

/// The key `probes.error` uses when there was no answer at all, rather than
/// an answer this crate disliked.
const TRANSPORT: &str = "transport";

/// The reason recorded for a raw call that collected no line before the
/// request timeout: [`Client::call_raw`] reports that as an empty reply
/// rather than as an [`Error`], because a server that says nothing to a
/// malformed request is behaving, not failing.
const NO_RAW_REPLY: &str = "no reply to the raw request";

/// One question, or one group of questions that is only ever asked and read
/// together.
///
/// The variants are the `probes.kind` values of DESIGN.md section 4 and the
/// spellings in [`as_str`](Self::as_str) are the column's contents, so they
/// are as stable as the table: renaming one splits every analysis query that
/// groups by it into a before and an after.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    /// `mempool.get_fee_histogram`.
    FeeHistogram,
    /// `blockchain.estimatefee` at every target of DESIGN.md section 6, in
    /// one set.
    Estimatefee,
    /// `blockchain.relayfee`.
    Relayfee,
    /// `mempool.get_info`.
    MempoolInfo,
    /// `server.features`, which is also where the genesis hash a connection
    /// is checked against comes from.
    Features,
    /// `server.banner`.
    Banner,
    /// `server.donation_address`.
    DonationAddress,
    /// `server.peers.subscribe`, which is also the source of `peer_edges`
    /// and of discovery.
    Peers,
    /// The nine deliberately odd requests of DESIGN.md section 6, in one
    /// set.
    Fingerprint,
    /// `blockchain.transaction.id_from_pos(height, 0)`: the coinbase txid of
    /// the block a server is on, asked once per branch while a divergence
    /// window is open.
    CoinbaseTxid,
}

impl ProbeKind {
    /// The spelling in `probes.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeKind::FeeHistogram => "fee_histogram",
            ProbeKind::Estimatefee => "estimatefee",
            ProbeKind::Relayfee => "relayfee",
            ProbeKind::MempoolInfo => "mempool_info",
            ProbeKind::Features => "features",
            ProbeKind::Banner => "banner",
            ProbeKind::DonationAddress => "donation_address",
            ProbeKind::Peers => "peers",
            ProbeKind::Fingerprint => "fingerprint",
            ProbeKind::CoinbaseTxid => "coinbase_txid",
        }
    }
}

/// A group of kinds that one timer fires together (DESIGN.md section 5 step
/// 5).
///
/// A set is a schedule rather than a row: each of its kinds is still its own
/// row, because `probes.kind` is what an analysis groups by and a histogram
/// and an estimate are not comparable quantities. What the set decides is
/// that they were asked at the same moment, which is what makes comparing
/// them across servers mean anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeSet {
    /// Every `cadence.fees_secs`, 300 s by default.
    Fees,
    /// Every `cadence.identity_secs`, 3600 s by default.
    Identity,
    /// Every `cadence.fingerprint_secs`, 86 400 s by default.
    Fingerprint,
}

impl ProbeSet {
    /// What the set asks, in the order it asks.
    pub fn kinds(self) -> &'static [ProbeKind] {
        match self {
            ProbeSet::Fees => &[
                ProbeKind::FeeHistogram,
                ProbeKind::Estimatefee,
                ProbeKind::Relayfee,
                ProbeKind::MempoolInfo,
            ],
            ProbeSet::Identity => &[
                ProbeKind::Features,
                ProbeKind::Banner,
                ProbeKind::DonationAddress,
                ProbeKind::Peers,
            ],
            ProbeSet::Fingerprint => &[ProbeKind::Fingerprint],
        }
    }
}

/// One request of a set, and how it has to be sent.
///
/// Most are a method and its parameters, sent with [`Client::call`] like
/// anything else. The two that are not are the point of the fingerprint set:
/// a request whose `id` is not a number and a JSON-RPC batch cannot be built
/// by `call` at all, and the answer to the first cannot be routed by id,
/// because the id that comes back is whatever the server made of the one
/// that went out. Those go through [`Client::call_raw`], which hands back
/// the lines verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRequest {
    /// An ordinary request.
    Call { method: &'static str, params: Value },
    /// A request whose `id` is the string `id` rather than a number.
    OddId {
        method: &'static str,
        params: Value,
        id: &'static str,
    },
    /// Several requests in one JSON array, with ids allocated as it goes
    /// out.
    Batch { members: Vec<(&'static str, Value)> },
}

impl ProbeRequest {
    /// The element this request contributes to `probes.params`.
    ///
    /// A batch has no parameters of its own, so it contributes the array of
    /// its members'.
    pub fn params(&self) -> Value {
        match self {
            ProbeRequest::Call { params, .. } | ProbeRequest::OddId { params, .. } => {
                params.clone()
            }
            ProbeRequest::Batch { members } => {
                Value::Array(members.iter().map(|(_, params)| params.clone()).collect())
            }
        }
    }

    /// The method, or `None` for a batch, which is several.
    pub fn method(&self) -> Option<&'static str> {
        match self {
            ProbeRequest::Call { method, .. } | ProbeRequest::OddId { method, .. } => Some(method),
            ProbeRequest::Batch { .. } => None,
        }
    }
}

/// Whatever a kind needs beyond its own name.
///
/// One field so far, and a struct rather than a bare `Option<i64>` so that
/// the next kind with an argument does not change [`run`]'s signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbeArgs {
    /// The block [`ProbeKind::CoinbaseTxid`] asks about.
    ///
    /// Every other kind ignores it. A coinbase probe without one asks for
    /// the txid at a `null` height, which the server refuses and the row
    /// records as the refusal it is: a caller that forgot the height is a
    /// bug in the session, and inventing a height would hide it behind a
    /// plausible answer about the wrong block.
    pub height: Option<i64>,
}

impl ProbeArgs {
    /// The arguments for a coinbase probe at `height`.
    pub fn at_height(height: i64) -> Self {
        ProbeArgs {
            height: Some(height),
        }
    }
}

/// The ids the session already chose for the row this probe will become.
///
/// `probe_id` is chosen before the probe is sent because `peer_edges` names
/// it and has to be written in the same batch (DESIGN.md section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeIds {
    pub probe_id: i64,
    pub connection_id: i64,
    pub server_id: i64,
}

/// What a kind asks, as an ordered list of requests.
///
/// Built from the kind alone (plus [`ProbeArgs`]), so it is the one place
/// the protocol methods of DESIGN.md section 6 are written down and the one
/// thing a test has to read to know that a set still asks what the design
/// says it does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeSpec {
    kind: ProbeKind,
    requests: Vec<ProbeRequest>,
}

impl ProbeSpec {
    /// The requests `kind` is made of.
    pub fn new(kind: ProbeKind, args: ProbeArgs) -> Self {
        ProbeSpec {
            kind,
            requests: requests_for(kind, args),
        }
    }

    /// Which kind this is.
    pub fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// The requests, in the order `probes.params` is indexed by.
    pub fn requests(&self) -> &[ProbeRequest] {
        &self.requests
    }

    /// The `probes.params` column: one element per request.
    pub fn params(&self) -> Value {
        Value::Array(self.requests.iter().map(ProbeRequest::params).collect())
    }
}

/// An ordinary request.
fn call(method: &'static str, params: Value) -> ProbeRequest {
    ProbeRequest::Call { method, params }
}

fn requests_for(kind: ProbeKind, args: ProbeArgs) -> Vec<ProbeRequest> {
    match kind {
        ProbeKind::FeeHistogram => vec![call("mempool.get_fee_histogram", json!([]))],
        ProbeKind::Estimatefee => estimatefee_requests(),
        ProbeKind::Relayfee => vec![call("blockchain.relayfee", json!([]))],
        ProbeKind::MempoolInfo => vec![call("mempool.get_info", json!([]))],
        ProbeKind::Features => vec![call("server.features", json!([]))],
        ProbeKind::Banner => vec![call("server.banner", json!([]))],
        ProbeKind::DonationAddress => vec![call("server.donation_address", json!([]))],
        ProbeKind::Peers => vec![call("server.peers.subscribe", json!([]))],
        ProbeKind::Fingerprint => fingerprint_requests(),
        ProbeKind::CoinbaseTxid => vec![call(
            "blockchain.transaction.id_from_pos",
            json!([args.height, COINBASE_POSITION]),
        )],
    }
}

/// The ordinary targets, then the edge cases, then the modes: the order
/// DESIGN.md section 6 lists them in, and the order `probes.params` is read
/// by.
fn estimatefee_requests() -> Vec<ProbeRequest> {
    ESTIMATEFEE_TARGETS
        .iter()
        .chain(ESTIMATEFEE_EDGE_TARGETS)
        .map(|target| call("blockchain.estimatefee", json!([target])))
        .chain(ESTIMATEFEE_MODES.iter().map(|mode| {
            call(
                "blockchain.estimatefee",
                json!([ESTIMATEFEE_MODE_TARGET, mode]),
            )
        }))
        .collect()
}

/// The nine of DESIGN.md section 6, in the order it lists them.
///
/// Nine and not more: ElectrumX counts and costs requests per connection and
/// disconnects a client that trips its limit, so this set is deliberately
/// the cheapest thing that still tells the implementations apart -- which is
/// why it runs once a day, and why the same objection is not provoked twice
/// in two spellings.
fn fingerprint_requests() -> Vec<ProbeRequest> {
    vec![
        call(UNKNOWN_METHOD, json!([])),
        call("blockchain.block.header", json!([-1])),
        call("blockchain.block.header", json!(["1"])),
        call("blockchain.estimatefee", json!([])),
        call("blockchain.block.header", json!([1, 0, 0])),
        ProbeRequest::OddId {
            method: "server.ping",
            params: json!([]),
            id: ODD_ID,
        },
        ProbeRequest::Batch {
            members: vec![
                ("server.ping", json!([])),
                ("blockchain.relayfee", json!([])),
            ],
        },
        call("server.ping", json!([PONG_LEN])),
        call("server.version", json!([CLIENT_NAME, PROTOCOL_VERSION])),
    ]
}

/// What a probe set turned into: the row, and the edges if it was a peer
/// list.
///
/// Two events rather than one because they are two tables, and because
/// `peer_edges` is written from the probe id the row carries -- the caller
/// sends both down the same channel and the writer puts them in the same
/// transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeResult {
    /// Always an [`Event::Probe`].
    pub event: Event,
    /// An [`Event::PeerEdges`], for [`ProbeKind::Peers`] when the answer
    /// held at least one well-formed row.
    pub peer_edges: Option<Event>,
}

/// What one request of a set came back as.
///
/// Both transport results -- a [`Response`] and a [`RawCall`] -- collapse
/// into this before anything is encoded, which is what makes the encoding a
/// pure function of values a test can write down rather than something that
/// only happens when a socket is involved.
#[derive(Clone, Debug, PartialEq)]
enum Outcome {
    /// A `result`.
    Answer {
        sent_at: SystemTime,
        received_at: SystemTime,
        result: Value,
    },
    /// The server's `error` object, kept exactly as it arrived.
    Refusal {
        sent_at: SystemTime,
        received_at: SystemTime,
        error: Value,
    },
    /// The verbatim lines a raw call collected, at least one.
    Lines {
        sent_at: SystemTime,
        received_at: SystemTime,
        lines: Vec<String>,
    },
    /// No answer at all. `sent_at` is absent when the request never reached
    /// the socket.
    Transport {
        sent_at: Option<SystemTime>,
        error: String,
    },
}

impl Outcome {
    /// When the request went out, for the outcomes that know.
    fn sent_at(&self) -> Option<SystemTime> {
        match self {
            Outcome::Answer { sent_at, .. }
            | Outcome::Refusal { sent_at, .. }
            | Outcome::Lines { sent_at, .. } => Some(*sent_at),
            Outcome::Transport { sent_at, .. } => *sent_at,
        }
    }

    /// When the answer arrived, if one did.
    fn received_at(&self) -> Option<SystemTime> {
        match self {
            Outcome::Answer { received_at, .. }
            | Outcome::Refusal { received_at, .. }
            | Outcome::Lines { received_at, .. } => Some(*received_at),
            Outcome::Transport { .. } => None,
        }
    }

    /// What this request contributes to the result, if anything.
    ///
    /// A raw call contributes the lines it collected as an array of strings:
    /// the whole reason to send a malformed request is to see what the
    /// server made of it, and parsing the answer back into a result would
    /// throw away the half of it that is not a result.
    fn result(&self) -> Option<Value> {
        match self {
            Outcome::Answer { result, .. } => Some(result.clone()),
            Outcome::Lines { lines, .. } => {
                Some(Value::Array(lines.iter().map(|line| json!(line)).collect()))
            }
            Outcome::Refusal { .. } | Outcome::Transport { .. } => None,
        }
    }

    /// What this request contributes to `probes.error`: `null` when it
    /// answered.
    fn error(&self) -> Value {
        match self {
            Outcome::Answer { .. } | Outcome::Lines { .. } => Value::Null,
            Outcome::Refusal { error, .. } => error.clone(),
            Outcome::Transport { error, .. } => json!({ TRANSPORT: error }),
        }
    }
}

/// Asks one probe and makes the row out of the answers.
///
/// The requests of a set go out together and are awaited together, because a
/// set is "what this server said at one moment"; the two raw requests of the
/// fingerprint set are sent one after the other, because
/// [`Client::call_raw`] takes the connection's untyped line sink and a
/// second overlapping raw call would make "whose line was that"
/// unanswerable. They still run alongside the ordinary ones.
///
/// Never fails. A timeout, a closed connection or a write that could not
/// happen are recorded in `probes.error` and the rest of the set carries on,
/// because what a dead connection means is the session's decision and not
/// this module's -- and because a set that gave up at its first failure
/// would lose the answers that came back in the same breath.
pub async fn run(client: &Client, kind: ProbeKind, ids: ProbeIds, extra: ProbeArgs) -> ProbeResult {
    let spec = ProbeSpec::new(kind, extra);
    let started_at = SystemTime::now();
    let outcomes = send(client, &spec).await;
    let peer_edges = if kind == ProbeKind::Peers {
        peer_edges_event(ids, &outcomes)
    } else {
        None
    };
    ProbeResult {
        event: encode(&spec, ids, started_at, &outcomes),
        peer_edges,
    }
}

/// Sends every request of a set and collects the outcomes in the set's own
/// order.
async fn send(client: &Client, spec: &ProbeSpec) -> Vec<Outcome> {
    let mut ordinary = Vec::new();
    let mut raw = Vec::new();
    for (index, request) in spec.requests().iter().enumerate() {
        match request {
            ProbeRequest::Call { method, params } => ordinary.push(async move {
                (index, outcome_of(client.call(method, params.clone()).await))
            }),
            ProbeRequest::OddId { method, params, id } => {
                raw.push((index, odd_id_line(method, params, id), Vec::new()));
            }
            ProbeRequest::Batch { members } => {
                let (line, ids) = batch_line(members, || client.next_id());
                raw.push((index, line, ids));
            }
        }
    }
    let (ordinary, raw) = tokio::join!(join_all(ordinary), raw_in_turn(client, raw));
    let mut all: Vec<(usize, Outcome)> = ordinary.into_iter().chain(raw).collect();
    all.sort_by_key(|(index, _)| *index);
    all.into_iter().map(|(_, outcome)| outcome).collect()
}

/// The request line for a request whose `id` is a string.
fn odd_id_line(method: &str, params: &Value, id: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// The request line for a batch, and the ids its members were given.
///
/// The ids are real ones from the connection's counter, so that the answer
/// -- which a server sends as one array carrying both -- can be waited for
/// by id rather than by guessing how many lines are coming.
fn batch_line(
    members: &[(&'static str, Value)],
    mut next_id: impl FnMut() -> u64,
) -> (String, Vec<u64>) {
    let mut ids = Vec::with_capacity(members.len());
    let elements: Vec<Value> = members
        .iter()
        .map(|(method, params)| {
            let id = next_id();
            ids.push(id);
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        })
        .collect();
    (Value::Array(elements).to_string(), ids)
}

/// The raw calls of a set, one at a time.
async fn raw_in_turn(
    client: &Client,
    raw: Vec<(usize, String, Vec<u64>)>,
) -> Vec<(usize, Outcome)> {
    let mut outcomes = Vec::with_capacity(raw.len());
    for (index, line, expect_ids) in raw {
        let outcome = match client.call_raw(&line, &expect_ids).await {
            Ok(call) => outcome_of_raw(call),
            Err(e) => Outcome::Transport {
                sent_at: None,
                error: e.to_string(),
            },
        };
        outcomes.push((index, outcome));
    }
    outcomes
}

/// A result, an error object or no answer at all, as one value.
fn outcome_of(reply: Result<Response, Error>) -> Outcome {
    match reply {
        Ok(response) => {
            let (sent_at, received_at) = (response.sent_at, response.received_at);
            match response.outcome {
                Ok(result) => Outcome::Answer {
                    sent_at,
                    received_at,
                    result,
                },
                Err(error) => Outcome::Refusal {
                    sent_at,
                    received_at,
                    error: error.raw,
                },
            }
        }
        Err(e) => Outcome::Transport {
            sent_at: None,
            error: e.to_string(),
        },
    }
}

/// The lines a raw call collected, or the fact that it collected none.
fn outcome_of_raw(call: RawCall) -> Outcome {
    // The lines are in arrival order, so the last one is the latest.
    match call.lines.last() {
        Some(last) => Outcome::Lines {
            sent_at: call.sent_at,
            received_at: last.received_at,
            lines: call.lines.iter().map(|line| line.text.clone()).collect(),
        },
        None => Outcome::Transport {
            sent_at: Some(call.sent_at),
            error: NO_RAW_REPLY.to_string(),
        },
    }
}

/// The row, from the set and its answers. Pure.
fn encode(spec: &ProbeSpec, ids: ProbeIds, started_at: SystemTime, outcomes: &[Outcome]) -> Event {
    let sent_at = Micros::from(
        outcomes
            .iter()
            .filter_map(Outcome::sent_at)
            .min()
            .unwrap_or(started_at),
    );
    let recv_at = outcomes
        .iter()
        .filter_map(Outcome::received_at)
        .max()
        .map(Micros::from);
    let result = if spec.requests().len() == 1 {
        outcomes.first().and_then(Outcome::result)
    } else {
        Some(Value::Array(
            outcomes
                .iter()
                .map(|outcome| outcome.result().unwrap_or(Value::Null))
                .collect(),
        ))
    };
    let errors: Vec<Value> = outcomes.iter().map(Outcome::error).collect();
    let anything_failed = errors.iter().any(|error| !error.is_null());
    let error = if anything_failed {
        Some(Value::Array(errors))
    } else {
        None
    };
    Event::Probe {
        id: ids.probe_id,
        connection_id: ids.connection_id,
        server_id: ids.server_id,
        kind: spec.kind().as_str().to_string(),
        params: spec.params(),
        sent_at,
        recv_at,
        rtt_us: recv_at.map(|at| at.as_i64() - sent_at.as_i64()),
        result,
        error,
    }
}

/// The edges a `server.peers.subscribe` answer advertised, if it answered.
fn peer_edges_event(ids: ProbeIds, outcomes: &[Outcome]) -> Option<Event> {
    let Some(Outcome::Answer { result, .. }) = outcomes.first() else {
        return None;
    };
    let (edges, skipped) = peer_edges(result);
    debug!(
        target: TARGET_PROBES,
        server_id = ids.server_id,
        edges = edges.len(),
        skipped,
        "read an advertised peer list"
    );
    if edges.is_empty() {
        return None;
    }
    Some(Event::PeerEdges {
        probe_id: ids.probe_id,
        from_server_id: ids.server_id,
        edges,
    })
}

/// Every well-formed row of a peer list, and how many rows were not.
///
/// A reply that is not an array at all counts as one skipped row rather than
/// as an empty list: a server that answers a peer list with an object said
/// something, and "nothing was advertised" is a different observation.
///
/// `discovery.rs` reads the same rows for the endpoints they carry; the two
/// agree on the row shape and on nothing else, because what makes a row
/// usable here (a host) is not what makes it usable there (a host and a
/// port).
fn peer_edges(result: &Value) -> (Vec<PeerEdge>, usize) {
    let Some(rows) = result.as_array() else {
        return (Vec::new(), 1);
    };
    let mut edges = Vec::new();
    let mut skipped = 0;
    for row in rows {
        match peer_edge(row) {
            Some(edge) => edges.push(edge),
            None => skipped += 1,
        }
    }
    (edges, skipped)
}

/// One `[ip, host, [features...]]` row (DESIGN.md section 7).
///
/// The host is what the edge is about, so a row without one is not an edge;
/// the address may be missing or empty, because a server that advertises a
/// peer it only knows by name is still advertising it.
fn peer_edge(row: &Value) -> Option<PeerEdge> {
    let row = row.as_array()?;
    let peer_ip = row
        .first()?
        .as_str()
        .filter(|ip| !ip.is_empty())
        .map(str::to_owned);
    let host = row.get(1)?.as_str()?;
    if host.is_empty() {
        return None;
    }
    let features = row.get(2)?.as_array()?;
    Some(PeerEdge {
        peer_host: host.to_owned(),
        peer_ip,
        features: features
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
    })
}

/// Polls every future to completion and returns the outputs in the order
/// the inputs were given.
///
/// `futures::future::join_all` in a dozen lines. A probe set is the one
/// place this crate needs it -- everything else either awaits one thing or
/// owns a task -- and a dependency whose whole surface is one call is a
/// dependency to explain in `Cargo.toml` for the lifetime of the crate.
async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pending: Vec<Option<Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut done: Vec<Option<F::Output>> = Vec::new();
    done.resize_with(pending.len(), || None);
    poll_fn(|cx| {
        let mut waiting = false;
        for (slot, output) in pending.iter_mut().zip(done.iter_mut()) {
            let Some(future) = slot else { continue };
            match future.as_mut().poll(cx) {
                Poll::Ready(value) => {
                    *output = Some(value);
                    *slot = None;
                }
                Poll::Pending => waiting = true,
            }
        }
        if waiting {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    done.into_iter()
        .map(|output| output.expect("every future was polled to completion"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::jsonrpc::{RawLine, RpcError};

    use super::*;

    /// A stamp, as microseconds since the epoch: the unit the row stores, so
    /// that an assertion about `sent_at` is an assertion about the number in
    /// the column.
    fn at(micros: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(u64::try_from(micros).expect("a stamp after 1970"))
    }

    fn ids() -> ProbeIds {
        ProbeIds {
            probe_id: 7,
            connection_id: 3,
            server_id: 11,
        }
    }

    fn spec_of(kind: ProbeKind) -> ProbeSpec {
        ProbeSpec::new(kind, ProbeArgs::default())
    }

    fn methods(spec: &ProbeSpec) -> Vec<Option<&'static str>> {
        spec.requests().iter().map(ProbeRequest::method).collect()
    }

    fn params_of(spec: &ProbeSpec) -> Vec<Value> {
        spec.requests().iter().map(ProbeRequest::params).collect()
    }

    fn answer(sent: i64, received: i64, result: Value) -> Outcome {
        Outcome::Answer {
            sent_at: at(sent),
            received_at: at(received),
            result,
        }
    }

    fn refusal(sent: i64, received: i64, error: Value) -> Outcome {
        Outcome::Refusal {
            sent_at: at(sent),
            received_at: at(received),
            error,
        }
    }

    fn transport(error: &str) -> Outcome {
        Outcome::Transport {
            sent_at: None,
            error: error.to_string(),
        }
    }

    /// The fields of the row, for an assertion that does not care about the
    /// ids.
    #[allow(clippy::type_complexity)]
    fn row(
        event: &Event,
    ) -> (
        &str,
        &Value,
        Micros,
        Option<Micros>,
        Option<i64>,
        &Option<Value>,
        &Option<Value>,
    ) {
        match event {
            Event::Probe {
                kind,
                params,
                sent_at,
                recv_at,
                rtt_us,
                result,
                error,
                ..
            } => (kind, params, *sent_at, *recv_at, *rtt_us, result, error),
            other => panic!("a probe is a probe, not {other:?}"),
        }
    }

    #[test]
    fn kind_names_are_the_column() {
        let names = [
            (ProbeKind::FeeHistogram, "fee_histogram"),
            (ProbeKind::Estimatefee, "estimatefee"),
            (ProbeKind::Relayfee, "relayfee"),
            (ProbeKind::MempoolInfo, "mempool_info"),
            (ProbeKind::Features, "features"),
            (ProbeKind::Banner, "banner"),
            (ProbeKind::DonationAddress, "donation_address"),
            (ProbeKind::Peers, "peers"),
            (ProbeKind::Fingerprint, "fingerprint"),
            (ProbeKind::CoinbaseTxid, "coinbase_txid"),
        ];
        for (kind, name) in names {
            assert_eq!(kind.as_str(), name, "{kind:?}");
        }
    }

    #[test]
    fn every_set_asks_what_the_design_says() {
        assert_eq!(
            ProbeSet::Fees.kinds(),
            &[
                ProbeKind::FeeHistogram,
                ProbeKind::Estimatefee,
                ProbeKind::Relayfee,
                ProbeKind::MempoolInfo,
            ]
        );
        assert_eq!(
            ProbeSet::Identity.kinds(),
            &[
                ProbeKind::Features,
                ProbeKind::Banner,
                ProbeKind::DonationAddress,
                ProbeKind::Peers,
            ]
        );
        assert_eq!(ProbeSet::Fingerprint.kinds(), &[ProbeKind::Fingerprint]);
    }

    /// The coinbase probe is in no set: the session fires it by itself while
    /// a divergence window is open.
    #[test]
    fn the_coinbase_probe_is_in_no_set() {
        for set in [ProbeSet::Fees, ProbeSet::Identity, ProbeSet::Fingerprint] {
            assert!(!set.kinds().contains(&ProbeKind::CoinbaseTxid), "{set:?}");
        }
    }

    #[test]
    fn single_request_kinds_ask_one_method_with_no_parameters() {
        let table = [
            (ProbeKind::FeeHistogram, "mempool.get_fee_histogram"),
            (ProbeKind::Relayfee, "blockchain.relayfee"),
            (ProbeKind::MempoolInfo, "mempool.get_info"),
            (ProbeKind::Features, "server.features"),
            (ProbeKind::Banner, "server.banner"),
            (ProbeKind::DonationAddress, "server.donation_address"),
            (ProbeKind::Peers, "server.peers.subscribe"),
        ];
        for (kind, method) in table {
            let spec = spec_of(kind);
            assert_eq!(spec.kind(), kind);
            assert_eq!(methods(&spec), vec![Some(method)], "{kind:?}");
            assert_eq!(spec.params(), json!([[]]), "{kind:?}");
        }
    }

    #[test]
    fn the_coinbase_probe_asks_for_position_zero_at_its_height() {
        let spec = ProbeSpec::new(ProbeKind::CoinbaseTxid, ProbeArgs::at_height(840_000));
        assert_eq!(
            methods(&spec),
            vec![Some("blockchain.transaction.id_from_pos")]
        );
        assert_eq!(spec.params(), json!([[840_000, 0]]));
    }

    /// Without a height the request goes out with a null one rather than
    /// with an invented block: the server's refusal is the record that the
    /// caller forgot.
    #[test]
    fn the_coinbase_probe_without_a_height_asks_about_null() {
        assert_eq!(
            spec_of(ProbeKind::CoinbaseTxid).params(),
            json!([[null, 0]])
        );
    }

    #[test]
    fn estimatefee_asks_every_documented_target_in_one_set() {
        let spec = spec_of(ProbeKind::Estimatefee);
        assert_eq!(ESTIMATEFEE_TARGETS, &[1, 2, 3, 6, 25, 144, 1008]);
        assert_eq!(ESTIMATEFEE_EDGE_TARGETS, &[0, 1009, 100_000]);
        assert_eq!(ESTIMATEFEE_MODES, &["ECONOMICAL", "CONSERVATIVE"]);
        assert!(
            methods(&spec)
                .iter()
                .all(|method| *method == Some("blockchain.estimatefee"))
        );
        assert_eq!(
            spec.params(),
            json!([
                [1],
                [2],
                [3],
                [6],
                [25],
                [144],
                [1008],
                [0],
                [1009],
                [100_000],
                [6, "ECONOMICAL"],
                [6, "CONSERVATIVE"],
            ])
        );
    }

    #[test]
    fn the_fingerprint_set_is_the_documented_nine() {
        let spec = spec_of(ProbeKind::Fingerprint);
        assert_eq!(spec.requests().len(), 9);
        assert_eq!(
            methods(&spec),
            vec![
                Some("server.no_such_method"),
                Some("blockchain.block.header"),
                Some("blockchain.block.header"),
                Some("blockchain.estimatefee"),
                Some("blockchain.block.header"),
                Some("server.ping"),
                None,
                Some("server.ping"),
                Some("server.version"),
            ]
        );
        let params = params_of(&spec);
        assert_eq!(params[0], json!([]), "an unknown method");
        assert_eq!(params[1], json!([-1]), "a negative height");
        assert_eq!(params[2], json!(["1"]), "a height as a string");
        assert_eq!(params[3], json!([]), "estimatefee with no parameters");
        assert_eq!(params[4], json!([1, 0, 0]), "too many parameters");
        assert_eq!(params[5], json!([]), "the odd id");
        assert_eq!(params[6], json!([[], []]), "the batch, by its members");
        assert_eq!(params[7], json!([8]), "ping with a pong_len");
        assert_eq!(params[8].as_array().expect("an array").len(), 2);
    }

    /// Two of the nine cannot be sent by `Client::call` at all, and which
    /// two is the reason `call_raw` exists.
    #[test]
    fn two_of_the_fingerprint_requests_are_raw() {
        let spec = spec_of(ProbeKind::Fingerprint);
        assert!(matches!(
            spec.requests()[5],
            ProbeRequest::OddId { id: ODD_ID, .. }
        ));
        assert!(matches!(spec.requests()[6], ProbeRequest::Batch { .. }));
    }

    #[test]
    fn an_odd_id_line_carries_the_id_as_a_string() {
        let line = odd_id_line("server.ping", &json!([]), "xyzzy");
        let parsed: Value = serde_json::from_str(&line).expect("a request line is JSON");
        assert_eq!(parsed["id"], json!("xyzzy"));
        assert_eq!(parsed["method"], json!("server.ping"));
        assert_eq!(parsed["params"], json!([]));
    }

    #[test]
    fn a_batch_line_is_an_array_with_the_ids_it_allocated() {
        let mut next = 40;
        let members = vec![
            ("server.ping", json!([])),
            ("blockchain.relayfee", json!([])),
        ];
        let (line, ids) = batch_line(&members, || {
            next += 1;
            next
        });
        assert_eq!(ids, vec![41, 42]);
        let parsed: Value = serde_json::from_str(&line).expect("a batch line is JSON");
        assert_eq!(
            parsed,
            json!([
                {"jsonrpc": "2.0", "id": 41, "method": "server.ping", "params": []},
                {"jsonrpc": "2.0", "id": 42, "method": "blockchain.relayfee", "params": []},
            ])
        );
    }

    #[test]
    fn a_response_becomes_an_answer_or_a_refusal() {
        let ok = outcome_of(Ok(Response {
            id: 1,
            sent_at: at(10),
            received_at: at(20),
            outcome: Ok(json!(0.0001)),
        }));
        assert_eq!(ok, answer(10, 20, json!(0.0001)));

        let raw = json!({"code": 1, "message": "server.version already sent"});
        let refused = outcome_of(Ok(Response {
            id: 2,
            sent_at: at(10),
            received_at: at(30),
            outcome: Err(RpcError {
                code: Some(1),
                message: "server.version already sent".to_string(),
                data: None,
                raw: raw.clone(),
            }),
        }));
        assert_eq!(refused, refusal(10, 30, raw));
    }

    #[test]
    fn a_transport_failure_becomes_its_display() {
        assert_eq!(
            outcome_of(Err(Error::Timeout)),
            transport("the request timed out")
        );
    }

    #[test]
    fn a_raw_call_keeps_every_line_and_the_latest_stamp() {
        let call = RawCall {
            sent_at: at(10),
            lines: vec![
                RawLine {
                    received_at: at(20),
                    text: "first".to_string(),
                    ids: vec![],
                },
                RawLine {
                    received_at: at(40),
                    text: "second".to_string(),
                    ids: vec![1],
                },
            ],
            complete: true,
        };
        assert_eq!(
            outcome_of_raw(call),
            Outcome::Lines {
                sent_at: at(10),
                received_at: at(40),
                lines: vec!["first".to_string(), "second".to_string()],
            }
        );
    }

    #[test]
    fn a_raw_call_with_no_lines_is_a_transport_failure_that_knows_when_it_went_out() {
        let outcome = outcome_of_raw(RawCall {
            sent_at: at(10),
            lines: Vec::new(),
            complete: false,
        });
        assert_eq!(
            outcome,
            Outcome::Transport {
                sent_at: Some(at(10)),
                error: NO_RAW_REPLY.to_string(),
            }
        );
    }

    #[test]
    fn a_single_request_set_stores_the_bare_result() {
        let features = json!({"genesis_hash": "00", "server_version": "Fulcrum 1.12.0"});
        let event = encode(
            &spec_of(ProbeKind::Features),
            ids(),
            at(0),
            &[answer(100, 350, features.clone())],
        );
        let (kind, params, sent_at, recv_at, rtt_us, result, error) = row(&event);
        assert_eq!(kind, "features");
        assert_eq!(*params, json!([[]]));
        assert_eq!(sent_at, Micros(100));
        assert_eq!(recv_at, Some(Micros(350)));
        assert_eq!(rtt_us, Some(250));
        assert_eq!(*result, Some(features));
        assert_eq!(*error, None);
    }

    /// A one-request set that failed has no result, so it keys no blob: the
    /// row is the error and nothing else.
    #[test]
    fn a_single_request_set_that_failed_has_no_result() {
        let refused = json!({"code": -32601, "message": "unknown method"});
        let event = encode(
            &spec_of(ProbeKind::Banner),
            ids(),
            at(0),
            &[refusal(100, 200, refused.clone())],
        );
        let (_, _, _, _, _, result, error) = row(&event);
        assert_eq!(*result, None);
        assert_eq!(*error, Some(json!([refused])));
    }

    #[test]
    fn a_multi_request_set_aligns_result_and_error_with_params() {
        let spec = spec_of(ProbeKind::Estimatefee);
        let refused = json!({"code": 1, "message": "target out of range"});
        let mut outcomes: Vec<Outcome> = (0..spec.requests().len())
            .map(|i| answer(100 + i as i64, 200 + i as i64, json!(0.0001)))
            .collect();
        outcomes[7] = refusal(107, 207, refused.clone());
        outcomes[9] = transport("the request timed out");

        let event = encode(&spec, ids(), at(0), &outcomes);
        let (kind, params, sent_at, recv_at, rtt_us, result, error) = row(&event);
        assert_eq!(kind, "estimatefee");
        let params = params.as_array().expect("an array of parameters");
        let result = result.as_ref().expect("a result array");
        let result = result.as_array().expect("an array of results");
        let error = error.as_ref().expect("an error array");
        let error = error.as_array().expect("an array of errors");
        assert_eq!(params.len(), 12);
        assert_eq!(result.len(), 12);
        assert_eq!(error.len(), 12);
        assert_eq!(result[7], Value::Null);
        assert_eq!(error[7], refused);
        assert_eq!(result[9], Value::Null);
        assert_eq!(error[9], json!({"transport": "the request timed out"}));
        assert_eq!(result[0], json!(0.0001));
        assert_eq!(error[0], Value::Null);
        assert_eq!(error[11], Value::Null);
        // The earliest request out and the latest answer in, over the whole
        // set, and the timed-out one contributes neither.
        assert_eq!(sent_at, Micros(100));
        assert_eq!(recv_at, Some(Micros(211)));
        assert_eq!(rtt_us, Some(111));
    }

    #[test]
    fn a_raw_answer_is_stored_as_the_lines_that_arrived() {
        let spec = spec_of(ProbeKind::Fingerprint);
        let mut outcomes: Vec<Outcome> = (0..spec.requests().len())
            .map(|_| answer(100, 200, Value::Null))
            .collect();
        outcomes[5] = Outcome::Lines {
            sent_at: at(100),
            received_at: at(300),
            lines: vec![r#"{"id":"electrum-observer","result":null}"#.to_string()],
        };
        let event = encode(&spec, ids(), at(0), &outcomes);
        let (_, _, _, _, _, result, error) = row(&event);
        let result = result.as_ref().expect("a result array");
        assert_eq!(
            result[5],
            json!([r#"{"id":"electrum-observer","result":null}"#])
        );
        assert_eq!(*error, None, "a verbatim line is an answer, not an error");
    }

    /// Nothing came back at all: the row still says when the set went out,
    /// which is what the fallback stamp is for.
    #[test]
    fn a_set_that_nothing_answered_keeps_its_dispatch_time() {
        let event = encode(
            &spec_of(ProbeKind::MempoolInfo),
            ids(),
            at(500),
            &[transport("the connection is closed: eof")],
        );
        let (_, _, sent_at, recv_at, rtt_us, result, error) = row(&event);
        assert_eq!(sent_at, Micros(500));
        assert_eq!(recv_at, None);
        assert_eq!(rtt_us, None);
        assert_eq!(*result, None);
        assert_eq!(
            *error,
            Some(json!([{"transport": "the connection is closed: eof"}]))
        );
    }

    /// A raw request that never reached the socket still knows when it was
    /// written, and that stamp is the set's.
    #[test]
    fn a_transport_failure_that_knows_its_stamp_contributes_it() {
        let event = encode(
            &spec_of(ProbeKind::Features),
            ids(),
            at(500),
            &[Outcome::Transport {
                sent_at: Some(at(120)),
                error: NO_RAW_REPLY.to_string(),
            }],
        );
        let (_, _, sent_at, recv_at, ..) = row(&event);
        assert_eq!(sent_at, Micros(120));
        assert_eq!(recv_at, None);
    }

    #[test]
    fn the_row_carries_the_ids_the_session_chose() {
        let event = encode(
            &spec_of(ProbeKind::Banner),
            ids(),
            at(0),
            &[answer(1, 2, json!("hello"))],
        );
        match event {
            Event::Probe {
                id,
                connection_id,
                server_id,
                ..
            } => assert_eq!((id, connection_id, server_id), (7, 3, 11)),
            other => panic!("a probe is a probe, not {other:?}"),
        }
    }

    #[test]
    fn well_formed_peer_rows_become_edges() {
        let (edges, skipped) = peer_edges(&json!([
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
            ["", "no.address.example.org", []],
        ]));
        assert_eq!(skipped, 0);
        assert_eq!(
            edges,
            vec![
                PeerEdge {
                    peer_host: "electrum.example.com".to_string(),
                    peer_ip: Some("104.198.149.61".to_string()),
                    features: vec![
                        "v1.4".to_string(),
                        "s50002".to_string(),
                        "t50001".to_string()
                    ],
                },
                PeerEdge {
                    peer_host: "fulcrum.example.de".to_string(),
                    peer_ip: Some("2a01:4f8:c17:3f6f::1".to_string()),
                    features: vec!["v1.4.5".to_string(), "s50002".to_string()],
                },
                PeerEdge {
                    peer_host: "no.address.example.org".to_string(),
                    peer_ip: None,
                    features: vec![],
                },
            ]
        );
    }

    #[test]
    fn junk_peer_rows_are_skipped_and_counted() {
        let (edges, skipped) = peer_edges(&json!([
            ["1.2.3.4"],
            ["1.2.3.4", "short.example.com"],
            ["1.2.3.4", "", ["v1.4"]],
            ["1.2.3.4", 50002, ["v1.4"]],
            ["1.2.3.4", "features.example.com", "v1.4"],
            "a string instead of a row",
            null,
            ["1.2.3.4", "good.example.com", ["v1.4", 50002]],
        ]));
        assert_eq!(skipped, 7);
        assert_eq!(
            edges,
            vec![PeerEdge {
                peer_host: "good.example.com".to_string(),
                peer_ip: Some("1.2.3.4".to_string()),
                // A feature that is not a string is dropped; the row is
                // still an advertisement.
                features: vec!["v1.4".to_string()],
            }]
        );
    }

    #[test]
    fn a_peer_list_that_is_not_a_list_is_one_skipped_row() {
        let (edges, skipped) = peer_edges(&json!({"peers": []}));
        assert!(edges.is_empty());
        assert_eq!(skipped, 1);
    }

    #[test]
    fn peer_edges_are_emitted_only_when_there_are_some() {
        let good = peer_edges_event(
            ids(),
            &[answer(1, 2, json!([["1.2.3.4", "a.example.com", []]]))],
        );
        assert_eq!(
            good,
            Some(Event::PeerEdges {
                probe_id: 7,
                from_server_id: 11,
                edges: vec![PeerEdge {
                    peer_host: "a.example.com".to_string(),
                    peer_ip: Some("1.2.3.4".to_string()),
                    features: vec![],
                }],
            })
        );
        assert_eq!(
            peer_edges_event(ids(), &[answer(1, 2, json!([["1.2.3.4"]]))]),
            None,
            "a list of nothing usable is no edges at all"
        );
        assert_eq!(
            peer_edges_event(ids(), &[refusal(1, 2, json!({"code": 1}))]),
            None,
            "a server that refused advertised nobody"
        );
    }

    async fn after(yields: usize, value: usize) -> usize {
        for _ in 0..yields {
            tokio::task::yield_now().await;
        }
        value
    }

    /// The outputs are the inputs' order and not the order they finished in,
    /// which is what makes `params[i]` and `result[i]` the same request.
    #[tokio::test]
    async fn join_all_keeps_the_order_it_was_given() {
        assert_eq!(
            join_all(vec![after(4, 0), after(0, 1), after(2, 2)]).await,
            vec![0, 1, 2]
        );
        assert!(
            join_all(Vec::<std::future::Ready<u8>>::new())
                .await
                .is_empty()
        );
    }
}
