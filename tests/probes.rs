//! The probe sets, asked of a server over a real socket.
//!
//! The unit tests in `src/probes.rs` are about the two halves of the module
//! that are pure: what a set asks, and what a row is made of a set's
//! answers. What they cannot show is the join between them -- that the
//! requests go out in the order `probes.params` is indexed by, that a
//! concurrent set does not interleave its answers, that the two requests of
//! the fingerprint set which cannot be sent by `Client::call` at all come
//! back verbatim, and that a member which errors or never answers takes only
//! its own index with it.
//!
//! So these drive `probes::run` against the mock Electrum server of
//! `tests/common/mock_server.rs`, which answers the methods of DESIGN.md
//! section 6 and can be told to refuse or ignore any one of them.

mod common;

use std::future::Future;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::TcpStream;

use electrum_observer::jsonrpc::{Client, Notifications};
use electrum_observer::probes::{self, ProbeArgs, ProbeIds, ProbeKind, ProbeResult, ProbeSpec};
use electrum_observer::store::{Event, Micros, PeerEdge};

use common::mock_server::{
    BAD_REQUEST, Behaviour, GENESIS_COINBASE_TXID, MockServer, Reaction, rpc_error,
};

/// How long any wait here may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(5);

/// A request timeout short enough to be waited out on purpose.
const IMPATIENCE: Duration = Duration::from_millis(300);

/// The ids a session would have chosen, so that the row can be asserted to
/// carry them.
const IDS: ProbeIds = ProbeIds {
    probe_id: 41,
    connection_id: 5,
    server_id: 9,
};

async fn soon<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("waited {PATIENCE:?} for {what}"))
}

async fn connect(server: &MockServer, request_timeout: Duration) -> (Client, Notifications) {
    let stream = soon("a connection", TcpStream::connect(server.addr()))
        .await
        .expect("the mock server is listening");
    Client::new(stream, request_timeout)
}

/// Runs one probe against a fresh connection to a server behaving that way.
async fn probe(behaviour: Behaviour, kind: ProbeKind) -> (MockServer, ProbeResult) {
    probe_with(behaviour, kind, ProbeArgs::default(), PATIENCE).await
}

async fn probe_with(
    behaviour: Behaviour,
    kind: ProbeKind,
    args: ProbeArgs,
    request_timeout: Duration,
) -> (MockServer, ProbeResult) {
    let server = MockServer::start(behaviour).await;
    // The notifications end is held for the length of the probe: dropping it
    // is how a session says it is done with the connection.
    let (client, _notifications) = connect(&server, request_timeout).await;
    let result = soon("a probe", probes::run(&client, kind, IDS, args)).await;
    (server, result)
}

/// The columns of the one row a probe set becomes.
struct Row<'a> {
    kind: &'a str,
    params: &'a Value,
    sent_at: Micros,
    recv_at: Option<Micros>,
    rtt_us: Option<i64>,
    result: Option<&'a Value>,
    error: Option<&'a Value>,
}

impl Row<'_> {
    /// The result of request `index` of a multi-request set.
    fn result_at(&self, index: usize) -> &Value {
        &self.result.expect("a result array")[index]
    }

    /// The error of request `index` of a multi-request set.
    fn error_at(&self, index: usize) -> &Value {
        &self.error.expect("an error array")[index]
    }

    /// That every request answered, and that the stamps are a round trip.
    fn is_a_round_trip(&self) {
        let recv_at = self.recv_at.expect("something came back");
        assert!(recv_at >= self.sent_at, "{:?}", (self.sent_at, recv_at));
        assert_eq!(
            self.rtt_us,
            Some(recv_at.as_i64() - self.sent_at.as_i64()),
            "the round trip is the difference of the two stamps"
        );
    }
}

fn row(result: &ProbeResult) -> Row<'_> {
    match &result.event {
        Event::Probe {
            id,
            connection_id,
            server_id,
            kind,
            params,
            sent_at,
            recv_at,
            rtt_us,
            result,
            error,
        } => {
            assert_eq!((*id, *connection_id, *server_id), (41, 5, 9));
            Row {
                kind,
                params,
                sent_at: *sent_at,
                recv_at: *recv_at,
                rtt_us: *rtt_us,
                result: result.as_ref(),
                error: error.as_ref(),
            }
        }
        other => panic!("a probe is a probe, not {other:?}"),
    }
}

/// Every kind that is one request stores the answer as it arrived, bare: an
/// analysis asking "did these two servers answer the same thing" compares
/// `blobs` rows, and a `server.features` object wrapped in an array would
/// only be equal to another wrapped one (DESIGN.md section 4).
#[tokio::test]
async fn a_single_request_kind_stores_the_bare_answer() {
    let behaviour = Behaviour::default();
    let expected = [
        (ProbeKind::Features, "features", behaviour.features.clone()),
        (ProbeKind::Banner, "banner", json!(behaviour.banner.clone())),
        (
            ProbeKind::DonationAddress,
            "donation_address",
            json!(behaviour.donation_address.clone()),
        ),
        (ProbeKind::Relayfee, "relayfee", behaviour.relayfee.clone()),
        (
            ProbeKind::FeeHistogram,
            "fee_histogram",
            behaviour.fee_histogram.clone(),
        ),
        (
            ProbeKind::MempoolInfo,
            "mempool_info",
            behaviour.mempool_info.clone(),
        ),
        (ProbeKind::Peers, "peers", behaviour.peers.clone()),
    ];
    for (kind, name, answer) in expected {
        let (_server, result) = probe(behaviour.clone(), kind).await;
        let row = row(&result);
        assert_eq!(row.kind, name);
        assert_eq!(row.params, &json!([[]]), "{name}");
        assert_eq!(row.result, Some(&answer), "{name}");
        assert_eq!(row.error, None, "{name}");
        row.is_a_round_trip();
    }
}

/// The probe DESIGN.md section 5 step 6 fires once per branch while a
/// divergence window is open: the coinbase of the block a server is on
/// identifies the branch after it has been orphaned.
#[tokio::test]
async fn the_coinbase_probe_asks_about_the_height_it_was_given() {
    let (server, result) = probe_with(
        Behaviour::default(),
        ProbeKind::CoinbaseTxid,
        ProbeArgs::at_height(0),
        PATIENCE,
    )
    .await;
    let row = row(&result);
    assert_eq!(row.kind, "coinbase_txid");
    assert_eq!(row.params, &json!([[0, 0]]));
    assert_eq!(row.result, Some(&json!(GENESIS_COINBASE_TXID)));
    assert_eq!(row.error, None);

    let sent = server.requests();
    let sent = sent.last().expect("a request was sent");
    assert_eq!(sent.method, "blockchain.transaction.id_from_pos");
    assert_eq!(sent.params, json!([0, 0]));
}

/// A server that does not have the block refuses, and the refusal is the
/// row: the branch was asked about, and this is what it said.
#[tokio::test]
async fn a_coinbase_probe_a_server_cannot_answer_keeps_the_refusal() {
    let (_server, result) = probe_with(
        Behaviour::default(),
        ProbeKind::CoinbaseTxid,
        ProbeArgs::at_height(840_000),
        PATIENCE,
    )
    .await;
    let row = row(&result);
    assert_eq!(row.result, None, "a refused set keys no blob");
    assert_eq!(
        row.error,
        Some(&json!([rpc_error(
            BAD_REQUEST,
            "no tx at position 0 in block at height 840000"
        )]))
    );
    row.is_a_round_trip();
}

/// Twelve requests, one row: the ordinary targets, the edge cases that
/// separate implementations, and the two `mode` variants, aligned with the
/// `params` array by index.
#[tokio::test]
async fn estimatefee_asks_every_target_in_one_row() {
    let behaviour = Behaviour::default();
    let (server, result) = probe(behaviour.clone(), ProbeKind::Estimatefee).await;
    let row = row(&result);
    assert_eq!(row.kind, "estimatefee");
    assert_eq!(
        row.params,
        &ProbeSpec::new(ProbeKind::Estimatefee, ProbeArgs::default()).params()
    );
    assert_eq!(row.error, None, "the mock answers every target");
    row.is_a_round_trip();

    // The targets the mock has an estimate for.
    for (index, target) in [1, 2, 3, 6, 25, 144, 1008].into_iter().enumerate() {
        assert_eq!(
            row.result_at(index),
            behaviour.estimatefee.get(&target).expect("an estimate"),
            "target {target}"
        );
    }
    // The edge cases, which this server answers the way a server with no
    // estimate for that horizon does.
    for index in 7..10 {
        assert_eq!(row.result_at(index), &json!(-1), "edge case {index}");
    }
    // The mode variants, at the target they are asked at.
    for index in 10..12 {
        assert_eq!(row.result_at(index), &json!(0.00009), "mode {index}");
    }

    let sent = server.requests();
    assert_eq!(
        sent.iter()
            .filter(|r| r.method == "blockchain.estimatefee")
            .count(),
        12,
        "every target goes out, and goes out once"
    );
}

/// The nine requests of DESIGN.md section 6 reach the server as the set
/// describes them, batch included -- the harness records a batch as one
/// entry per member, so ten entries for nine requests.
#[tokio::test]
async fn the_fingerprint_set_sends_what_it_says_it_sends() {
    let (server, _result) = probe(Behaviour::default(), ProbeKind::Fingerprint).await;
    let mut methods: Vec<String> = server
        .requests()
        .into_iter()
        .map(|request| request.method)
        .collect();
    methods.sort();
    let mut expected = vec![
        "server.no_such_method",
        "blockchain.block.header",
        "blockchain.block.header",
        "blockchain.block.header",
        "blockchain.estimatefee",
        "server.ping",
        "server.ping",
        "blockchain.relayfee",
        "server.ping",
        "server.version",
    ];
    expected.sort_unstable();
    assert_eq!(methods, expected);
}

/// The two requests that cannot be sent by `Client::call`: what comes back
/// is the line itself, because what is being collected is what the server
/// made of a request it should not have been sent.
#[tokio::test]
async fn the_odd_id_and_the_batch_come_back_verbatim() {
    let (_server, result) = probe(Behaviour::default(), ProbeKind::Fingerprint).await;
    let row = row(&result);

    let odd = row.result_at(5).as_array().expect("the lines that arrived");
    let odd = odd[0].as_str().expect("a line is text");
    assert!(
        odd.contains(r#""id":"electrum-observer""#),
        "the server echoed the string id: {odd}"
    );
    assert_eq!(
        row.error_at(5),
        &Value::Null,
        "a verbatim line is an answer"
    );

    let batch = row.result_at(6).as_array().expect("the lines that arrived");
    let batch: Value =
        serde_json::from_str(batch[0].as_str().expect("a line is text")).expect("a JSON line");
    assert_eq!(
        batch.as_array().expect("a batch reply is an array").len(),
        2,
        "both members answered in one line: {batch}"
    );
    assert_eq!(row.error_at(6), &Value::Null);
}

/// A server that never implemented batching answers the one line it has to
/// answer, and that line is the fingerprint.
#[tokio::test]
async fn a_server_that_refuses_batches_is_recorded_by_its_refusal() {
    let (_server, result) = probe_with(
        Behaviour::default().batches(false),
        ProbeKind::Fingerprint,
        ProbeArgs::default(),
        IMPATIENCE,
    )
    .await;
    let row = row(&result);
    let lines = row.result_at(6).as_array().expect("the lines that arrived");
    let line = lines[0].as_str().expect("a line is text");
    assert!(
        line.contains("batches are not supported"),
        "the refusal is kept verbatim: {line}"
    );
}

/// One member refused; the others are untouched, and the refusal is in the
/// error array at that member's index with the object exactly as it
/// arrived.
#[tokio::test]
async fn a_refusal_lands_at_its_own_index_only() {
    let refusal = json!({
        "code": 1,
        "message": "estimatefee is disabled on this server",
        "data": {"method": "blockchain.estimatefee"},
    });
    let (_server, result) = probe(
        Behaviour::default().on("blockchain.estimatefee", Reaction::Error(refusal.clone())),
        ProbeKind::Fingerprint,
    )
    .await;
    let row = row(&result);
    assert_eq!(row.error_at(3), &refusal, "verbatim, data and all");
    assert_eq!(row.result_at(3), &Value::Null);
    assert_eq!(row.error_at(8), &Value::Null);
    assert_eq!(
        row.result_at(8),
        &json!(["Fulcrum 1.12.0", "1.4"]),
        "the member after the refused one still answered"
    );
    row.is_a_round_trip();
}

/// A member that is never answered costs its own index and nothing else:
/// the set is not abandoned, and the row says the difference between "the
/// server refused" and "the server said nothing".
#[tokio::test]
async fn a_request_that_is_never_answered_is_a_transport_error_for_its_index() {
    let (_server, result) = probe_with(
        Behaviour::default().on("blockchain.estimatefee", Reaction::Never),
        ProbeKind::Fingerprint,
        ProbeArgs::default(),
        IMPATIENCE,
    )
    .await;
    let row = row(&result);
    assert_eq!(
        row.error_at(3),
        &json!({"transport": "the request timed out"})
    );
    assert_eq!(row.result_at(3), &Value::Null);
    assert_eq!(
        row.result_at(8),
        &json!(["Fulcrum 1.12.0", "1.4"]),
        "every other member answered"
    );
    row.is_a_round_trip();
}

/// ElectrumX's objection to a second handshake, which is one of the strings
/// the fingerprint set exists to collect.
#[tokio::test]
async fn the_fingerprint_set_records_an_already_handshaked_version() {
    let server = MockServer::start(Behaviour::default().require_version_first()).await;
    let (client, _notifications) = connect(&server, PATIENCE).await;
    soon(
        "the handshake",
        client.call("server.version", json!(["electrum-observer/0.1.0", "1.4"])),
    )
    .await
    .expect("the handshake is answered")
    .outcome
    .expect("the first server.version is accepted");

    let result = soon(
        "the fingerprint set",
        probes::run(&client, ProbeKind::Fingerprint, IDS, ProbeArgs::default()),
    )
    .await;
    let row = row(&result);
    assert_eq!(
        row.error_at(8),
        &rpc_error(BAD_REQUEST, "server.version already sent")
    );
    assert_eq!(row.result_at(8), &Value::Null);
}

/// The advertisement graph of DESIGN.md section 4, out of the same answer
/// the row keeps whole.
#[tokio::test]
async fn a_peer_list_becomes_edges_beside_the_row() {
    let (_server, result) = probe(Behaviour::default(), ProbeKind::Peers).await;
    match result.peer_edges.as_ref().expect("edges were advertised") {
        Event::PeerEdges {
            probe_id,
            from_server_id,
            edges,
        } => {
            assert_eq!((*probe_id, *from_server_id), (41, 9));
            assert_eq!(
                edges,
                &vec![
                    PeerEdge {
                        peer_host: "electrum.example.com".to_string(),
                        peer_ip: Some("104.198.149.61".to_string()),
                        features: vec![
                            "v1.4".to_string(),
                            "s50002".to_string(),
                            "t50001".to_string(),
                        ],
                    },
                    PeerEdge {
                        peer_host: "fulcrum.example.de".to_string(),
                        peer_ip: Some("2a01:4f8:c17:3f6f::1".to_string()),
                        features: vec!["v1.4.5".to_string(), "s50002".to_string()],
                    },
                    PeerEdge {
                        peer_host: "electrum.example.fr".to_string(),
                        peer_ip: Some("91.121.108.61".to_string()),
                        features: vec!["v1.4".to_string(), "t50001".to_string()],
                    },
                ]
            );
        }
        other => panic!("peer edges are peer edges, not {other:?}"),
    }
}

/// A peer list nobody can read is still an answer: the row keeps it whole,
/// and the graph gains nothing.
#[tokio::test]
async fn an_unreadable_peer_list_yields_no_edges_and_still_a_row() {
    let junk = json!(["not a row", {"host": "example.com"}, []]);
    let (_server, result) = probe(
        Behaviour::default().on("server.peers.subscribe", Reaction::Result(junk.clone())),
        ProbeKind::Peers,
    )
    .await;
    assert_eq!(result.peer_edges, None);
    assert_eq!(row(&result).result, Some(&junk));
}

/// Only the peer list produces edges; a probe of any other kind is a row and
/// nothing else, whatever its answer happens to look like.
#[tokio::test]
async fn no_other_kind_produces_edges() {
    let peers = Behaviour::default().peers.clone();
    let (_server, result) = probe(
        // An answer shaped exactly like a peer list, from a method that is
        // not one.
        Behaviour::default().on("server.features", Reaction::Result(peers)),
        ProbeKind::Features,
    )
    .await;
    assert_eq!(result.peer_edges, None);
}

/// A connection that is gone is recorded, not raised: what a dead socket
/// means is the session's decision (DESIGN.md section 5 step 7).
#[tokio::test]
async fn a_closed_connection_is_a_row_rather_than_a_failure() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server, IMPATIENCE).await;
    // The connection has to exist before it can be dropped.
    soon("a first answer", client.call("server.ping", json!([])))
        .await
        .expect("the server is up");
    server.disconnect_all();
    soon("the close to be noticed", client.closed()).await;

    let result = soon(
        "a probe on a dead connection",
        probes::run(&client, ProbeKind::Features, IDS, ProbeArgs::default()),
    )
    .await;
    let row = row(&result);
    assert_eq!(row.result, None);
    assert_eq!(row.recv_at, None);
    assert_eq!(row.rtt_us, None);
    let error = row.error_at(0);
    assert!(
        error.get("transport").and_then(Value::as_str).is_some(),
        "a closed connection is a transport error: {error}"
    );
}

/// The raw requests fail the same way as the ordinary ones when there is no
/// socket left to write to: a set on a dead connection is nine transport
/// errors and not a panic, whichever way each of them was going to be sent.
#[tokio::test]
async fn a_closed_connection_fails_the_raw_requests_too() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server, IMPATIENCE).await;
    soon("a first answer", client.call("server.ping", json!([])))
        .await
        .expect("the server is up");
    server.disconnect_all();
    soon("the close to be noticed", client.closed()).await;

    let result = soon(
        "a fingerprint set on a dead connection",
        probes::run(&client, ProbeKind::Fingerprint, IDS, ProbeArgs::default()),
    )
    .await;
    let row = row(&result);
    assert_eq!(row.recv_at, None);
    for index in 0..9 {
        let error = row.error_at(index);
        assert!(
            error.get("transport").and_then(Value::as_str).is_some(),
            "request {index} is a transport error: {error}"
        );
        assert_eq!(row.result_at(index), &Value::Null);
    }
}
