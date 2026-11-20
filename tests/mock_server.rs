//! The mock Electrum server, exercised through the client that will use it.
//!
//! The harness of `tests/common/mock_server.rs` is the foundation of every
//! integration test from step 7 of `PLAN.md` onwards, which means a bug in it
//! would show up as a failure somewhere else entirely -- a session test that
//! fails because the server never sent the notification, not because the
//! session missed it. So it is tested the way it will be used: over a real
//! TCP socket, through `electrum_observer::jsonrpc::Client`, asserting on
//! what the client makes of the answers rather than on the harness's own
//! internals.
//!
//! That also makes these tests the first end-to-end exercise of the client
//! against a socket instead of a `duplex` pipe, which is where a framing
//! mistake -- a missing newline, a flush that never happens -- would hide.

mod common;

use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::net::TcpStream;

use electrum_observer::jsonrpc::{Client, Error, Notification, Notifications, Response};
use electrum_observer::settings::Chain;

use common::mock_server::{
    BAD_REQUEST, BLOCK_1_HEADER, Behaviour, GENESIS_COINBASE_TXID, GENESIS_HEADER, MockServer,
    Reaction, header_hash, rpc_error,
};

/// How long any wait here may take before it is a failure.
///
/// Every await below is bounded by it: a test that hangs says nothing, and a
/// suite that hangs is one no amount of reruns makes flaky-or-not decidable.
/// Generous, because loopback is not where the time goes.
const PATIENCE: Duration = Duration::from_secs(5);

/// A request timeout short enough to be waited out on purpose.
const IMPATIENCE: Duration = Duration::from_millis(300);

async fn soon<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("waited {PATIENCE:?} for {what}"))
}

/// Dials the mock and hands back a client speaking to it.
async fn connect(server: &MockServer) -> (Client, Notifications) {
    connect_with(server, PATIENCE).await
}

async fn connect_with(server: &MockServer, request_timeout: Duration) -> (Client, Notifications) {
    let stream = soon("a connection", TcpStream::connect(server.addr()))
        .await
        .expect("the mock server is listening");
    Client::new(stream, request_timeout)
}

/// Calls and insists on a `result`.
async fn ask(client: &Client, method: &str, params: Value) -> Value {
    let response = soon(method, client.call(method, params))
        .await
        .unwrap_or_else(|e| panic!("{method} reached the server: {e}"));
    response
        .outcome
        .unwrap_or_else(|e| panic!("{method} answered a result, not {e:?}"))
}

/// Calls and insists on an `error`, returning its code and message.
async fn ask_err(client: &Client, method: &str, params: Value) -> (Option<i64>, String) {
    let response: Response = soon(method, client.call(method, params))
        .await
        .unwrap_or_else(|e| panic!("{method} reached the server: {e}"));
    let error = response
        .outcome
        .expect_err("the server was configured to answer an error");
    (error.code, error.message)
}

async fn next_notification(notifications: &mut Notifications) -> Notification {
    soon("a notification", notifications.recv())
        .await
        .expect("the connection is still open")
}

/// Every method the collector sends, answered from the defaults.
///
/// One test rather than thirteen because what is being checked is that the
/// canned table is wired to the right method names and shapes; a wrong one
/// here is a typo, and a typo does not need its own name.
#[tokio::test]
async fn canned_answers_round_trip() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server).await;

    assert_eq!(
        ask(
            &client,
            "server.version",
            json!(["electrum-observer/0.1.0", "1.4"])
        )
        .await,
        json!(["Fulcrum 1.12.0", "1.4"]),
    );

    let features = ask(&client, "server.features", json!([])).await;
    assert_eq!(
        features["genesis_hash"],
        json!(Chain::Mainnet.genesis_hash().to_string()),
        "the default server is on the chain the collector defaults to, so a \
         genesis check against it passes",
    );
    assert_eq!(features["pruning"], Value::Null);
    assert_eq!(features["protocol_min"], json!("1.4"));
    assert!(features["hosts"].is_object());

    assert!(
        ask(&client, "server.banner", json!([]))
            .await
            .as_str()
            .expect("a banner is a string")
            .contains("Fulcrum")
    );
    assert!(
        ask(&client, "server.donation_address", json!([]))
            .await
            .as_str()
            .expect("an address is a string")
            .starts_with('1')
    );
    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);

    let peers = ask(&client, "server.peers.subscribe", json!([])).await;
    let rows = peers.as_array().expect("peers is a list of rows");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0][1], json!("electrum.example.com"));
    assert_eq!(rows[0][2], json!(["v1.4", "s50002", "t50001"]));

    assert_eq!(
        ask(&client, "blockchain.relayfee", json!([])).await,
        json!(0.00001)
    );
    let histogram = ask(&client, "mempool.get_fee_histogram", json!([])).await;
    assert_eq!(histogram[0], json!([12, 128_812]));
    assert_eq!(
        ask(&client, "mempool.get_info", json!([])).await["mempoolminfee"],
        json!(0.00001),
    );

    assert_eq!(
        ask(&client, "blockchain.estimatefee", json!([2])).await,
        json!(0.00015)
    );
    assert_eq!(
        ask(&client, "blockchain.estimatefee", json!([100_000])).await,
        json!(-1),
        "an unknown target is the -1 a server with no estimate answers",
    );

    assert_eq!(
        ask(&client, "blockchain.headers.subscribe", json!([])).await,
        json!({ "height": 1, "hex": BLOCK_1_HEADER }),
    );
    assert_eq!(
        ask(&client, "blockchain.block.header", json!([0])).await,
        json!(GENESIS_HEADER),
    );
    assert_eq!(
        ask(&client, "blockchain.transaction.id_from_pos", json!([0, 0])).await,
        json!(GENESIS_COINBASE_TXID),
    );
}

/// The default headers are the real mainnet ones, hash and all.
///
/// Worth its own test because the whole point of using real data is that a
/// later test can assert on a hash it looked up elsewhere; if the constants
/// were ever edited into something that merely looks like a header, every one
/// of those tests would still pass against each other.
#[tokio::test]
async fn the_default_chain_is_the_real_one() {
    assert_eq!(
        header_hash(GENESIS_HEADER),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
    assert_eq!(
        header_hash(BLOCK_1_HEADER),
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    );
    assert_eq!(
        header_hash(GENESIS_HEADER),
        Chain::Mainnet.genesis_hash().to_string(),
    );
}

/// An announcement reaches every subscriber, and only subscribers.
#[tokio::test]
async fn an_announcement_reaches_every_subscriber() {
    let server = MockServer::start(Behaviour::default()).await;
    let (first, mut first_notifications) = connect(&server).await;
    let (second, mut second_notifications) = connect(&server).await;
    // A third connection that never subscribes: a server pushing headers at
    // it would be a server no session can be written against.
    let (silent, mut silent_notifications) = connect(&server).await;

    for client in [&first, &second] {
        assert_eq!(
            ask(client, "blockchain.headers.subscribe", json!([])).await["height"],
            json!(1),
        );
    }
    ask(&silent, "server.ping", json!([])).await;
    assert_eq!(server.connection_count(), 3);

    let announced = server.announce_header(2, GENESIS_HEADER);
    assert_eq!(
        announced, 2,
        "the unsubscribed connection is not announced to"
    );

    for notifications in [&mut first_notifications, &mut second_notifications] {
        let notification = next_notification(notifications).await;
        assert_eq!(notification.method, "blockchain.headers.subscribe");
        assert_eq!(
            notification.params,
            json!([{ "height": 2, "hex": GENESIS_HEADER }]),
        );
    }

    // The tip moved for whoever subscribes next, which is how a reconnecting
    // session catches up on what it missed.
    assert_eq!(
        ask(&silent, "blockchain.headers.subscribe", json!([])).await,
        json!({ "height": 2, "hex": GENESIS_HEADER }),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), silent_notifications.recv())
            .await
            .is_err(),
        "the connection that subscribed after the announcement is not sent it",
    );
}

/// `set_header` finishes what `announce_header` starts: a reorg.
#[tokio::test]
async fn a_reorg_is_an_announcement_then_a_changed_answer() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, mut notifications) = connect(&server).await;
    ask(&client, "blockchain.headers.subscribe", json!([])).await;

    // A different header announced at a height that was already announced:
    // the server is on another branch now, but still answers the old one when
    // polled, which is the window a divergence poll can land in.
    server.announce_header(1, GENESIS_HEADER);
    let notification = next_notification(&mut notifications).await;
    assert_eq!(notification.params[0]["hex"], json!(GENESIS_HEADER));
    assert_eq!(
        ask(&client, "blockchain.block.header", json!([1])).await,
        json!(BLOCK_1_HEADER),
    );

    server.set_header(1, GENESIS_HEADER);
    assert_eq!(
        ask(&client, "blockchain.block.header", json!([1])).await,
        json!(GENESIS_HEADER),
        "after the switch the polled answer is the announced branch",
    );
}

/// ElectrumX's handshake rule, both halves of it.
#[tokio::test]
async fn require_version_first_refuses_both_ways() {
    let server = MockServer::start(Behaviour::default().require_version_first()).await;
    let (client, _notifications) = connect(&server).await;

    let (code, message) = ask_err(&client, "server.banner", json!([])).await;
    assert_eq!(code, Some(BAD_REQUEST));
    assert_eq!(
        message,
        "use server.version to declare your protocol version first"
    );

    let version = json!(["electrum-observer/0.1.0", "1.4"]);
    assert_eq!(
        ask(&client, "server.version", version.clone()).await,
        json!(["Fulcrum 1.12.0", "1.4"]),
    );
    // Now that the handshake is done, the method that was refused works.
    assert!(ask(&client, "server.banner", json!([])).await.is_string());

    let (code, message) = ask_err(&client, "server.version", version).await;
    assert_eq!(code, Some(BAD_REQUEST));
    assert_eq!(message, "server.version already sent");
}

/// The errors a server answers rather than failing on, which DESIGN.md
/// section 6 collects as data.
#[tokio::test]
async fn errors_are_answers() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server).await;

    let (code, message) = ask_err(&client, "blockchain.scripthash.subscribe", json!([])).await;
    assert_eq!(code, Some(-32601));
    assert_eq!(message, "unknown method");

    let (code, message) = ask_err(&client, "blockchain.block.header", json!([99])).await;
    assert_eq!(code, Some(BAD_REQUEST));
    assert_eq!(message, "height 99 out of range");

    let (code, message) = ask_err(&client, "blockchain.estimatefee", json!([])).await;
    assert_eq!(code, Some(-32602));
    assert_eq!(message, "invalid parameters: expected a block target");

    let (code, message) =
        ask_err(&client, "blockchain.transaction.id_from_pos", json!([7, 0])).await;
    assert_eq!(code, Some(BAD_REQUEST));
    assert_eq!(message, "no tx at position 0 in block at height 7");

    // An override replaces any of them with the exact string a test is
    // fingerprinting for.
    let server = MockServer::start(Behaviour::default().on(
        "server.banner",
        Reaction::Error(rpc_error(1, "banner is disabled")),
    ))
    .await;
    let (client, _notifications) = connect(&server).await;
    let (code, message) = ask_err(&client, "server.banner", json!([])).await;
    assert_eq!(code, Some(1));
    assert_eq!(message, "banner is disabled");
}

/// A method that is never answered is a timeout, not a disconnection.
///
/// The distinction is the whole reason `timeouts.request_secs` bounds one
/// request rather than the connection: the subscription has to survive a
/// probe that went unanswered.
#[tokio::test]
async fn a_method_that_never_answers_times_out() {
    let server =
        MockServer::start(Behaviour::default().on("mempool.get_info", Reaction::Never)).await;
    let (client, _notifications) = connect_with(&server, IMPATIENCE).await;

    let outcome = soon(
        "the request timeout",
        client.call("mempool.get_info", json!([])),
    )
    .await;
    assert!(
        matches!(outcome, Err(Error::Timeout)),
        "a silent method times out: {outcome:?}",
    );

    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);
    assert_eq!(
        server.connection_count(),
        1,
        "the connection survived the unanswered request",
    );
}

/// A delayed answer arrives late and in its own time.
#[tokio::test]
async fn a_delayed_answer_still_arrives() {
    let delay = Duration::from_millis(250);
    let server =
        MockServer::start(Behaviour::default().on("mempool.get_info", Reaction::Delay(delay)))
            .await;
    let (client, _notifications) = connect(&server).await;

    let started = Instant::now();
    let slow = tokio::spawn({
        let client = client.clone();
        async move { client.call("mempool.get_info", json!([])).await }
    });
    // The connection is not blocked while the delayed answer is pending: a
    // server that stopped reading is a different failure from a slow one.
    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);

    let response = soon("the delayed answer", slow)
        .await
        .expect("the task ran")
        .expect("the call reached the server");
    assert!(response.outcome.is_ok());
    assert!(
        started.elapsed() >= delay,
        "the answer waited: {:?}",
        started.elapsed(),
    );
}

/// Junk before the first reply is counted and survived.
#[tokio::test]
async fn junk_lines_are_counted_not_fatal() {
    let server = MockServer::start(Behaviour::default().junk_lines(&[
        "Welcome to the mock server",
        "",
        "<html>",
    ]))
    .await;
    let (client, _notifications) = connect(&server).await;

    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);
    assert_eq!(
        client.malformed_lines(),
        3,
        "the junk was read and counted before the reply that followed it",
    );
}

/// A line that is not JSON is a parse error, not a closed connection.
#[tokio::test]
async fn a_line_that_is_not_json_is_a_parse_error() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server).await;

    let raw = soon("the parse error", client.call_raw("not json at all", &[]))
        .await
        .expect("the line was written");
    assert!(raw.complete);
    let answer: Value = serde_json::from_str(&raw.lines[0].text).expect("the server answers JSON");
    assert_eq!(answer["error"]["code"], json!(-32700));
    assert_eq!(answer["id"], Value::Null);

    // And the connection is still usable, which is the half that matters.
    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);
    let recorded = server.requests();
    assert_eq!(recorded[0].raw, "not json at all");
    assert_eq!(recorded[0].method, "", "an unparseable line has no method");
}

/// A batch is an array of answers, or a refusal, depending on the knob.
#[tokio::test]
async fn a_batch_is_answered_or_refused() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server).await;
    let (first, second) = (client.next_id(), client.next_id());
    let batch = json!([
        { "jsonrpc": "2.0", "id": first, "method": "server.banner", "params": [] },
        { "jsonrpc": "2.0", "id": second, "method": "server.ping", "params": [] },
    ])
    .to_string();

    let raw = soon("the batch", client.call_raw(&batch, &[first, second]))
        .await
        .expect("the batch was written");
    assert!(raw.complete, "both ids came back");
    let answers: Value = serde_json::from_str(&raw.lines[0].text).expect("one array, one line");
    let answers = answers.as_array().expect("a batch answers an array");
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["id"], json!(first));
    assert_eq!(answers[1]["result"], Value::Null);

    let server = MockServer::start(Behaviour::default().batches(false)).await;
    let (client, _notifications) = connect(&server).await;
    let raw = soon("the refusal", client.call_raw(&batch, &[]))
        .await
        .expect("the batch was written");
    let answer: Value = serde_json::from_str(&raw.lines[0].text).expect("the server answers JSON");
    assert_eq!(answer["error"]["code"], json!(-32600));
    assert_eq!(
        answer["error"]["message"],
        json!("batches are not supported")
    );
    assert_eq!(
        server.requests().len(),
        2,
        "a refused batch still records both of its requests",
    );
}

/// What was sent, in order, with its ids and parameters.
///
/// This is the assertion surface for every later test about *what a session
/// asks and when*: the handshake first, the initial probe set, the
/// subscription (DESIGN.md section 5).
#[tokio::test]
async fn requests_records_what_was_sent() {
    let server = MockServer::start(Behaviour::default()).await;
    let (first, _first_notifications) = connect(&server).await;
    ask(
        &first,
        "server.version",
        json!(["electrum-observer/0.1.0", "1.4"]),
    )
    .await;
    ask(&first, "blockchain.estimatefee", json!([6, "ECONOMICAL"])).await;

    let (second, _second_notifications) = connect(&server).await;
    ask(&second, "server.ping", json!([])).await;

    let recorded = server.requests();
    let methods: Vec<&str> = recorded.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(
        methods,
        ["server.version", "blockchain.estimatefee", "server.ping"],
        "in arrival order across connections",
    );

    assert_eq!(recorded[0].id, Some(json!(1)));
    assert_eq!(recorded[1].id, Some(json!(2)));
    assert_eq!(
        recorded[1].params,
        json!([6, "ECONOMICAL"]),
        "parameters are kept verbatim, mode and all",
    );
    assert!(
        recorded[1]
            .raw
            .contains("\"method\":\"blockchain.estimatefee\"")
    );
    assert_eq!(recorded[0].connection, 0);
    assert_eq!(
        recorded[2].connection, 1,
        "connections are numbered in accept order"
    );
    assert!(recorded[0].at <= recorded[2].at);
}

/// `disconnect_all` is what a server going away looks like to the client.
#[tokio::test]
async fn disconnect_all_closes_the_client() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, mut notifications) = connect(&server).await;
    ask(&client, "server.ping", json!([])).await;
    assert_eq!(server.connection_count(), 1);

    let closed = client.closed();
    server.disconnect_all();
    assert_eq!(server.connection_count(), 0);

    let reason = soon("the close", closed).await;
    assert_eq!(reason, "eof", "the client saw the socket end: {reason}");
    assert!(
        soon("the end of the stream", notifications.recv())
            .await
            .is_none(),
        "the notification stream ends with the connection",
    );

    // The listener is still up, so a session can reconnect to the same
    // address -- which is what the backoff test of step 10 needs.
    let (again, _notifications) = connect(&server).await;
    assert_eq!(ask(&again, "server.ping", json!([])).await, Value::Null);
    assert_eq!(server.connection_count(), 1);
}

/// `shutdown` takes the listener with it.
#[tokio::test]
async fn shutdown_stops_the_listener() {
    let server = MockServer::start(Behaviour::default()).await;
    let addr = server.addr();
    let (client, _notifications) = connect(&server).await;
    ask(&client, "server.ping", json!([])).await;

    server.shutdown();
    assert_eq!(server.connection_count(), 0);
    assert!(
        soon(
            "the connection to fail",
            client.call("server.ping", json!([]))
        )
        .await
        .is_err(),
        "the connection went with the server",
    );

    // A connect to a listener that is gone either fails outright or is
    // accepted by a backlog nobody is reading; either way nothing answers.
    if let Ok(stream) = soon("a dial", TcpStream::connect(addr)).await {
        let (orphan, _notifications) = Client::new(stream, IMPATIENCE);
        assert!(
            soon("the orphan call", orphan.call("server.ping", json!([])))
                .await
                .is_err(),
            "a shut-down server answers nothing",
        );
    }
}

/// A server that is not the default one: another implementation, another
/// position on the chain, another answer to a method the defaults cover.
///
/// The builders exist so that a test which cares about one server among
/// several -- two mock servers, one announcing a fork, as the end-to-end test
/// of step 14 runs -- can say what makes them different and nothing else.
#[tokio::test]
async fn a_behaviour_can_be_built_to_order() {
    // A server that has the genesis block and nothing after it: a real state
    // for a freshly started backend, and one a session must survive.
    let server = MockServer::start(
        Behaviour::default()
            .version("ElectrumX 1.16.0", "1.4")
            .tip(0, GENESIS_HEADER)
            .header(0, GENESIS_HEADER)
            .txid(0, 0, GENESIS_COINBASE_TXID)
            // The `{"data": ...}` pong of the protocol documentation, which
            // is what `Reaction::Result` is for: a shape the harness has no
            // canned answer for.
            .on("server.ping", Reaction::Result(json!({ "data": "" }))),
    )
    .await;
    let (client, _notifications) = connect(&server).await;

    assert_eq!(
        ask(
            &client,
            "server.version",
            json!(["electrum-observer/0.1.0", "1.4"])
        )
        .await,
        json!(["ElectrumX 1.16.0", "1.4"]),
    );
    assert_eq!(
        ask(&client, "blockchain.headers.subscribe", json!([])).await,
        json!({ "height": 0, "hex": GENESIS_HEADER }),
    );
    assert_eq!(
        ask(&client, "blockchain.transaction.id_from_pos", json!([0, 0])).await,
        json!(GENESIS_COINBASE_TXID),
    );
    assert_eq!(
        ask(&client, "server.ping", json!([])).await,
        json!({ "data": "" }),
    );

    // Two of the fingerprint probes of DESIGN.md section 6: a height passed
    // as a string, and a call with the wrong number of parameters.
    let (code, message) = ask_err(&client, "blockchain.block.header", json!(["0"])).await;
    assert_eq!(code, Some(-32602));
    assert_eq!(message, "invalid parameters: expected a height");
    let (code, message) = ask_err(&client, "blockchain.transaction.id_from_pos", json!([0])).await;
    assert_eq!(code, Some(-32602));
    assert_eq!(
        message,
        "invalid parameters: expected a height and a position"
    );
}

/// A server can change its mind while a session is connected.
///
/// Which is the whole reason for the identity set of DESIGN.md section 6: a
/// banner edit is slow-moving data, and a test of it needs a server whose
/// banner moves.
#[tokio::test]
async fn set_behaviour_changes_the_answers_mid_connection() {
    let server = MockServer::start(Behaviour::default()).await;
    let (client, _notifications) = connect(&server).await;
    assert!(
        ask(&client, "server.banner", json!([]))
            .await
            .as_str()
            .expect("a banner is a string")
            .contains("Fulcrum")
    );

    // The plain-struct half of the API: everything else stays as it was.
    let edited = Behaviour {
        banner: "Donations keep this server running".to_string(),
        ..Behaviour::default()
    };
    server.set_behaviour(edited);

    assert_eq!(
        ask(&client, "server.banner", json!([])).await,
        json!("Donations keep this server running"),
    );
}

/// The request shapes that are not requests, answered as the specification
/// says and not by closing the connection.
#[tokio::test]
async fn odd_requests_are_answered_the_way_a_server_answers_them() {
    let server = MockServer::start(Behaviour::default()).await;
    // Short, because two of these are waits for an answer that never comes.
    let (client, _notifications) = connect_with(&server, IMPATIENCE).await;

    let answer = raw_answer(&client, "[]").await;
    assert_eq!(answer["error"]["code"], json!(-32600), "an empty batch");

    let answer = raw_answer(&client, r#"{"jsonrpc": "2.0", "id": 99}"#).await;
    assert_eq!(answer["error"]["code"], json!(-32600), "no method");
    assert_eq!(answer["id"], json!(99), "the id comes back even so");

    // A request without an id is a JSON-RPC notification, which a server
    // acts on and does not answer -- alone or inside a batch.
    for line in [
        r#"{"jsonrpc": "2.0", "method": "server.ping"}"#,
        r#"[{"jsonrpc": "2.0", "method": "server.ping"}]"#,
    ] {
        let raw = soon("the silence", client.call_raw(line, &[]))
            .await
            .expect("the line was written");
        assert!(!raw.complete, "a notification is not answered: {line}");
        assert!(raw.lines.is_empty());
    }

    // Every one of them was recorded, and the connection is still up.
    assert_eq!(server.requests().len(), 4);
    assert_eq!(ask(&client, "server.ping", json!([])).await, Value::Null);
}

/// Sends a line the client cannot build and parses the one answer to it.
async fn raw_answer(client: &Client, line: &str) -> Value {
    let raw = soon("an answer", client.call_raw(line, &[]))
        .await
        .expect("the line was written");
    assert!(raw.complete, "{line} was answered");
    serde_json::from_str(&raw.lines[0].text).expect("the server answers JSON")
}
