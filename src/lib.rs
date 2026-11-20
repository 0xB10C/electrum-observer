//! Watches public Electrum servers and records what they answer.
//!
//! The collector lives here rather than in the binary so that the end-to-end
//! tests can drive it in process against mock servers: the wiring between
//! discovery, sessions, probes and the store is only exercised by starting
//! it, and a unit test of any one part cannot see a channel plugged into the
//! wrong end.
//!
//! `DESIGN.md` is the authority on behaviour -- what is collected, why, and
//! into which table -- and `PLAN.md` is the order the modules arrive in.

pub mod dial;
pub mod discovery;
pub mod endpoint;
pub mod fdlimit;
pub mod headers;
pub mod jsonrpc;
pub mod logging;
pub mod probes;
pub mod seeds;
pub mod session;
pub mod settings;
pub mod shutdown;
pub mod store;

pub use endpoint::{Endpoint, Host, Network, Transport};
pub use settings::Settings;
pub use shutdown::Shutdown;

/// The binary itself: startup, the descriptor limit and the stop signal.
///
/// Tracing targets are stable names rather than module paths, which move
/// whenever a file does, so that one phase of a run can be turned up on its
/// own from the configuration (`log.targets` in `config-example.yaml`, which
/// lists the names). Each constant appears with the module
/// that logs under it; this one is not a module at all but the handful of
/// lines a process runs before and after the collection, and they log under a
/// name of their own so that `main: debug` says what startup did without
/// turning up everything else.
///
/// Public, unlike crawler's, because here the binary logs too: it is what
/// says the process started.
pub const TARGET_MAIN: &str = "main";

/// The database: the schema, the writer task and the few direct queries.
///
/// Its own target because what it logs is the shape of the collection rather
/// than any one server -- a batch that could not be committed, a row a
/// constraint refused -- and an operator chasing a database problem wants
/// `store: debug` without 450 sessions talking at the same time.
pub const TARGET_STORE: &str = "store";

/// The JSON-RPC client: what came back that nobody was waiting for.
///
/// Turned up (`jsonrpc: debug`) it names the answers that matched no pending
/// request and the lines that were not JSON at all -- the two things a server
/// can do that are neither an answer nor a disconnection, and that a session
/// otherwise never sees.
pub const TARGET_JSONRPC: &str = "jsonrpc";

/// Opening connections: what a name resolved to, what was dialed, and what
/// certificate came back.
///
/// Its own target because a dial is the one phase that fails for reasons
/// outside this process -- a name that stopped resolving, a port that started
/// refusing, a handshake that no longer completes -- and `dial: debug` is
/// how an operator tells "the server is gone" from "our resolver is". The
/// certificate is named by its fingerprint and never by its bytes.
pub const TARGET_DIAL: &str = "dial";

/// The seed sources: what was read, from where, and what was not readable.
///
/// Its own target because an import is a command somebody is watching rather
/// than a phase of a run: `seeds: debug` says how many rows the 1209k page
/// had and how many of them were not endpoints, which is the question asked
/// exactly when that page has changed shape.
pub const TARGET_SEEDS: &str = "seeds";

/// The probe sets: what a peer list was made of, beyond what the row keeps.
///
/// A probe answer is data and goes to the database rather than to the log,
/// so this is quiet by design. What it does say (`probes: debug`) is how
/// many of a `server.peers.subscribe` answer's rows were well formed and how
/// many were skipped, which is the one thing the `peer_edges` rows cannot
/// say about themselves: a server advertising fifty peers in a shape nobody
/// else uses leaves no row behind at all.
pub const TARGET_PROBES: &str = "probes";

/// Discovery: which advertised peers became servers, and which did not fit.
///
/// Its own target because what it says is about the shape of the run rather
/// than about any one connection -- how the monitored set grew, when it
/// stopped growing because `discovery.max_servers` was reached, and which
/// rows of a peer list were unreadable. At `info` it says only that new
/// servers were found; `discovery: debug` is what names every skipped row,
/// which is the level to run at when a peer list yields fewer servers than
/// it should.
pub const TARGET_DISCOVERY: &str = "discovery";

/// One connection's lifecycle: the handshake, the probes, the headers and
/// the reconnect.
///
/// The target an operator actually watches: `session: info` is one line for
/// every connection that comes up and one for every connection that ends,
/// carrying the server, the endpoint, the session index and the
/// `end_reason`, which together are the uptime of the whole collection as it
/// happens. `session: debug` adds what each connection did in between --
/// every header it was told about, every probe set that went out, every
/// reconnect delay -- and against six hundred servers that is a great deal
/// of it, which is why the two levels are separated here rather than sharing
/// a target with the dial.
pub const TARGET_SESSION: &str = "session";
