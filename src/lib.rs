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

pub mod endpoint;
pub mod fdlimit;
pub mod logging;
pub mod shutdown;

pub use endpoint::{Endpoint, Host, Network, Transport};
pub use shutdown::Shutdown;

/// The binary itself: startup, the descriptor limit and the stop signal.
///
/// Tracing targets are stable names rather than module paths, which move
/// whenever a file does, so that one phase of a run can be turned up on its
/// own once the configuration can ask for it (`log` in
/// `config-example.yaml`, from step 3). Each constant appears with the module
/// that logs under it; this one is not a module at all but the handful of
/// lines a process runs before and after the collection, and they log under a
/// name of their own so that `main: debug` says what startup did without
/// turning up everything else.
///
/// Public, unlike crawler's, because here the binary logs too: it is what
/// says the process started.
pub const TARGET_MAIN: &str = "main";
