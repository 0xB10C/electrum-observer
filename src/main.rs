//! The binary: what only a process can do before the collector runs.
//!
//! Build the runtime, install a subscriber, make room for the descriptors,
//! arm the stop signal. Everything else is in the library, so that the
//! end-to-end tests can drive the collector in process against mock servers
//! (DESIGN.md section 3).
//!
//! There is nothing to run yet. The clap CLI -- `run`, `import` and
//! `servers` -- arrives with the subcommands that need it, and `run()` with
//! step 14 of `PLAN.md`; until then this starts up, says so, and exits.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use electrum_observer::{Shutdown, TARGET_MAIN, fdlimit, logging};
use tracing::info;

/// What the log filter is set to until the config file sets it.
///
/// Step 3 replaces this with `log.level` and `log.targets` from the YAML.
const LOG_DIRECTIVES: &str = "info";

/// How many sessions the descriptor limit has to cover.
///
/// `discovery.max_servers` times `sessions_per_server`, which is 600 times 1
/// at the defaults of DESIGN.md section 8. A constant until step 3 can read
/// the two keys; the point of asking now is that the check happens before any
/// socket is opened, and that does not change when the numbers come from a
/// file.
const MAX_SESSIONS: usize = 600;

fn main() -> ExitCode {
    match tokio_runtime().and_then(|tokio| tokio.block_on(start())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Before the subscriber is installed there is nowhere else for
            // this to go, and after it the operator is still looking at the
            // terminal they typed into. The whole chain, because the context
            // is what says which file or which key was the problem.
            eprintln!("electrum-observer: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// The runtime the collector runs on: multi-thread, timers and I/O enabled.
///
/// Built by hand rather than by `#[tokio::main]` so that the knobs are this
/// crate's to set once there is a reason to set them. `#[tokio::test]` is
/// unaffected and keeps building a runtime of its own per test.
fn tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting a tokio runtime")
}

/// Everything that can fail before the collecting begins, in the order it has
/// to happen: start logging, make room for the sessions, arm the stop signal.
async fn start() -> Result<()> {
    logging::init(LOG_DIRECTIVES)?;

    // Before anything opens a socket: the descriptor limit is what decides
    // whether every configured server can be connected at once (see
    // `fdlimit`).
    if let Err(reason) = fdlimit::prepare(MAX_SESSIONS) {
        bail!(reason);
    }

    // Nothing watches the flag yet. Installed anyway, and here rather than in
    // `run()`, because the handlers have to be registered before the work
    // starts (see `Shutdown::install`).
    let _shutdown = Shutdown::install().context("installing the signal handlers")?;

    info!(
        target: TARGET_MAIN,
        version = env!("CARGO_PKG_VERSION"),
        "electrum-observer starting"
    );
    Ok(())
}
