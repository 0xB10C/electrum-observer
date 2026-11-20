//! The binary: the CLI, and what only a process can do before the collector
//! runs.
//!
//! Read the configuration, build the runtime, install a subscriber, make room
//! for the descriptors, arm the stop signal. Everything else is in the
//! library, so that the end-to-end tests can drive the collector in process
//! against mock servers (DESIGN.md section 3).
//!
//! One subcommand so far. `run` sets everything up and returns, because
//! `run()` itself arrives with step 14 of `PLAN.md`; `import` and `servers`
//! arrive with the sources and the supervisor they report on, in steps 13 and
//! 14.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use electrum_observer::{Settings, Shutdown, TARGET_MAIN, fdlimit, logging};
use tracing::info;

/// The arguments that change per invocation. Everything else is in the
/// configuration file (DESIGN.md section 8).
#[derive(Debug, Parser)]
#[command(
    version,
    about = "Watches public Electrum servers and records what they answer."
)]
struct Cli {
    /// The YAML configuration file. See config-example.yaml.
    // Global and defaulted, because every subcommand needs it and because the
    // common case is a daemon started by a unit file that names one.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "config.yaml",
        global = true
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Connect to every enabled server and collect until stopped.
    Run,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` arrive here too; they are not
            // failures, and clap knows which stream each one belongs on.
            let failed = error.use_stderr();
            let _ = error.print();
            return if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    match tokio_runtime().and_then(|tokio| tokio.block_on(start(cli))) {
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

/// Which subcommand was asked for.
async fn start(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run => run(&cli.config).await,
    }
}

/// Everything that can fail before the collecting begins, in the order it has
/// to happen: read the configuration, start logging, make room for the
/// sessions, arm the stop signal.
async fn run(config: &Path) -> Result<()> {
    // Loading validates, so a level that is not a level is a configuration
    // error here rather than a filter that quietly drops lines below.
    let settings = Settings::load(config)?;

    logging::init(&settings.log)?;

    // Before anything opens a socket: the descriptor limit is what decides
    // whether every configured server can be connected at once (see
    // `fdlimit`).
    if let Err(reason) = fdlimit::prepare(settings.max_sessions()) {
        bail!(reason);
    }

    // Nothing watches the flag yet. Installed anyway, and here rather than in
    // the collector, because the handlers have to be registered before the
    // work starts (see `Shutdown::install`).
    let _shutdown = Shutdown::install().context("installing the signal handlers")?;

    // The database and the cap, because those are what an operator checks
    // first in a log that is otherwise about servers: whether the daemon is
    // writing where they think it is, and how many servers it will hold open.
    info!(
        target: TARGET_MAIN,
        version = env!("CARGO_PKG_VERSION"),
        config = %config.display(),
        database = %settings.database.display(),
        max_servers = settings.discovery.max_servers,
        max_sessions = settings.max_sessions(),
        "electrum-observer starting"
    );
    Ok(())
}
