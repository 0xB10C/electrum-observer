//! The binary: the CLI, and what only a process can do before the collector
//! runs.
//!
//! Read the configuration, build the runtime, install a subscriber, make room
//! for the descriptors, arm the stop signal. Everything else is in the
//! library, so that the end-to-end tests can drive the collector in process
//! against mock servers.
//!
//! Three subcommands. `run` sets all of that up and hands the configuration
//! and the stop flag to [`electrum_observer::run::run`], which is the
//! collector; `import` fills the `servers` table from the sources of
//! `seeds`, and `servers` prints what is in it.
//!
//! `import` and `servers` are the pair that makes an import checkable: one
//! writes rows, the other says which rows are there and where each came from,
//! in a shape that can be piped into `grep` and `cut` rather than into
//! `sqlite3`. Both write their result to stdout and log to the subscriber, so
//! a count never arrives mixed into a log line.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use electrum_observer::store::Store;
use electrum_observer::{Endpoint, Settings, Shutdown, TARGET_MAIN, fdlimit, logging, run, seeds};
use tracing::{debug, info};

/// The arguments that change per invocation. Everything else is in the
/// configuration file.
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

    /// Add servers from a seed source to the database.
    Import {
        #[command(subcommand)]
        source: Source,
    },

    /// Print every known server, one per line.
    Servers,
}

/// Where an import reads its endpoints from.
///
/// One subcommand per source rather than a `--from` with three values,
/// because the file source takes a path and the others do not, and clap can
/// say that for us.
#[derive(Debug, Subcommand)]
enum Source {
    /// The server table at 1209k.com. Mainnet only, and the one command here
    /// that touches the network.
    #[command(name = "1209k")]
    Table1209k,

    /// The public servers Sparrow Wallet ships, for the configured chain.
    Sparrow,

    /// A file of endpoints, one per line, `#` for comments.
    File {
        /// The list to read. Either spelling: ssl://host:port or host:port:s.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` arrive here too; they are not
            // failures, and clap knows which stream each one belongs on and
            // which code the shell should see for each: 2 for a usage error,
            // which is what every getopt-shaped tool returns and what a shell
            // script tells from the 1 of a run that started and failed, and 0
            // for the help it was asked to print.
            let _ = error.print();
            let code = u8::try_from(error.exit_code()).unwrap_or(2);
            return ExitCode::from(code);
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
        Command::Import { source } => import(&cli.config, source),
        Command::Servers => servers(&cli.config),
    }
}

/// Everything that can fail before the collecting begins, in the order it has
/// to happen: read the configuration, start logging, make room for the
/// sessions, arm the stop signal. Then [`electrum_observer::run::run`], which
/// returns when that signal has arrived and everything observed has been
/// written.
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

    // Installed here rather than in the collector because the handlers have
    // to be registered before the work starts: a SIGTERM arriving while the
    // database is being opened must flip the flag the sessions are about to
    // watch, not kill the process (see `Shutdown::install`).
    let shutdown = Shutdown::install().context("installing the signal handlers")?;

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

    run::run(settings, shutdown).await
}

/// `import`: read a seed source and write what it names into `servers`.
///
/// Blocking inside an async function on purpose: this is a command someone
/// typed, there is nothing else on the runtime to starve, and the one request
/// it may make is a single page fetch whose timeout is in `seeds`.
///
/// Nothing is capped. `discovery.max_servers` is about peer lists, which are
/// unbounded and partly stale; a seed list is what the operator asked to be
/// watched, and a cap applied to it would silently disable the servers an
/// experiment was set up for. Nothing is enabled again either:
/// `upsert_server` returns an existing row untouched, so a server disabled by
/// hand stays disabled through the next import.
fn import(config: &Path, source: Source) -> Result<()> {
    let settings = Settings::load(config)?;
    logging::init(&settings.log)?;

    // `skipped` is the source's own: rows of the 1209k table whose host, port
    // and transport were not an endpoint. A file has none, because a line
    // that is not an endpoint fails the import rather than being dropped, and
    // the built-in list has none by construction.
    let (name, endpoints, skipped): (&str, Vec<Endpoint>, usize) = match source {
        Source::Table1209k => {
            let html = seeds::fetch_1209k(settings.chain)?;
            let table = seeds::parse_1209k_table(&html)?;
            let endpoints = table.rows.into_iter().map(|row| row.endpoint).collect();
            (seeds::SOURCE_1209K, endpoints, table.skipped)
        }
        Source::Sparrow => (seeds::SOURCE_SPARROW, seeds::sparrow(settings.chain), 0),
        Source::File { path } => (seeds::SOURCE_FILE, seeds::from_file(&path)?, 0),
    };

    let store = Store::open(&settings.database)?;
    // The ids that existed before this import, so that "added" is what this
    // command inserted and not what the source happened to name. An endpoint
    // a source lists twice is counted once as added and once as known, which
    // is what it is.
    let mut known_ids: HashSet<i64> = store
        .servers()
        .context("reading the known servers")?
        .into_iter()
        .map(|row| row.id)
        .collect();

    let mut added = 0usize;
    let mut known = 0usize;
    for endpoint in &endpoints {
        let row = store
            .upsert_server(endpoint, name, None)
            .with_context(|| format!("adding {endpoint}"))?;
        if known_ids.insert(row.id) {
            added += 1;
        } else {
            known += 1;
        }
    }

    debug!(
        target: TARGET_MAIN,
        source = name,
        database = %settings.database.display(),
        added,
        known,
        skipped,
        "import finished",
    );
    println!("added {added}, already known {known}, skipped {skipped}");
    Ok(())
}

/// `servers`: one line per row of the `servers` table.
///
/// Tab separated and in no one's idea of a table layout, because what this
/// output is for is `grep`, `cut` and `wc -l`: which servers an import added,
/// which source named a host, which rows are disabled and why. The columns
/// are the ones that identify and gate a server, in that order, and a column
/// with nothing in it is a `-` rather than an empty field so that every line
/// has the same number of fields.
fn servers(config: &Path) -> Result<()> {
    let settings = Settings::load(config)?;
    logging::init(&settings.log)?;

    let store = Store::open(&settings.database)?;
    let rows = store.servers().context("reading the known servers")?;
    for row in &rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        let reason = row.disabled_reason.as_deref().unwrap_or("-");
        println!(
            "{id}\t{endpoint}\t{source}\t{state}\t{reason}",
            id = row.id,
            endpoint = row.endpoint,
            source = row.source,
        );
    }
    debug!(
        target: TARGET_MAIN,
        database = %settings.database.display(),
        servers = rows.len(),
        "servers listed",
    );
    Ok(())
}
