//! The binary as an operator drives it: `import`, `servers`, and the exit
//! codes in between.
//!
//! Driven by running the built binary rather than by calling into the
//! library, because what is being pinned here is only true of a process: that
//! the counts go to stdout and the complaints to stderr, that a second import
//! of the same list adds nothing, that a bad line fails the command with the
//! line number in it, and that a subcommand nobody has is clap's usage error
//! and not a crash.
//!
//! Nothing here reaches further than loopback. `import 1209k` is the one
//! subcommand that would, and it is tested through `seeds`' parser against
//! the committed fixture instead; a test that fetches is a test that fails
//! when a website is down. The `run` test below does open a socket, to a
//! mock Electrum server this test process is itself hosting.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::mock_server::{Behaviour, MockServer};

/// Runs the binary with these arguments.
fn observer(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_electrum-observer"))
        .args(args)
        .output()
        .expect("the binary built by cargo runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// A configuration whose database is in the temporary directory, which is the
/// only key these subcommands read besides the chain.
fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("observer.yaml");
    let body = format!(
        "chain: mainnet\ndatabase: {}\n",
        dir.join("observer.sqlite").display()
    );
    std::fs::write(&path, body).expect("the temporary directory is writable");
    path
}

/// Writes a server list and returns its path.
fn write_list(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("servers.txt");
    std::fs::write(&path, body).expect("the temporary directory is writable");
    path
}

/// A path as the command line wants it.
fn arg(path: &Path) -> &str {
    path.to_str().expect("a utf-8 temporary path")
}

/// How long the `run` test waits for anything before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How often it looks again.
const TICK: Duration = Duration::from_millis(50);

/// A configuration for a `run`: one server from the list, every cadence at
/// the one second the file's resolution allows, no discovery and no Tor.
///
/// Discovery is off so that the only server this run can connect to is the
/// one in the list -- the mock advertises peers that do not exist, and a
/// `connections` row from a lookup of one of those would be a row this test
/// would have to tell apart from the row it is waiting for.
fn write_run_config(dir: &Path, database: &Path, servers_file: &Path) -> PathBuf {
    let path = dir.join("run.yaml");
    let body = format!(
        "chain: mainnet\n\
         database: {database}\n\
         servers_file: {servers_file}\n\
         timeouts: {{ connect_secs: 5, request_secs: 2 }}\n\
         reconnect: {{ min_secs: 1, max_secs: 2 }}\n\
         cadence: {{ ping_secs: 1, fees_secs: 60, identity_secs: 60, fingerprint_secs: 60 }}\n\
         discovery: {{ enabled: false }}\n\
         tor: {{ enabled: false }}\n\
         log: {{ level: info }}\n",
        database = database.display(),
        servers_file = servers_file.display(),
    );
    std::fs::write(&path, body).expect("the temporary directory is writable");
    path
}

/// The log the daemon wrote so far, which is empty until it writes a line.
fn read(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

/// How many connections the daemon has recorded, and 0 for a database it has
/// not created yet.
///
/// Attached only once the file exists, because opening it would otherwise
/// create an empty one at the path the daemon is about to create.
fn connections(database: &Path) -> i64 {
    if !database.exists() {
        return 0;
    }
    rusqlite::Connection::open(database)
        .and_then(|conn| {
            conn.query_row(
                "SELECT count(*) FROM connections WHERE connected_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
        })
        .unwrap_or(0)
}

/// Polls `ready` until it is true, or fails the test with the daemon's log.
async fn wait_for<F: FnMut() -> bool>(log: &Path, what: &str, mut ready: F) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if ready() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "waited {PATIENCE:?} for {what}: {}",
            read(log),
        );
        tokio::time::sleep(TICK).await;
    }
}

/// The daemon as a child process, killed on the way out however the test
/// ends.
///
/// The `Drop` is the point: a test that fails before the signal is sent
/// would otherwise leave a collector running against a mock server that is
/// about to disappear, and the next test in this binary would be sharing the
/// machine with it.
struct Daemon(Child);

impl Daemon {
    /// Starts `run` with its log in a file rather than a pipe, so that
    /// nothing has to be read while the daemon is running: a full pipe would
    /// block the very process the test is waiting on.
    fn start(config: &Path, log: &Path) -> Daemon {
        let stderr = std::fs::File::create(log).expect("the log file is created");
        Daemon(
            Command::new(env!("CARGO_BIN_EXE_electrum-observer"))
                .args(["--config", arg(config), "run"])
                .stdout(Stdio::null())
                .stderr(Stdio::from(stderr))
                .spawn()
                .expect("the binary built by cargo runs"),
        )
    }

    /// Sends SIGTERM, as a unit file's `systemctl stop` does.
    ///
    /// Through `kill` rather than `libc`, because the one rule about
    /// `unsafe` in this crate is that it lives in `fdlimit.rs`.
    fn terminate(&self) {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -TERM {}", self.0.id()))
            .status()
            .expect("a shell to send the signal with");
        assert!(status.success(), "could not signal the daemon");
    }

    /// Waits for the process to exit, polling rather than blocking so that
    /// the mock server in this process keeps answering while it shuts down.
    async fn wait_for_exit(&mut self, log: &Path) -> ExitStatus {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = self.0.try_wait().expect("the child can be waited for") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not exit within {PATIENCE:?}: {}",
                read(log),
            );
            tokio::time::sleep(TICK).await;
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A file import counts what it inserted, and a second run of the same file
/// counts the same servers as known rather than inserting them twice: the
/// identity of a server is its canonical endpoint, so the same list imported
/// twice is the same rows.
#[test]
fn a_file_import_counts_what_it_added_and_what_was_known() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());
    let list = write_list(
        dir.path(),
        "# the positive controls of thread #167\n\
         ssl://bitcoin.grey.pw:50002\n\
         \n\
         fulcrum.grey.pw:50001:t\n\
         ssl://electrum.blockstream.info:50002\n",
    );

    let first = observer(&["--config", arg(&config), "import", "file", arg(&list)]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(
        stdout(&first).trim(),
        "added 3, already known 0, skipped 0",
        "{}",
        stderr(&first)
    );

    let second = observer(&["--config", arg(&config), "import", "file", arg(&list)]);
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    assert_eq!(
        stdout(&second).trim(),
        "added 0, already known 3, skipped 0",
        "{}",
        stderr(&second)
    );
}

/// The built-in list, which is the import that needs neither a file nor the
/// network, and the one an operator runs first.
#[test]
fn a_sparrow_import_adds_the_eight_mainnet_servers() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());

    let output = observer(&["--config", arg(&config), "import", "sparrow"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).trim(),
        "added 8, already known 0, skipped 0",
        "{}",
        stderr(&output)
    );
}

/// `servers` is how an import is checked: every row, its source and whether
/// a session would be opened to it, one line each and tab separated.
#[test]
fn servers_lists_every_row_with_its_source() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());
    let list = write_list(dir.path(), "tcp://fulcrum.grey.pw:50001\n");

    assert_eq!(
        observer(&["--config", arg(&config), "import", "sparrow"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        observer(&["--config", arg(&config), "import", "file", arg(&list)])
            .status
            .code(),
        Some(0)
    );

    let output = observer(&["--config", arg(&config), "servers"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let listing = stdout(&output);
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 9, "eight from sparrow and one from the file");

    let first: Vec<&str> = lines[0].split('\t').collect();
    assert_eq!(first.len(), 5, "id, endpoint, source, state, reason");
    assert_eq!(first[0], "1");
    assert_eq!(first[1], "ssl://blockstream.info:700");
    assert_eq!(first[2], "sparrow");
    assert_eq!(first[3], "enabled");
    assert_eq!(first[4], "-", "an enabled server has no reason to be given");

    assert_eq!(
        listing
            .lines()
            .filter(|line| line.contains("\tsparrow\t"))
            .count(),
        8
    );
    let from_file: Vec<&str> = lines[8].split('\t').collect();
    assert_eq!(from_file[1], "tcp://fulcrum.grey.pw:50001");
    assert_eq!(from_file[2], "config", "a file is the operator's own list");
}

/// An empty database is an empty listing and not a failure: that is what
/// `servers` says before the first import.
#[test]
fn servers_on_a_fresh_database_prints_nothing() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());

    let output = observer(&["--config", arg(&config), "servers"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
}

/// A bad line fails the import and names the line, because a list the
/// operator wrote is not a list to silently drop a server out of. Nothing is
/// imported: the file is read before the database is opened.
#[test]
fn a_bad_line_fails_the_import_and_names_the_line() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());
    let list = write_list(
        dir.path(),
        "ssl://bitcoin.grey.pw:50002\n# a comment\nhttps://bad.example:50002\n",
    );

    let output = observer(&["--config", arg(&config), "import", "file", arg(&list)]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("line 3"), "{err}");
    assert!(err.contains("https://bad.example:50002"), "{err}");
    assert!(err.contains("servers.txt"), "{err}");
    assert_eq!(stdout(&output), "", "no counts for an import that failed");

    let listing = observer(&["--config", arg(&config), "servers"]);
    assert_eq!(stdout(&listing), "", "nothing was imported");
}

/// A file that is not there names the path rather than a line.
#[test]
fn an_import_of_a_missing_file_names_the_path() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = write_config(dir.path());

    let output = observer(&[
        "--config",
        arg(&config),
        "import",
        "file",
        "/nonexistent/servers.txt",
    ]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("/nonexistent/servers.txt"),
        "{}",
        stderr(&output)
    );
}

/// A configuration file that is not there is the same failure for an import
/// as for a run: the command never gets as far as the database.
#[test]
fn an_import_without_a_config_file_fails() {
    let output = observer(&[
        "--config",
        "/nonexistent/observer.yaml",
        "import",
        "sparrow",
    ]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("/nonexistent/observer.yaml"),
        "{}",
        stderr(&output)
    );
}

/// A subcommand nobody has is clap's usage error: exit 2, and the usage on
/// stderr. The code is the one a shell script tells from the 1 of a command
/// that ran and failed.
#[test]
fn an_unknown_subcommand_is_a_usage_error() {
    let output = observer(&["import", "electrum-org"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("electrum-org"),
        "{}",
        stderr(&output)
    );

    let missing = observer(&[]);
    assert_eq!(missing.status.code(), Some(2), "{}", stderr(&missing));
}

/// `--help` is not a failure, and it lists the subcommands this step added.
#[test]
fn help_lists_the_subcommands() {
    let output = observer(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    let help = stdout(&output);
    for subcommand in ["run", "import", "servers", "--config"] {
        assert!(help.contains(subcommand), "{subcommand} is in {help}");
    }

    let sources = stdout(&observer(&["import", "--help"]));
    for source in ["1209k", "sparrow", "file"] {
        assert!(sources.contains(source), "{source} is in {sources}");
    }
}

/// `run` as an operator starts it: the binary, a configuration naming one
/// server, a SIGTERM, and an exit code of zero.
///
/// The one thing only a process can show. In the library's own end-to-end
/// test the stop flag is raised by a function call; here it arrives as the
/// signal a unit file sends, through the handlers `main` installs, and what
/// is pinned is the whole path from that signal to a clean exit: the
/// sessions end, the writer commits, the last line says the collector
/// stopped, and the status is 0 so that systemd does not count a restart.
#[tokio::test]
async fn a_run_collects_until_it_is_signalled() {
    let server = MockServer::start(Behaviour::default()).await;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let database = dir.path().join("observer.sqlite");
    let list = write_list(dir.path(), &format!("tcp://{}\n", server.addr()));
    let config = write_run_config(dir.path(), &database, &list);
    let log = dir.path().join("observer.log");

    let mut daemon = Daemon::start(&config, &log);
    // Discovery is off in that configuration, so this row can only be the
    // configured server: the file was read, the session was opened, and the
    // handshake was answered.
    wait_for(&log, "a connection to the configured server", || {
        connections(&database) >= 1
    })
    .await;

    daemon.terminate();
    let status = daemon.wait_for_exit(&log).await;

    assert_eq!(status.code(), Some(0), "{}", read(&log));
    let stderr = read(&log);
    assert!(
        stderr.contains("stopped"),
        "the collector says it stopped: {stderr}",
    );
}
