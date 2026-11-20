//! The signal to stop on.
//!
//! Copied from crawler's `src/shutdown.rs`, which adapted p2p-observer's
//! `common/src/shutdown.rs`. Nothing changed but the words: the parts that
//! watch the flag here are the sessions and the store's writer task rather
//! than a crawl's dialer and parquet writer.

use tokio::sync::watch;
use tracing::info;

use crate::TARGET_MAIN;

/// The flag every long-running part of the collector watches.
///
/// A `watch` channel rather than a future, because the process has one stop
/// signal and many places that have to notice it: every open session, the
/// reconnect backoff each of them sleeps in, the writer. Each takes a
/// [`watch::Receiver`] and sees the flag flip whenever it next looks, and a
/// receiver created after the flag is already set sees it set -- which a
/// broadcast or a oneshot would not give, and which matters because sessions
/// are spawned, and respawned after a disconnect, while the signal may
/// already have arrived.
///
/// p2p-observer waits on the signals as a future. Here the same two signals
/// set a flag instead: SIGTERM and SIGINT mean "write out what you have and
/// stop", and what is in flight -- a batch the writer has not committed, a
/// request a session is waiting on -- needs a flag it can read rather than a
/// future one of them consumes.
#[derive(Clone, Debug)]
pub struct Shutdown {
    stop: watch::Sender<bool>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// A stop signal that nothing will ever flip on its own.
    ///
    /// What a test runs with, and what any caller that stops the collector
    /// for a reason other than a signal uses.
    pub fn new() -> Self {
        Self {
            stop: watch::channel(false).0,
        }
    }

    /// Installs the signal handlers and hands back the flag they flip.
    ///
    /// The handlers are registered here, before the task that waits on them
    /// is spawned, and not inside it: a SIGTERM arriving between this
    /// function returning and that task's first poll would otherwise be
    /// handled by the default disposition, which is to kill the process --
    /// exactly the outcome the shutdown path exists to prevent.
    ///
    /// A failure to register is a failure to start. The observer holds
    /// hundreds of sessions open and a SQLite transaction uncommitted, and a
    /// process that cannot be asked to stop cleanly can only be killed --
    /// which costs the batch and, under systemd, a restart loop nobody
    /// notices.
    pub fn install() -> std::io::Result<Self> {
        let shutdown = Self::new();
        let stop = shutdown.stop.clone();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut terminate = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            tokio::spawn(async move {
                let signal = tokio::select! {
                    _ = terminate.recv() => "SIGTERM",
                    _ = interrupt.recv() => "SIGINT",
                };
                info!(target: TARGET_MAIN, signal, "stopping");
                stop.send_replace(true);
            });
        }
        #[cfg(not(unix))]
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!(target: TARGET_MAIN, signal = "ctrl-c", "stopping");
                let _ = stop.send(true);
            }
        });

        Ok(shutdown)
    }

    /// A view of the flag for one task.
    pub fn watcher(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Flips the flag without a signal, for tests and for any caller that
    /// stops the collector itself.
    ///
    /// `send_replace` rather than `send`, which fails when every receiver has
    /// been dropped and then leaves the flag unset: the flag is also read
    /// through [`Shutdown::is_stopped`] and by receivers made afterwards, so
    /// "nobody is listening yet" must not mean "it was not stopped".
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Whether the collector has been asked to stop.
    pub fn is_stopped(&self) -> bool {
        *self.stop.borrow()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// How long a test waits for a flag it expects to have flipped.
    ///
    /// Bounded rather than awaited outright: a change that stops flipping
    /// the flag should fail the test, and a test that hangs instead of
    /// failing is one nobody can read the output of.
    const SOON: Duration = Duration::from_secs(5);

    /// Waits for the flag, or says it never came.
    async fn flipped(watcher: &mut watch::Receiver<bool>) {
        tokio::time::timeout(SOON, watcher.changed())
            .await
            .expect("the flag should have flipped")
            .expect("the sender is still here");
    }

    /// A watcher made before the flag flips sees it flip.
    #[tokio::test]
    async fn a_watcher_sees_the_flag_flip() {
        let shutdown = Shutdown::new();
        let mut watcher = shutdown.watcher();
        assert!(!*watcher.borrow_and_update());
        assert!(!shutdown.is_stopped());

        shutdown.stop();

        flipped(&mut watcher).await;
        assert!(*watcher.borrow());
        assert!(shutdown.is_stopped());
    }

    /// And a watcher made afterwards starts out stopped, which is what keeps
    /// a connection spawned during the shutdown from running a full session.
    #[tokio::test]
    async fn a_watcher_made_after_the_signal_is_already_stopped() {
        // Through `Default`, which is the way a test or a tool that has no
        // signals to install gets one.
        let shutdown = Shutdown::default();
        shutdown.stop();
        assert!(*shutdown.watcher().borrow());
    }

    /// SIGTERM reaches the flag rather than the process's default handler,
    /// which would end the process without writing anything out.
    ///
    /// Sent through `kill` rather than `libc::raise`, because the one rule
    /// about `unsafe` in this crate is that it lives in `fdlimit.rs` and this
    /// is not it. The signal goes to this very process: if the handler
    /// were not installed by the time it arrives, the test binary would be
    /// terminated, which is a loud enough failure.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_sigterm_stops_the_collector_instead_of_the_process() {
        let shutdown = Shutdown::install().expect("the handlers register");
        let mut watcher = shutdown.watcher();
        assert!(!*watcher.borrow_and_update());

        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -TERM {}", std::process::id()))
            .status()
            .expect("a shell to send the signal with");
        assert!(status.success(), "could not signal this process");

        flipped(&mut watcher).await;
        assert!(shutdown.is_stopped());
    }
}
