//! Raising the open file descriptor limit.
//!
//! Copied from crawler's `src/fdlimit.rs`, which adapted p2p-observer's
//! `observer/src/fdlimit.rs`. The arithmetic is unchanged; what differs is
//! which configuration decides the ceiling and what the reserve is for.
//!
//! Here the ceiling is `discovery.max_servers` times `sessions_per_server`:
//! every monitored server holds its connection open for as long as the
//! process runs, so the descriptors are not borrowed for a dial and returned
//! like a crawler's -- they are all held at once, all the time, and the
//! daemon reaches its ceiling within minutes of starting and stays there.
//! That makes the limit worth checking before the first socket is opened
//! rather than after: once 600 sessions are reconnecting, the log line about
//! a descriptor is competing with every other session failing the same way,
//! and the sessions that did get a descriptor keep collecting, so the
//! database looks fine while a third of the servers are silently missing.
//!
//! So: raise the soft limit as far as the OS allows, refuse to start if even
//! the hard limit cannot cover the configured sessions plus a reserve, and
//! report the headroom either way.
//!
//! Bitcoin Core does the same thing in `RaiseFileDescriptorLimit`, and for the
//! same reason -- its connection count is bounded too, but the limit still
//! decides whether the bound is reachable.

use tracing::{info, warn};

use crate::TARGET_MAIN;

/// Descriptors reserved for everything that is not a session.
///
/// The SQLite database and the two files WAL mode keeps beside it, arti's
/// state directory and its own connections to guards and directory caches,
/// the DNS sockets hickory opens per lookup, stdout, and what the tokio
/// runtime keeps for itself. Generous on purpose: overestimating costs a
/// line at startup, underestimating costs an unexplained failure hours in.
const RESERVE: u64 = 512;

/// The limit the collector needs before a single server is connected.
fn floor(max_sessions: u64) -> u64 {
    max_sessions.saturating_add(RESERVE)
}

/// What to do about the limit we found.
///
/// `RLIM_INFINITY` arrives as `u64::MAX`, which needs no special case here: it
/// is above every floor and is a legitimate thing to raise the soft limit to.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The soft limit is already everything we can have.
    Keep { limit: u64 },
    /// Raise the soft limit to the hard one.
    Raise { to: u64 },
    /// Not even the hard limit covers the floor. Nothing to do but say so.
    TooLow { hard: u64, floor: u64 },
}

/// The decision, as arithmetic over the three numbers that make it.
///
/// Pure, and tested as such: this is the part that decides whether the
/// collector starts, and it should not take two hosts with different limits
/// to find out that it decides correctly.
fn plan(soft: u64, hard: u64, floor: u64) -> Plan {
    if hard < floor {
        Plan::TooLow { hard, floor }
    } else if soft < hard {
        // Taken whether or not the soft limit already clears the floor:
        // descriptors the OS will part with cost nothing to hold, and the
        // cap on sessions is the config's to set, not the kernel's.
        Plan::Raise { to: hard }
    } else {
        Plan::Keep { limit: soft }
    }
}

/// Raise the open file limit as far as the OS allows, and report what it
/// leaves for sessions.
///
/// `max_sessions` is `discovery.max_servers` times `sessions_per_server`:
/// every one of them is a socket held open for the life of the process.
///
/// Fails only when the limit cannot cover [`floor`] -- a misconfigured host
/// rather than a busy one, and one that will not get better by running.
#[cfg(unix)]
pub fn prepare(max_sessions: usize) -> Result<(), String> {
    let floor = floor(max_sessions as u64);
    let (soft, hard) = current().map_err(|e| format!("cannot read the open file limit: {e}"))?;

    let mut limit = match plan(soft, hard, floor) {
        Plan::TooLow { hard, floor } => {
            return Err(format!(
                "the open file limit allows at most {hard} descriptors, \
                 and {floor} are needed for {max_sessions} sessions \
                 plus {RESERVE} reserved -- raise it, or lower \
                 discovery.max_servers or sessions_per_server"
            ));
        }
        Plan::Keep { limit } => limit,
        Plan::Raise { to } => match raise(to, hard) {
            Ok(()) => to,
            // Not fatal in itself: macOS refuses a raise to an unlimited hard
            // limit, and a sandbox may refuse one outright. What matters is
            // whether the limit we are left with clears the floor, which the
            // check below does.
            Err(e) => {
                warn!(target: TARGET_MAIN,
                    soft, hard, wanted = to, error = %e,
                    "could not raise the open file limit"
                );
                soft
            }
        },
    };
    if limit < floor {
        return Err(format!(
            "the open file limit is {limit} descriptors and {floor} are needed \
             for {max_sessions} sessions plus {RESERVE} reserved -- raise it, \
             or lower discovery.max_servers or sessions_per_server"
        ));
    }

    // Re-read rather than trust the raise: the kernel is free to clamp, and a
    // number we only believe is worse than no number at all here.
    if let Ok((soft, _)) = current() {
        limit = soft;
    }
    let headroom = limit.saturating_sub(floor);
    if limit == u64::MAX {
        info!(target: TARGET_MAIN,
            "the open file limit is unlimited: only discovery.max_servers and \
             sessions_per_server bound how many servers are connected at once"
        );
    } else {
        info!(target: TARGET_MAIN,
            limit, reserved = RESERVE, max_sessions, headroom,
            "open file limit"
        );
    }
    Ok(())
}

/// Nothing to raise and nothing to check: a platform without the limit has no
/// ceiling for us to report.
#[cfg(not(unix))]
pub fn prepare(_max_sessions: usize) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
// `rlim_t` is u64 here and on macOS but i64 on the BSDs, so the casts are
// portability and not redundancy, whatever the lint says on this platform.
#[allow(clippy::unnecessary_cast)]
fn current() -> std::io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is initialised and lives across the call, which only
    // writes the two fields it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((lim.rlim_cur as u64, lim.rlim_max as u64))
}

#[cfg(unix)]
// `rlim_t` is u64 here and on macOS but i64 on the BSDs, so the casts are
// portability and not redundancy, whatever the lint says on this platform.
#[allow(clippy::unnecessary_cast)]
fn raise(to: u64, hard: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: to as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `lim` is initialised and lives across the call, which only
    // reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor covers every session the config allows, plus what the
    /// database and the Tor client need for themselves.
    #[test]
    fn the_floor_covers_the_configured_sessions() {
        assert_eq!(floor(2000), 2000 + RESERVE);
        assert_eq!(floor(0), RESERVE);
        // A configured number large enough to overflow is still a number.
        assert_eq!(floor(u64::MAX), u64::MAX);
    }

    /// The soft limit is raised whenever the hard one is higher, even when the
    /// soft limit would already do: the spare descriptors are free, and a
    /// session three days in should not be the thing that discovers an
    /// off-by-a-few.
    #[test]
    fn a_higher_hard_limit_is_always_taken() {
        assert_eq!(plan(1024, 1_048_576, 2512), Plan::Raise { to: 1_048_576 });
        assert_eq!(plan(128, 4096, 2512), Plan::Raise { to: 4096 });
        assert_eq!(
            plan(4096, u64::MAX, 2512),
            Plan::Raise { to: u64::MAX },
            "an unlimited hard limit is a target like any other"
        );
    }

    /// Nothing to do when the soft limit is already the hard one.
    #[test]
    fn an_exhausted_hard_limit_is_kept() {
        assert_eq!(plan(4096, 4096, 2512), Plan::Keep { limit: 4096 });
    }

    /// Exactly enough is enough: a host whose limit covers the floor and not
    /// one descriptor more is a host the daemon can start on, and refusing it
    /// would be refusing the number the operator was told to configure.
    #[test]
    fn a_limit_that_exactly_covers_the_floor_is_accepted() {
        assert_eq!(plan(2512, 2512, 2512), Plan::Keep { limit: 2512 });
        assert_eq!(plan(1024, 2512, 2512), Plan::Raise { to: 2512 });
        assert_eq!(
            plan(1024, 2511, 2512),
            Plan::TooLow {
                hard: 2511,
                floor: 2512
            },
            "and one descriptor short is short"
        );
    }

    /// A hard limit under the floor cannot be fixed by raising anything, and
    /// is reported with both numbers so the operator can act on it.
    #[test]
    fn a_hard_limit_under_the_floor_is_refused() {
        assert_eq!(
            plan(1024, 2000, 2512),
            Plan::TooLow {
                hard: 2000,
                floor: 2512
            }
        );
        // Refused on the hard limit even where the soft one happens to clear
        // the floor, which the OS does not allow but the arithmetic should
        // not depend on.
        assert_eq!(
            plan(3000, 2000, 2512),
            Plan::TooLow {
                hard: 2000,
                floor: 2512
            }
        );
    }

    /// `prepare` reads the real limit, raises it, and leaves the process able
    /// to open what the config promised.
    ///
    /// Everything above this was the decision in the abstract. This is the
    /// part that calls `getrlimit` and `setrlimit` -- the part that either
    /// lets the daemon hold its sessions or refuses to start.
    ///
    /// Raising the soft limit to the hard one is the only side effect, and it
    /// is the one the binary has anyway: more descriptors, no fewer.
    ///
    /// The soft limit is first lowered by exactly one, so that there is
    /// something for `prepare` to raise on a host where it already sits at
    /// the hard limit. By one and not to the floor: the process is still a
    /// test binary opening sockets and files on other threads, and a limit
    /// one below the hard one is as roomy as the one it replaces.
    #[cfg(unix)]
    #[test]
    fn prepare_raises_the_soft_limit_to_the_hard_one() {
        let (_, hard_before) = current().expect("the kernel reports RLIMIT_NOFILE");
        raise(hard_before - 1, hard_before).expect("the soft limit may always go down");
        assert_eq!(
            current().expect("the kernel reports RLIMIT_NOFILE").0,
            hard_before - 1,
            "the test could not make room for a raise"
        );

        prepare(200).expect("200 sessions plus a reserve fits in any usable limit");

        let (soft, hard) = current().expect("the kernel reports RLIMIT_NOFILE");
        assert_eq!(hard, hard_before, "the hard limit is not ours to move");
        assert_eq!(
            soft, hard,
            "the soft limit should have been raised to the hard one"
        );
        assert!(
            soft >= floor(200),
            "{soft} descriptors is under the {} needed",
            floor(200)
        );

        // And the limit we ended up with is enough for exactly as many
        // sessions as it covers, not one fewer. The arithmetic says so
        // above; this says the check after the raise agrees, which is the
        // one that turns a number into a refusal. In the same test as the
        // raise, because both move this process's soft limit and a second
        // test doing that in parallel would race this one.
        if let Ok(exactly) = usize::try_from(hard.saturating_sub(RESERVE)) {
            prepare(exactly).unwrap_or_else(|e| {
                panic!("a limit of {hard} covers {exactly} sessions and a {RESERVE} reserve: {e}")
            });
        }
    }

    /// And it refuses, by name, when the limit cannot cover the configured
    /// sessions.
    ///
    /// The refusal is deliberate -- starting and then failing to connect to
    /// a third of the servers is worse than not starting, because the
    /// database would look like data rather than like a misconfiguration --
    /// so the message is what an operator has to act on, and it has to name
    /// both numbers and the keys they can change. Asked for more sessions
    /// than any host could have descriptors for, which exercises the real
    /// syscalls without moving the process's own limit anywhere.
    #[cfg(unix)]
    #[test]
    fn prepare_refuses_a_limit_that_cannot_cover_the_sessions() {
        let (_, hard) = current().expect("the kernel reports RLIMIT_NOFILE");
        if hard == u64::MAX {
            // An unlimited hard limit covers anything, and saying so is the
            // other branch's job.
            return;
        }
        let too_many = usize::try_from(hard).unwrap_or(usize::MAX);
        let err = prepare(too_many).expect_err("more sessions than descriptors");
        assert!(
            err.contains(&hard.to_string()),
            "{err}: the message should name the limit it found"
        );
        assert!(
            err.contains("discovery.max_servers"),
            "{err}: the message should name the key to change"
        );
        assert!(
            err.contains("sessions_per_server"),
            "{err}: and the other key the ceiling is made of"
        );
    }
}
