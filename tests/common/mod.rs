//! What the integration tests share.
//!
//! One module so far, the mock Electrum server of step 6 of `PLAN.md`. It
//! lives here rather than in `src/` behind a `#[cfg(test)]` because the tests
//! that need it -- the session of step 10 and the end-to-end run of step 14 --
//! drive the library from outside, as a user of the crate would, and a
//! harness compiled into the library would be a second public API nobody
//! ships.

// Every test binary that says `mod common;` compiles the whole module and
// sees a private copy of it, so a knob no test in *that* binary touches reads
// as dead code. The harness is deliberately wider than today's tests: it
// answers the methods of DESIGN.md sections 5 and 6 that steps 7 to 10 and 14
// will ask for, and trimming it to what the first test file happens to use
// would mean growing it back one method per commit.
#![allow(dead_code)]

pub mod mock_server;
