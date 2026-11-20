//! What the integration tests share.
//!
//! One module so far, the mock Electrum server. It lives here rather than in
//! `src/` behind a `#[cfg(test)]` because the tests that need it -- the
//! session tests and the end-to-end run -- drive the library from outside, as
//! a user of the crate would, and a harness compiled into the library would
//! be a second public API nobody ships.

// Every test binary that says `mod common;` compiles the whole module and
// sees a private copy of it, so a knob no test in *that* binary touches reads
// as dead code. The harness is deliberately wider than today's tests: it
// answers every method a session sends, and trimming it to what the first
// test file happens to use would mean growing it back one method per commit.
#![allow(dead_code)]

pub mod mock_server;
