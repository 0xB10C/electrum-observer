//! Which block a server saw, when it saw it, and which side of a split it
//! was on.
//!
//! This is the module thread
//! [#167](https://bnoc.xyz/t/electrum-server-monitoring-header-propagation-and-shared-infrastructure/167)
//! is about. Two servers announcing the same block tens of milliseconds
//! apart are a hint that one `bitcoind` is behind both of them; two servers
//! announcing *different* blocks at one height, and the time each of them
//! takes to change its mind afterwards, is the other half of the same
//! question -- and the half that thread could not measure, because nothing
//! was polling while the split lasted. The measurement is therefore two
//! numbers per server per block: which hash, and when.
//!
//! Everything here is pure. No clock is read, no socket is touched and no
//! task is spawned: time arrives as [`Micros`] arguments taken where the
//! bytes arrived, and the I/O belongs to the session (`session.rs`) and the
//! run loop. A tracker driven by its caller's clock is a tracker a test can
//! run a week of blocks through in a millisecond, and -- more to the point --
//! one that cannot accidentally stamp an observation with the time it was
//! *processed* rather than the time it arrived, which is the one error this
//! whole crate is built to avoid.
//!
//! Three things come out of it, in the shape the rest of the crate needs:
//!
//! - [`parse_header`] and [`Announcement`] turn what came off the wire into
//!   a hash, a previous hash and a height, for `header_events`.
//! - [`Tracker::observe`] answers the two questions a `header_events` row
//!   cannot answer from its own columns: was this server contradicting
//!   itself (`reorg`), and was anyone ahead of it with this block.
//! - [`Tracker::open_window`] says whether the chain is currently split and
//!   at which heights, which is what puts every session into divergence
//!   polling.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use serde_json::Value;

use crate::store::Micros;

/// A serialised block header, as every chain since 2009 has spelled it.
const HEADER_BYTES: usize = 80;

/// How many announcements of its own each server is remembered by.
///
/// The `reorg` rule needs that server's own hash at `height - 1`, and the
/// last announcement alone does not have it as soon as a server skips a
/// height -- which happens whenever a block arrives while the connection is
/// re-establishing, or when a server is behind and catches up in one jump.
/// Sixteen is far past any sequence of skipped heights that is not a resync,
/// cheap at 450 servers, and bounded, which the alternative (every
/// announcement ever) is not.
const HISTORY_DEPTH: usize = 16;

/// How far below the best height the block book is kept.
///
/// A difficulty retarget window. The book exists to answer "is there another
/// hash at this height" and "who was first with this one", and both questions
/// are asked about the tip: a divergence window is half an hour and the
/// deepest reorg bitcoin has ever had is a handful of blocks, so anything
/// kept is already more than enough. 2016 is chosen over something tighter
/// because it is the one depth in bitcoin that needs no justification of its
/// own, and because the cost of being generous is small: a few hundred bytes
/// per block, so a few hundred kilobytes in total, rather than the unbounded
/// growth of a daemon that is meant to run for months. Blocks below the
/// cutoff stay in the database; it is only this in-memory book that forgets
/// them.
const PRUNE_DEPTH: u64 = 2016;

/// Why a header or an announcement could not be read.
///
/// Carried rather than logged: what a server sends that is not a header is
/// itself an observation about that server, so the caller decides whether it
/// is a disconnection, a `header_events` row that is not written, or a line
/// in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The text is not hexadecimal: an odd number of characters, or a
    /// character outside `0-9a-fA-F`.
    Hex(String),
    /// Hexadecimal, but not 80 bytes of it.
    ///
    /// Every rejection by the consensus decoder arrives here, because with
    /// exactly 80 bytes in hand that decoder cannot fail -- a header is six
    /// fixed-width fields and no length prefix, none of which it validates --
    /// so a decode that does fail has the wrong number of bytes and nothing
    /// else.
    Length(usize),
    /// The JSON was not the `{hex, height}` object the protocol documents.
    Shape(String),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::Hex(reason) => write!(f, "the header is not hexadecimal: {reason}"),
            HeaderError::Length(bytes) => write!(
                f,
                "a block header is {HEADER_BYTES} bytes, this one is {bytes}"
            ),
            HeaderError::Shape(reason) => write!(f, "not a header announcement: {reason}"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// One header, with the two hashes that place it in a chain.
///
/// The hexadecimal is kept verbatim rather than re-encoded from the decoded
/// header, because `header_events.header_hex` is meant to be what the server
/// said: a server that spells its hex in capitals, or that announces a header
/// that round-trips to something else, is exactly the kind of difference this
/// crate records instead of normalising away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedHeader {
    /// The double-sha256 of the 80 bytes, as everything else names a block.
    pub hash: BlockHash,
    /// The parent this header claims, which is what makes an announcement a
    /// chain extension or a change of mind.
    pub prev_hash: BlockHash,
    /// The decoded header, for the fields nothing needs yet -- the timestamp
    /// a server's clock put in it, the target, the nonce.
    pub header: Header,
    /// The hexadecimal exactly as it arrived.
    pub hex: String,
}

/// Decodes the 80 bytes of a block header.
///
/// Both lengths that are not 80 and every non-hexadecimal text are rejected
/// with a reason, because this is called on whatever a stranger put on the
/// wire.
pub fn parse_header(hex: &str) -> Result<ParsedHeader, HeaderError> {
    let bytes = hex::decode(hex).map_err(|e| HeaderError::Hex(e.to_string()))?;
    let header: Header = deserialize(&bytes).map_err(|_| HeaderError::Length(bytes.len()))?;
    Ok(ParsedHeader {
        hash: header.block_hash(),
        prev_hash: header.prev_blockhash,
        header,
        hex: hex.to_string(),
    })
}

/// A header and the height a server put it at.
///
/// `blockchain.headers.subscribe` answers with `{hex, height}` and then sends
/// the same object as `params[0]` of every notification, so one type covers
/// both and the caller keeps the distinction where it belongs: in
/// [`HeaderKind`](crate::store::HeaderKind), which says whether this was the
/// tip we happened to connect to or a block the server learned while we were
/// watching.
///
/// The height is the server's claim, not a verified fact. Nothing here checks
/// it against the header, and nothing should: a server that puts a header at
/// the wrong height has told us something about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    /// The height the server claims for this header.
    pub height: u64,
    /// The header itself.
    pub header: ParsedHeader,
}

impl Announcement {
    /// Reads the `{hex, height}` object of a subscribe reply or of a
    /// notification's `params[0]`.
    pub fn from_value(value: &Value) -> Result<Self, HeaderError> {
        let object = value
            .as_object()
            .ok_or_else(|| HeaderError::Shape("it is not an object".to_string()))?;
        let hex = object
            .get("hex")
            .ok_or_else(|| HeaderError::Shape("there is no \"hex\"".to_string()))?
            .as_str()
            .ok_or_else(|| HeaderError::Shape("\"hex\" is not a string".to_string()))?;
        let height = object
            .get("height")
            .ok_or_else(|| HeaderError::Shape("there is no \"height\"".to_string()))?
            .as_u64()
            .ok_or_else(|| {
                HeaderError::Shape("\"height\" is not a non-negative integer".to_string())
            })?;
        Ok(Announcement {
            height,
            header: parse_header(hex)?,
        })
    }
}

/// One row of `blocks`, as the tracker is seeded from it at startup.
///
/// The announcer count is not among the columns and is not reconstructed:
/// `blocks` keeps who was *first*, which is the measurement, and counting
/// who else announced a block is a query over `header_events` rather than a
/// column. A seeded block therefore starts at zero announcers and counts
/// again from the observations this process makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownBlock {
    /// The block.
    pub hash: BlockHash,
    /// Its height.
    pub height: u64,
    /// Its parent.
    pub prev_hash: BlockHash,
    /// When it was first seen, over every run that wrote to this database.
    pub first_seen_at: Micros,
    /// Which server was first with it.
    pub first_seen_server_id: i64,
}

/// What the book knows about one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    /// The height it was announced at.
    pub height: u64,
    /// Its parent.
    pub prev_hash: BlockHash,
    /// The earliest observation of it, which is the number the first-seen
    /// matrix is built from.
    pub first_seen_at: Micros,
    /// The server that earliest observation came from.
    pub first_seen_server_id: i64,
    /// How many distinct servers have announced it.
    ///
    /// Distinct as far as [`HISTORY_DEPTH`] can tell: a server that announces
    /// a hash it announced within its last sixteen announcements is not
    /// counted twice, which is what keeps `sessions_per_server > 1` -- two
    /// connections to one endpoint, announcing every block twice -- from
    /// doubling a server's weight in [`Tracker::majority_at`].
    pub announcers: usize,
}

/// What one observation meant, beyond the row it writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// `header_events.reorg`: this server contradicted its own last
    /// announcement rather than extending it.
    pub reorg: bool,
    /// No server had announced this hash before.
    ///
    /// Novelty to the tracker, not a claim about the clock: an observation
    /// that arrives late but was stamped early is not `first_seen`, yet it
    /// does become the block's [`BlockRecord::first_seen_at`].
    pub first_seen: bool,
    /// The height this observation landed on has more than one hash, and a
    /// window is open over it.
    pub divergence: Option<Divergence>,
}

/// Two or more hashes at one height, and the window that arms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// The height that is split.
    pub height: u64,
    /// Every hash known at it, in the order they were first seen.
    pub hashes: Vec<BlockHash>,
    /// When the window covering this split opened. A split that arrives
    /// while a window is already open extends that window rather than
    /// starting one, so this is the first split of the episode and not
    /// necessarily this one.
    pub opened_at: Micros,
    /// This observation is the one that split the height: the hash it
    /// carried had never been seen, and the height already had another. Only
    /// one observation per new hash per height ever gets this; every later
    /// announcement at the split height reports the divergence with it
    /// false.
    pub newly_opened: bool,
}

/// An open divergence window: what to poll, and until when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// When the first split of this episode was seen.
    pub since: Micros,
    /// When the window closes, unless another split extends it.
    pub until: Micros,
    /// The heights that are split, ascending. `blockchain.block.header` is
    /// asked at each of them: a two-block fork splits two heights, and the
    /// interesting answer is at both.
    pub heights: Vec<u64>,
}

/// A window that has expired, for whoever logs or counts them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedWindow {
    /// When it opened.
    pub since: Micros,
    /// When it closed, which is the deadline it reached and not the moment
    /// the caller noticed.
    pub until: Micros,
    /// The heights it covered, ascending.
    pub heights: Vec<u64>,
}

/// The window as the tracker holds it while it is open.
#[derive(Clone, Debug)]
struct WindowState {
    since: Micros,
    until: Micros,
    heights: Vec<u64>,
}

/// Every server's tip, every block anyone announced, and the splits.
///
/// One of these for the whole process, not one per session: a divergence is
/// by definition something no single connection can see, and the first-seen
/// time of a block is the earliest over all of them. The run loop owns it and
/// the sessions hand it their announcements.
#[derive(Clone, Debug)]
pub struct Tracker {
    /// How long a window stays open after a split (`divergence.window_secs`).
    window: Duration,
    /// The block book.
    blocks: HashMap<BlockHash, BlockRecord>,
    /// Which hashes are known at each height, first seen first. Ordered so
    /// that pruning below a height is one split.
    by_height: BTreeMap<u64, Vec<BlockHash>>,
    /// Each server's last [`HISTORY_DEPTH`] announcements, oldest first.
    servers: HashMap<i64, VecDeque<(u64, BlockHash)>>,
    /// The window, while one is open.
    open: Option<WindowState>,
    /// Windows that have expired and not yet been reported.
    closed: Vec<ClosedWindow>,
    /// The highest height anyone has announced, which is what pruning is
    /// measured from.
    best_height: u64,
}

impl Tracker {
    /// An empty tracker whose windows last `window`
    /// ([`DivergenceSettings::window`](crate::settings::DivergenceSettings::window)).
    pub fn new(window: Duration) -> Self {
        Tracker {
            window,
            blocks: HashMap::new(),
            by_height: BTreeMap::new(),
            servers: HashMap::new(),
            open: None,
            closed: Vec::new(),
            best_height: 0,
        }
    }

    /// A tracker that already knows the blocks of earlier runs.
    ///
    /// Without this, a restart during a split would see the first
    /// announcement of each branch as a new hash at a height that already had
    /// another one, arm a window, and poll every server about a fork that was
    /// resolved yesterday. Seeding from `blocks` makes a known hash a known
    /// hash, so only a split that is new to the database arms anything.
    ///
    /// The seed is pruned like everything else, so handing it a whole table
    /// costs the parse and not the memory.
    pub fn with_known_blocks<I>(window: Duration, known: I) -> Self
    where
        I: IntoIterator<Item = KnownBlock>,
    {
        let mut tracker = Tracker::new(window);
        for block in known {
            let record = BlockRecord {
                height: block.height,
                prev_hash: block.prev_hash,
                first_seen_at: block.first_seen_at,
                first_seen_server_id: block.first_seen_server_id,
                announcers: 0,
            };
            if tracker.blocks.insert(block.hash, record).is_none() {
                tracker
                    .by_height
                    .entry(block.height)
                    .or_default()
                    .push(block.hash);
            }
            tracker.best_height = tracker.best_height.max(block.height);
        }
        tracker.prune();
        tracker
    }

    /// Forgets what this server last announced, because a new connection to
    /// it has been made.
    ///
    /// The reply to `blockchain.headers.subscribe` is whatever the server's
    /// tip happened to be when we connected, so it is never evidence that the
    /// server changed its mind. Without this, a server that restarted behind
    /// where we last saw it would be recorded as having reorged when all it
    /// did was reconnect.
    ///
    /// With `sessions_per_server > 1` the history belongs to the server and
    /// not to the connection, so the second session's handshake clears the
    /// first session's memory too. That costs one unflagged reorg in the
    /// window between a reconnect and the next block, and buys a `reorg`
    /// column that means what it is supposed to mean -- the server changed
    /// its mind -- for the much more common single-session case.
    pub fn session_started(&mut self, server_id: i64) {
        self.servers.remove(&server_id);
    }

    /// Records one announcement and says what it meant.
    ///
    /// `at` is when the last byte of the line arrived, not when this was
    /// called.
    pub fn observe(&mut self, server_id: i64, ann: &Announcement, at: Micros) -> Observation {
        let height = ann.height;
        let hash = ann.header.hash;

        let reorg = self.is_reorg(server_id, ann);
        let announced_before = self
            .servers
            .get(&server_id)
            .is_some_and(|history| history.iter().any(|(_, seen)| *seen == hash));
        self.remember(server_id, height, hash);

        let first_seen = match self.blocks.entry(hash) {
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                // The earliest sighting wins even when it is not the first to
                // be handed over: two servers' announcements of one block are
                // tens of milliseconds apart and nothing guarantees they
                // reach the tracker in that order. This is the same rule the
                // `blocks` upsert applies in SQL.
                if at < record.first_seen_at {
                    record.first_seen_at = at;
                    record.first_seen_server_id = server_id;
                }
                if !announced_before {
                    record.announcers += 1;
                }
                false
            }
            Entry::Vacant(slot) => {
                slot.insert(BlockRecord {
                    height,
                    prev_hash: ann.header.prev_hash,
                    first_seen_at: at,
                    first_seen_server_id: server_id,
                    announcers: 1,
                });
                true
            }
        };
        if first_seen {
            self.by_height.entry(height).or_default().push(hash);
        }

        let hashes = self.hashes_at(height).to_vec();
        let divergence = if hashes.len() < 2 {
            None
        } else if first_seen {
            // The hash is new and the height already had one: this
            // observation is the split.
            let opened_at = self.arm(height, at);
            Some(Divergence {
                height,
                hashes,
                opened_at,
                newly_opened: true,
            })
        } else {
            // A height that is still split and still being polled. Reported
            // so that the caller knows this announcement landed inside a
            // window -- which side a server is on is the measurement -- but
            // it neither opens nor extends anything.
            self.open
                .as_ref()
                .filter(|window| at < window.until && window.heights.contains(&height))
                .map(|window| Divergence {
                    height,
                    hashes,
                    opened_at: window.since,
                    newly_opened: false,
                })
        };

        self.best_height = self.best_height.max(height);
        self.prune();

        Observation {
            reorg,
            first_seen,
            divergence,
        }
    }

    /// The window to poll in, if the chain is split right now.
    ///
    /// The session asks this on its poll timer: `Some` means ask
    /// `blockchain.block.header` at each of [`Window::heights`] and write
    /// `tip_checks`, `None` means the ordinary timers. A window that has
    /// passed its deadline is already `None` here, whether or not
    /// [`Tracker::close_expired`] has been called.
    pub fn open_window(&self, now: Micros) -> Option<Window> {
        let window = self.open.as_ref()?;
        if now >= window.until {
            return None;
        }
        let mut heights = window.heights.clone();
        heights.sort_unstable();
        Some(Window {
            since: window.since,
            until: window.until,
            heights,
        })
    }

    /// Takes the windows that have expired.
    ///
    /// Each one is reported exactly once, which is what makes it usable as a
    /// log line or a counter. A `Vec` rather than an `Option` because a
    /// caller that does not ask for a while can have more than one to
    /// collect: at most one window is ever open, but a window that expired
    /// unreported is retired by the next split.
    pub fn close_expired(&mut self, now: Micros) -> Vec<ClosedWindow> {
        self.retire_expired(now);
        std::mem::take(&mut self.closed)
    }

    /// What this server last announced.
    pub fn tip_of(&self, server_id: i64) -> Option<(u64, BlockHash)> {
        self.servers
            .get(&server_id)
            .and_then(|history| history.back())
            .copied()
    }

    /// Every hash known at a height, in the order they were first seen.
    /// More than one of them is a split.
    pub fn hashes_at(&self, height: u64) -> &[BlockHash] {
        self.by_height.get(&height).map_or(&[][..], Vec::as_slice)
    }

    /// What the book knows about a block.
    pub fn block(&self, hash: &BlockHash) -> Option<&BlockRecord> {
        self.blocks.get(hash)
    }

    /// The hash the most servers announced at a height.
    ///
    /// `None` when the height is unknown, and also when two hashes are level:
    /// during a split that is the normal state for the first few seconds, and
    /// a "majority" decided by iteration order would be a worse answer than
    /// no answer. This is a convenience for logging and for later analysis
    /// steps; nothing in the collection path votes on which branch is right.
    pub fn majority_at(&self, height: u64) -> Option<BlockHash> {
        let mut leader: Option<BlockHash> = None;
        let mut best = 0usize;
        let mut tied = false;
        for hash in self.hashes_at(height) {
            let count = self.blocks.get(hash).map_or(0, |record| record.announcers);
            if leader.is_none() || count > best {
                leader = Some(*hash);
                best = count;
                tied = false;
            } else if count == best {
                tied = true;
            }
        }
        if tied { None } else { leader }
    }

    /// How many blocks the book holds, which is what pruning bounds.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// `reorg` is set when the announced `prev_hash` is not this server's own
    /// hash at `height - 1`, or when the height did not increase.
    ///
    /// Two cases are not reorgs even though the rule read literally would
    /// make them one, and both are about the absence of evidence rather than
    /// evidence of absence:
    ///
    /// - The server has told us nothing yet, so there is no chain of its own
    ///   to contradict.
    /// - The server repeated its tip. ElectrumX re-announces on reconnect and
    ///   a second session to one endpoint announces everything twice; neither
    ///   is a change of mind.
    ///
    /// And when the server's own hash at `height - 1` is not in its history
    /// at all -- it skipped a height, or jumped further than
    /// [`HISTORY_DEPTH`] -- the flag stays clear. A server catching up is the
    /// common reason for a gap, and a `reorg` column that fires on catching
    /// up measures our own connection stability instead of the chain.
    fn is_reorg(&self, server_id: i64, ann: &Announcement) -> bool {
        let Some(&(last_height, last_hash)) = self.servers.get(&server_id).and_then(VecDeque::back)
        else {
            return false;
        };
        if last_height == ann.height && last_hash == ann.header.hash {
            return false;
        }
        if ann.height <= last_height {
            return true;
        }
        match self
            .servers
            .get(&server_id)
            // `ann.height` is above `last_height` here, so it is at least
            // one and the subtraction cannot wrap.
            .and_then(|history| history.iter().rev().find(|(h, _)| *h == ann.height - 1))
        {
            Some((_, parent)) => *parent != ann.header.prev_hash,
            None => false,
        }
    }

    /// Appends to a server's history, dropping the oldest when it is full.
    fn remember(&mut self, server_id: i64, height: u64, hash: BlockHash) {
        let history = self.servers.entry(server_id).or_default();
        if history.len() == HISTORY_DEPTH {
            history.pop_front();
        }
        history.push_back((height, hash));
    }

    /// Opens a window over `height`, or extends the open one, and answers
    /// when the episode started.
    fn arm(&mut self, height: u64, at: Micros) -> Micros {
        let until = micros_after(at, self.window);
        if let Some(window) = self.open.as_mut()
            && at < window.until
        {
            // A second split while the chain is still being polled is the
            // same episode -- a two-block fork splits two heights seconds
            // apart -- so the deadline moves instead of a window starting
            // beside the first.
            window.until = until;
            if !window.heights.contains(&height) {
                window.heights.push(height);
            }
            return window.since;
        }
        self.retire_expired(at);
        self.open = Some(WindowState {
            since: at,
            until,
            heights: vec![height],
        });
        at
    }

    /// Moves the open window to the reporting queue once its deadline has
    /// passed.
    fn retire_expired(&mut self, now: Micros) {
        if let Some(window) = self.open.take_if(|window| window.until <= now) {
            let mut heights = window.heights;
            heights.sort_unstable();
            self.closed.push(ClosedWindow {
                since: window.since,
                until: window.until,
                heights,
            });
        }
    }

    /// Drops the book below `best_height - PRUNE_DEPTH`.
    ///
    /// Called after every observation rather than only when the tip moves,
    /// because in the steady state it is one comparison against the lowest
    /// height in an ordered map and there is then nothing to drop. The
    /// heights of an open window are within a few blocks of the tip, so
    /// nothing being polled is ever pruned.
    fn prune(&mut self) {
        let Some(cutoff) = self.best_height.checked_sub(PRUNE_DEPTH) else {
            return;
        };
        while let Some(oldest) = self.by_height.first_entry() {
            if *oldest.key() >= cutoff {
                break;
            }
            for hash in oldest.remove() {
                self.blocks.remove(&hash);
            }
        }
    }
}

/// `at + window`, saturating rather than wrapping on a configuration that
/// asks for a window longer than the epoch.
fn micros_after(at: Micros, window: Duration) -> Micros {
    let span = i64::try_from(window.as_micros()).unwrap_or(i64::MAX);
    Micros(at.as_i64().saturating_add(span))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The mainnet genesis header, and the two blocks on top of it. Real
    /// bytes rather than a fabricated chain, because the hashes below are
    /// public knowledge: if the parse were wrong in any way -- byte order,
    /// field widths, which hash function -- it would have to be wrong in
    /// exactly the way that still produces these three strings.
    const GENESIS: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    const BLOCK1: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    const BLOCK2: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";

    const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const BLOCK1_HASH: &str = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
    const BLOCK2_HASH: &str = "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd";
    const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A competing block: the same parent and the same height, a different
    /// hash. Mining one is four bytes of nonce, which is also all it takes to
    /// make one here -- the nonce is the last field of the 80, so the last
    /// eight characters of the hex.
    fn fork(hex: &str, nonce: &str) -> String {
        assert_eq!(nonce.len(), 8, "a nonce is four bytes");
        format!("{}{nonce}", &hex[..hex.len() - 8])
    }

    fn ann(height: u64, hex: &str) -> Announcement {
        Announcement {
            height,
            header: parse_header(hex).expect("a real header"),
        }
    }

    fn hash_of(hex: &str) -> BlockHash {
        parse_header(hex).expect("a real header").hash
    }

    fn window() -> Duration {
        Duration::from_secs(1800)
    }

    /// Five minutes, in the microseconds everything here counts in.
    const MINUTE: i64 = 60 * 1_000_000;

    #[test]
    fn real_headers_parse_to_their_published_hashes() {
        let cases: &[(&str, &str, &str, &str)] = &[
            ("genesis", GENESIS, GENESIS_HASH, ZEROS),
            ("block 1", BLOCK1, BLOCK1_HASH, GENESIS_HASH),
            ("block 2", BLOCK2, BLOCK2_HASH, BLOCK1_HASH),
        ];
        for (name, hex, hash, prev) in cases {
            let parsed = parse_header(hex).expect(name);
            assert_eq!(parsed.hash.to_string(), *hash, "{name}: hash");
            assert_eq!(parsed.prev_hash.to_string(), *prev, "{name}: prev");
            assert_eq!(parsed.hex, *hex, "{name}: the hex is kept verbatim");
            assert_eq!(parsed.header.block_hash(), parsed.hash, "{name}: agrees");
        }
    }

    #[test]
    fn a_mutated_nonce_is_a_different_block_at_the_same_place() {
        let original = parse_header(BLOCK2).expect("a real header");
        let forked = parse_header(&fork(BLOCK2, "deadbeef")).expect("still 80 bytes");
        assert_ne!(forked.hash, original.hash);
        assert_eq!(forked.prev_hash, original.prev_hash);
    }

    #[test]
    fn a_header_that_is_not_eighty_bytes_of_hex_is_rejected() {
        let short = &GENESIS[..GENESIS.len() - 2];
        let long = format!("{GENESIS}00");
        let odd = &GENESIS[..GENESIS.len() - 1];
        let cases: &[(&str, &str, &str)] = &[
            (
                "not hexadecimal",
                &GENESIS.replace("01000000", "zz000000"),
                "the header is not hexadecimal: Invalid character 'z' at position 0",
            ),
            (
                "an odd number of characters",
                odd,
                "the header is not hexadecimal: Odd number of digits",
            ),
            (
                "one byte short",
                short,
                "a block header is 80 bytes, this one is 79",
            ),
            (
                "one byte long",
                &long,
                "a block header is 80 bytes, this one is 81",
            ),
            ("empty", "", "a block header is 80 bytes, this one is 0"),
        ];
        for (name, hex, message) in cases {
            let error = parse_header(hex).expect_err(name);
            assert_eq!(error.to_string(), *message, "{name}");
        }
    }

    #[test]
    fn an_announcement_is_read_from_a_reply_and_from_a_notification() {
        let reply = json!({"hex": BLOCK1, "height": 1});
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "blockchain.headers.subscribe",
            "params": [{"hex": BLOCK1, "height": 1}],
        });
        let from_reply = Announcement::from_value(&reply).expect("a reply");
        let from_notification =
            Announcement::from_value(&notification["params"][0]).expect("a notification");
        assert_eq!(from_reply, from_notification);
        assert_eq!(from_reply.height, 1);
        assert_eq!(from_reply.header.hash.to_string(), BLOCK1_HASH);
    }

    #[test]
    fn an_announcement_that_is_not_hex_and_a_height_is_rejected() {
        let cases: &[(&str, Value, &str)] = &[
            (
                "not an object",
                json!([BLOCK1, 1]),
                "not a header announcement: it is not an object",
            ),
            (
                "no hex",
                json!({"height": 1}),
                "not a header announcement: there is no \"hex\"",
            ),
            (
                "hex is not a string",
                json!({"hex": 1, "height": 1}),
                "not a header announcement: \"hex\" is not a string",
            ),
            (
                "no height",
                json!({"hex": BLOCK1}),
                "not a header announcement: there is no \"height\"",
            ),
            (
                "a negative height",
                json!({"hex": BLOCK1, "height": -1}),
                "not a header announcement: \"height\" is not a non-negative integer",
            ),
            (
                "a fractional height",
                json!({"hex": BLOCK1, "height": 1.5}),
                "not a header announcement: \"height\" is not a non-negative integer",
            ),
            (
                "a header that is not one",
                json!({"hex": "0100", "height": 1}),
                "a block header is 80 bytes, this one is 2",
            ),
        ];
        for (name, value, message) in cases {
            let error = Announcement::from_value(value).expect_err(name);
            assert_eq!(error.to_string(), *message, "{name}");
        }
    }

    /// Everything the `reorg` flag has to say, as one script per case.
    ///
    /// A table because the rule is three sentences and the cases are the
    /// cross product of them: a case that is missing is then a row that is
    /// missing rather than a function nobody wrote.
    /// A named script: what the server announces, and whether each
    /// announcement is a reorg.
    type ReorgCase<'a> = (&'a str, &'a [(u64, &'a str, bool)]);

    #[test]
    fn reorg_is_set_when_a_server_contradicts_itself() {
        let fork1 = fork(BLOCK1, "11111111");
        let fork2 = fork(BLOCK2, "22222222");
        let cases: &[ReorgCase] = &[
            (
                "the first announcement is never a reorg, wherever it is",
                &[(2, BLOCK2, false)],
            ),
            (
                "extending the chain is not a reorg",
                &[(0, GENESIS, false), (1, BLOCK1, false), (2, BLOCK2, false)],
            ),
            (
                "another hash at the same height is",
                &[(1, BLOCK1, false), (1, fork1.as_str(), true)],
            ),
            (
                "a height that goes backwards is",
                &[(1, BLOCK1, false), (2, BLOCK2, false), (1, BLOCK1, true)],
            ),
            (
                "a parent that is not what this server announced is",
                // BLOCK2 claims block 1 as its parent, not the genesis.
                &[(0, GENESIS, false), (1, BLOCK2, true)],
            ),
            (
                "repeating the same tip is not",
                &[(1, BLOCK1, false), (1, BLOCK1, false)],
            ),
            (
                "a skipped height is not, because nothing is known about it",
                &[(0, GENESIS, false), (2, BLOCK2, false)],
            ),
            (
                "and a later announcement over the gap is judged on its parent",
                &[
                    (0, GENESIS, false),
                    (2, fork2.as_str(), false),
                    (3, BLOCK2, true),
                ],
            ),
            (
                "the fork of a block this server has is still a reorg",
                &[
                    (0, GENESIS, false),
                    (1, BLOCK1, false),
                    (2, BLOCK2, false),
                    (2, fork2.as_str(), true),
                ],
            ),
        ];
        for (name, steps) in cases {
            let mut tracker = Tracker::new(window());
            for (index, (height, hex, expected)) in steps.iter().enumerate() {
                let observation = tracker.observe(7, &ann(*height, hex), Micros(index as i64));
                assert_eq!(observation.reorg, *expected, "{name}: step {index}");
            }
        }
    }

    #[test]
    fn a_reconnect_clears_what_the_server_last_said() {
        let mut tracker = Tracker::new(window());
        tracker.observe(1, &ann(2, BLOCK2), Micros(1));
        // Without the reset this is a height that did not increase.
        tracker.session_started(1);
        assert_eq!(tracker.tip_of(1), None, "the history is gone");
        let observation = tracker.observe(1, &ann(1, BLOCK1), Micros(2));
        assert!(!observation.reorg, "a subscribe reply is not a reorg");
        assert_eq!(tracker.tip_of(1), Some((1, hash_of(BLOCK1))));
    }

    #[test]
    fn a_server_beyond_the_history_depth_keeps_only_its_last_announcements() {
        let mut tracker = Tracker::new(window());
        for index in 0..(HISTORY_DEPTH as u64 + 4) {
            let hex = fork(BLOCK1, &format!("{index:08x}"));
            tracker.observe(1, &ann(index, &hex), Micros(index as i64));
        }
        let history = tracker.servers.get(&1).expect("a history");
        assert_eq!(history.len(), HISTORY_DEPTH);
        assert_eq!(history.front().expect("oldest").0, 4);
        let last = HISTORY_DEPTH as u64 + 3;
        assert_eq!(
            tracker.tip_of(1),
            Some((last, hash_of(&fork(BLOCK1, &format!("{last:08x}")))))
        );
    }

    #[test]
    fn a_hash_is_first_seen_once_and_counts_its_announcers() {
        let mut tracker = Tracker::new(window());
        let hash = hash_of(BLOCK1);
        assert!(tracker.observe(1, &ann(1, BLOCK1), Micros(100)).first_seen);
        assert!(!tracker.observe(2, &ann(1, BLOCK1), Micros(200)).first_seen);
        // The same server again, as a second session to one endpoint does.
        assert!(!tracker.observe(2, &ann(1, BLOCK1), Micros(300)).first_seen);
        let record = tracker.block(&hash).expect("booked");
        assert_eq!(record.announcers, 2, "two servers, not three announcements");
        assert_eq!(record.height, 1);
        assert_eq!(record.prev_hash.to_string(), GENESIS_HASH);
        assert_eq!(record.first_seen_at, Micros(100));
        assert_eq!(record.first_seen_server_id, 1);
        assert_eq!(tracker.block_count(), 1);
        assert_eq!(tracker.hashes_at(1), &[hash]);
        assert_eq!(tracker.hashes_at(9), &[]);
        assert_eq!(tracker.block(&hash_of(BLOCK2)), None);
    }

    #[test]
    fn the_earliest_sighting_wins_whatever_order_it_arrives_in() {
        let mut tracker = Tracker::new(window());
        tracker.observe(1, &ann(1, BLOCK1), Micros(500));
        // Server 2 saw it first but was handed over second.
        tracker.observe(2, &ann(1, BLOCK1), Micros(100));
        tracker.observe(3, &ann(1, BLOCK1), Micros(900));
        let record = tracker.block(&hash_of(BLOCK1)).expect("booked");
        assert_eq!(record.first_seen_at, Micros(100));
        assert_eq!(record.first_seen_server_id, 2);
        assert_eq!(record.announcers, 3);

        // Two servers stamped to the same microsecond: the one already
        // booked stays, because nothing makes the later arrival the earlier
        // sighting and "first" has to be one server.
        tracker.observe(4, &ann(1, BLOCK1), Micros(100));
        let record = tracker.block(&hash_of(BLOCK1)).expect("booked");
        assert_eq!(record.first_seen_at, Micros(100));
        assert_eq!(record.first_seen_server_id, 2, "a tie does not change it");
    }

    #[test]
    fn the_second_hash_at_a_height_opens_the_window() {
        let forked = fork(BLOCK1, "0badf00d");
        let mut tracker = Tracker::new(window());
        let opened = Micros(10 * MINUTE);

        assert_eq!(
            tracker
                .observe(1, &ann(1, BLOCK1), Micros(9 * MINUTE))
                .divergence,
            None,
            "one hash at a height is a chain, not a split"
        );
        assert_eq!(tracker.open_window(Micros(9 * MINUTE)), None);

        let split = tracker
            .observe(2, &ann(1, &forked), opened)
            .divergence
            .expect("a split");
        assert_eq!(
            split,
            Divergence {
                height: 1,
                hashes: vec![hash_of(BLOCK1), hash_of(&forked)],
                opened_at: opened,
                newly_opened: true,
            }
        );

        // A third server joining the minority branch is inside the window,
        // but it is not a new split.
        let joined = tracker
            .observe(3, &ann(1, &forked), Micros(11 * MINUTE))
            .divergence
            .expect("still split");
        assert!(!joined.newly_opened);
        assert_eq!(joined.opened_at, opened);

        let until = Micros(opened.as_i64() + 30 * MINUTE);
        assert_eq!(
            tracker.open_window(Micros(11 * MINUTE)),
            Some(Window {
                since: opened,
                until,
                heights: vec![1],
            })
        );
        assert_eq!(tracker.open_window(until), None, "closed at the deadline");
        assert_eq!(
            tracker.majority_at(1),
            Some(hash_of(&forked)),
            "two servers on the fork against one"
        );
    }

    #[test]
    fn a_two_block_fork_extends_the_window_and_is_polled_at_both_heights() {
        let fork1 = fork(BLOCK1, "0badf00d");
        let fork2 = fork(BLOCK2, "0badcafe");
        let mut tracker = Tracker::new(window());
        let first = Micros(10 * MINUTE);
        let second = Micros(20 * MINUTE);

        tracker.observe(1, &ann(1, BLOCK1), Micros(9 * MINUTE));
        tracker.observe(2, &ann(1, &fork1), first);
        tracker.observe(1, &ann(2, BLOCK2), Micros(19 * MINUTE));
        let extended = tracker
            .observe(2, &ann(2, &fork2), second)
            .divergence
            .expect("a second split");

        assert!(extended.newly_opened, "a new height is a new split");
        assert_eq!(
            extended.opened_at, first,
            "the episode started with the first split"
        );
        assert_eq!(
            tracker.open_window(second),
            Some(Window {
                since: first,
                until: Micros(second.as_i64() + 30 * MINUTE),
                heights: vec![1, 2],
            }),
            "both heights are polled, and the deadline moved"
        );
        // A third hash at a height that is already split extends it again
        // without listing the height twice.
        let third = Micros(25 * MINUTE);
        let again = tracker
            .observe(3, &ann(2, &fork(BLOCK2, "0badbeef")), third)
            .divergence
            .expect("a third branch");
        assert!(again.newly_opened);
        assert_eq!(again.hashes.len(), 3);
        let open = tracker.open_window(third).expect("still open");
        assert_eq!(open.heights, vec![1, 2]);
        assert_eq!(open.until, Micros(third.as_i64() + 30 * MINUTE));
    }

    #[test]
    fn a_window_is_reported_closed_once_and_only_after_its_deadline() {
        let forked = fork(BLOCK1, "0badf00d");
        let mut tracker = Tracker::new(window());
        let opened = Micros(10 * MINUTE);
        let until = Micros(opened.as_i64() + 30 * MINUTE);

        tracker.observe(1, &ann(1, BLOCK1), opened);
        tracker.observe(2, &ann(1, &forked), opened);

        assert_eq!(tracker.close_expired(Micros(until.as_i64() - 1)), vec![]);
        // The deadline itself is outside the window: an announcement stamped
        // exactly there is no longer being polled for.
        assert_eq!(
            tracker.observe(3, &ann(1, &forked), until).divergence,
            None,
            "the window is closed at its deadline, not after it"
        );
        assert_eq!(
            tracker.close_expired(until),
            vec![ClosedWindow {
                since: opened,
                until,
                heights: vec![1],
            }]
        );
        assert_eq!(tracker.close_expired(until), vec![], "reported once");
        assert_eq!(tracker.open_window(until), None);

        // An announcement at a height that is still split, after the window
        // closed, polls nothing: the episode is over.
        let late = tracker.observe(3, &ann(1, &forked), Micros(60 * MINUTE));
        assert_eq!(late.divergence, None);
        assert!(!late.first_seen);
    }

    #[test]
    fn a_split_after_an_unreported_window_retires_it_and_starts_another() {
        let mut tracker = Tracker::new(window());
        let first = Micros(10 * MINUTE);
        // Exactly the first window's deadline: the episode is over, so this
        // is a new window and not an extension of it.
        let later = Micros(first.as_i64() + 30 * MINUTE);

        tracker.observe(1, &ann(1, BLOCK1), first);
        tracker.observe(2, &ann(1, &fork(BLOCK1, "0badf00d")), first);
        tracker.observe(1, &ann(2, BLOCK2), later);
        tracker.observe(2, &ann(2, &fork(BLOCK2, "0badcafe")), later);

        assert_eq!(
            tracker.open_window(later),
            Some(Window {
                since: later,
                until: Micros(later.as_i64() + 30 * MINUTE),
                heights: vec![2],
            }),
            "a new episode, not an extension of the expired one"
        );
        assert_eq!(
            tracker.close_expired(later),
            vec![ClosedWindow {
                since: first,
                until: Micros(first.as_i64() + 30 * MINUTE),
                heights: vec![1],
            }],
            "the expired window is still reported"
        );
    }

    /// A height can be split in the book without being in the window: the
    /// seed carries yesterday's forks, which are not polled for. An
    /// announcement there is not a divergence just because some other height
    /// is being polled right now.
    #[test]
    fn only_the_heights_the_window_covers_report_a_divergence() {
        let old_fork = fork(BLOCK2, "0badcafe");
        let known = vec![
            KnownBlock {
                hash: hash_of(BLOCK2),
                height: 2,
                prev_hash: hash_of(BLOCK1),
                first_seen_at: Micros(1),
                first_seen_server_id: 1,
            },
            KnownBlock {
                hash: hash_of(&old_fork),
                height: 2,
                prev_hash: hash_of(BLOCK1),
                first_seen_at: Micros(2),
                first_seen_server_id: 2,
            },
        ];
        let mut tracker = Tracker::with_known_blocks(window(), known);
        let opened = Micros(10 * MINUTE);

        // A live split, at height 1 only.
        tracker.observe(1, &ann(1, BLOCK1), opened);
        tracker.observe(2, &ann(1, &fork(BLOCK1, "0badf00d")), opened);
        let open = tracker.open_window(opened).expect("open");
        assert_eq!(open.heights, vec![1]);

        let inside = tracker.observe(3, &ann(2, &old_fork), Micros(11 * MINUTE));
        assert_eq!(
            inside.divergence, None,
            "height 2 is split but nobody is polling it"
        );
        assert_eq!(tracker.hashes_at(2).len(), 2, "it is still a split height");
    }

    #[test]
    fn a_window_longer_than_the_epoch_saturates_instead_of_wrapping() {
        let mut tracker = Tracker::new(Duration::MAX);
        tracker.observe(1, &ann(1, BLOCK1), Micros(1));
        tracker.observe(2, &ann(1, &fork(BLOCK1, "0badf00d")), Micros(1));
        let open = tracker.open_window(Micros(2)).expect("open");
        assert_eq!(open.until, Micros(i64::MAX));
    }

    #[test]
    fn seeded_blocks_do_not_arm_a_window_for_a_split_already_known() {
        let forked = fork(BLOCK1, "0badf00d");
        let known = vec![
            KnownBlock {
                hash: hash_of(BLOCK1),
                height: 1,
                prev_hash: hash_of(GENESIS),
                first_seen_at: Micros(5),
                first_seen_server_id: 1,
            },
            KnownBlock {
                hash: hash_of(&forked),
                height: 1,
                prev_hash: hash_of(GENESIS),
                first_seen_at: Micros(6),
                first_seen_server_id: 2,
            },
            // The same row twice, which a caller should not do and which must
            // not look like a third branch.
            KnownBlock {
                hash: hash_of(BLOCK1),
                height: 1,
                prev_hash: hash_of(GENESIS),
                first_seen_at: Micros(5),
                first_seen_server_id: 1,
            },
        ];
        let mut tracker = Tracker::with_known_blocks(window(), known);
        assert_eq!(tracker.block_count(), 2);
        assert_eq!(tracker.hashes_at(1).len(), 2);
        assert_eq!(
            tracker.block(&hash_of(BLOCK1)).expect("seeded").announcers,
            0,
            "the blocks table does not count announcers"
        );

        let after_restart = tracker.observe(1, &ann(1, BLOCK1), Micros(1_000));
        assert_eq!(after_restart.divergence, None, "yesterday's fork is known");
        assert!(!after_restart.first_seen);
        assert_eq!(tracker.open_window(Micros(1_000)), None);
        assert_eq!(
            tracker
                .block(&hash_of(BLOCK1))
                .expect("seeded")
                .first_seen_at,
            Micros(5),
            "the seeded sighting is earlier and stands"
        );

        // A branch that is new to the database still arms.
        let fresh = tracker.observe(2, &ann(1, &fork(BLOCK1, "0badcafe")), Micros(2_000));
        assert!(
            fresh.divergence.expect("a new branch").newly_opened,
            "a hash nobody has seen is a new split"
        );
    }

    #[test]
    fn the_majority_is_the_hash_the_most_servers_announced() {
        let forked = fork(BLOCK1, "0badf00d");
        let mut tracker = Tracker::new(window());
        assert_eq!(tracker.majority_at(1), None, "an unknown height");

        tracker.observe(1, &ann(1, BLOCK1), Micros(1));
        assert_eq!(
            tracker.majority_at(1),
            Some(hash_of(BLOCK1)),
            "one hash is its own majority"
        );

        tracker.observe(2, &ann(1, &forked), Micros(2));
        assert_eq!(tracker.majority_at(1), None, "one each");

        tracker.observe(3, &ann(1, &forked), Micros(3));
        assert_eq!(tracker.majority_at(1), Some(hash_of(&forked)));

        tracker.observe(4, &ann(1, BLOCK1), Micros(4));
        assert_eq!(tracker.majority_at(1), None, "level again");

        tracker.observe(5, &ann(1, BLOCK1), Micros(5));
        assert_eq!(tracker.majority_at(1), Some(hash_of(BLOCK1)));
    }

    #[test]
    fn the_book_is_pruned_to_the_retarget_window_below_the_tip() {
        let mut tracker = Tracker::new(window());
        let tip = PRUNE_DEPTH + 10;
        for height in 0..=tip {
            let hex = fork(BLOCK1, &format!("{height:08x}"));
            tracker.observe(1, &ann(height, &hex), Micros(height as i64));
        }
        assert_eq!(
            tracker.block_count(),
            (PRUNE_DEPTH + 1) as usize,
            "the cutoff height and everything above it"
        );
        assert_eq!(tracker.hashes_at(9), &[], "below the cutoff, forgotten");
        assert_eq!(tracker.hashes_at(10).len(), 1, "the cutoff itself, kept");
        assert_eq!(tracker.hashes_at(tip).len(), 1, "the tip, kept");
    }

    #[test]
    fn seeding_is_pruned_too() {
        let known = (0..=PRUNE_DEPTH + 10)
            .map(|height| KnownBlock {
                hash: hash_of(&fork(BLOCK1, &format!("{height:08x}"))),
                height,
                prev_hash: hash_of(GENESIS),
                first_seen_at: Micros(height as i64),
                first_seen_server_id: 1,
            })
            .collect::<Vec<_>>();
        let tracker = Tracker::with_known_blocks(window(), known);
        assert_eq!(tracker.block_count(), (PRUNE_DEPTH + 1) as usize);
        assert_eq!(tracker.hashes_at(9), &[]);
    }

    #[test]
    fn an_empty_tracker_answers_nothing_rather_than_panicking() {
        let mut tracker = Tracker::new(window());
        assert_eq!(tracker.block_count(), 0);
        assert_eq!(tracker.tip_of(1), None);
        assert_eq!(tracker.hashes_at(0), &[]);
        assert_eq!(tracker.majority_at(0), None);
        assert_eq!(tracker.open_window(Micros(0)), None);
        assert_eq!(tracker.close_expired(Micros(0)), vec![]);
        tracker.session_started(1);
        assert_eq!(tracker.tip_of(1), None);
    }
}
