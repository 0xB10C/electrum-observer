//! Where the first servers come from.
//!
//! Discovery (DESIGN.md section 7) only works once there is something to ask,
//! and the thing it asks is a server this crate was told about by other
//! means. There are three such means and they are all here: a file the
//! operator wrote, the hand-picked list Sparrow Wallet ships, and the server
//! table at <https://1209k.com/bitcoin-eye/>, which is the only public census
//! of Electrum servers that is kept current. Each one produces
//! [`Endpoint`]s, and `electrum-observer import` writes them into `servers`
//! with the matching `source` (DESIGN.md section 4), so a later query can ask
//! where a server was learned from as well as what it answered.
//!
//! None of this is on the measurement path: an import is a command an
//! operator runs, it touches the network once if at all, and what it writes
//! is read by the next `run`. So the parsers here are allowed to be
//! deliberate about saying what they could not read -- a line number for a
//! file, a count of rows for the table -- where a session would only be
//! allowed to log it.

use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::debug;

use crate::TARGET_SEEDS;
use crate::endpoint::Endpoint;
use crate::settings::Chain;

/// The `servers.source` value for endpoints that came from a file.
///
/// The same spelling the configuration's `servers_file` uses, because they
/// are the same thing said twice: a list the operator chose. DESIGN.md
/// section 4 names four sources and this is one of them.
pub const SOURCE_FILE: &str = "config";

/// The `servers.source` value for the built-in Sparrow list.
pub const SOURCE_SPARROW: &str = "sparrow";

/// The `servers.source` value for the 1209k table.
pub const SOURCE_1209K: &str = "1209k";

/// Reads a file of endpoints, one per line.
///
/// Either spelling is accepted, because both are what people have in their
/// files: `ssl://host:port` from this crate's own output and `host:port:s`
/// from Electrum's. `#` starts a comment, to the end of the line, and blank
/// lines are nothing.
///
/// A line that is not an endpoint is an error and not a warning: this file is
/// what the operator asked to be watched, and a typo that silently drops one
/// server out of six hundred is a hole in a measurement nobody would notice
/// for weeks. The error names the line number and the text, which is what it
/// takes to fix it.
pub fn from_file(path: impl AsRef<Path>) -> Result<Vec<Endpoint>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the server list {}", path.display()))?;
    let endpoints = parse_file(&text).with_context(|| format!("in {}", path.display()))?;
    debug!(
        target: TARGET_SEEDS,
        path = %path.display(),
        endpoints = endpoints.len(),
        "server list read",
    );
    Ok(endpoints)
}

/// The parse alone, without the file, so the line numbers can be tested
/// without one.
fn parse_file(text: &str) -> Result<Vec<Endpoint>> {
    let mut endpoints = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        // Numbered the way an editor numbers them, because the number is for
        // the person who has the file open.
        let number = index + 1;
        let line = match raw.split_once('#') {
            Some((before, _comment)) => before.trim(),
            None => raw.trim(),
        };
        if line.is_empty() {
            continue;
        }
        let endpoint = line
            .parse::<Endpoint>()
            .with_context(|| format!("line {number}: {line:?}"))?;
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}

/// The public servers Sparrow Wallet ships, per chain.
///
/// Sparrow is a wallet with a server picker, so its list is a set of servers
/// someone maintains against the ones that actually answer, which is exactly
/// what a seed list wants to be and exactly what a wallet's own list is
/// usually not. It is hardcoded rather than fetched because it is a Java
/// source file in another project's repository: there is no endpoint to ask,
/// and a list that changes twice a year is better as a diff in a commit than
/// as a parse of someone's `master` branch.
///
/// Copied from
/// <https://github.com/sparrowwallet/sparrow/blob/master/src/main/java/com/sparrowwallet/sparrow/net/PublicElectrumServer.java>
/// as of 2026-11-20. Regtest has none, because a regtest server is
/// necessarily somebody's own.
pub fn sparrow(chain: Chain) -> Vec<Endpoint> {
    let list: &[&str] = match chain {
        Chain::Mainnet => &[
            "ssl://blockstream.info:700",
            "ssl://electrum.blockstream.info:50002",
            "ssl://bitcoin.lu.ke:50002",
            "ssl://electrum.emzy.de:50002",
            "ssl://electrum.bitaroo.net:50002",
            "ssl://electrum.diynodes.com:50022",
            "ssl://fulcrum.sethforprivacy.com:50002",
            "ssl://frigate.2140.dev:50002",
        ],
        Chain::Testnet3 => &[
            "ssl://testnet.aranguren.org:51002",
            "ssl://testnet.qtornado.com:51002",
        ],
        Chain::Testnet4 => &[
            "ssl://mempool.space:40002",
            "ssl://blackie.c3-soft.com:57010",
        ],
        Chain::Signet => &["ssl://mempool.space:60602"],
        Chain::Regtest => &[],
    };
    list.iter()
        .map(|text| {
            // These are constants of this file, and a test parses every one
            // of them, so a failure here is this list being edited wrongly
            // rather than anything a run can encounter.
            text.parse()
                .unwrap_or_else(|e| panic!("the built-in Sparrow list is endpoints: {e}"))
        })
        .collect()
}

/// One row of the 1209k server table.
///
/// The three columns beyond the endpoint are kept because they are the
/// table's own view of a server and this crate is about to form its own: what
/// software 1209k saw, which protocol version it negotiated, and whether it
/// was answering at all when the page was rendered. An import does not act on
/// any of them -- a `CLOSED` server is still inserted, because a server that
/// is down today is a server to watch recovering -- but they are what makes a
/// skipped or surprising row readable afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row1209k {
    /// Host, port and transport, from the first three columns.
    pub endpoint: Endpoint,
    /// The `server.version` string 1209k saw, `None` when the cell is empty.
    pub version: Option<String>,
    /// The negotiated protocol version, as `1.4`.
    pub protocol: Option<String>,
    /// `OK`, `CLOSED`, `BEHIND`, or whatever else the page says.
    pub status: Option<String>,
}

/// The table, with the rows that were not endpoints counted.
///
/// The count is part of the result rather than only a log line because it is
/// the one number that says whether this parser still understands the page:
/// rows that stop being endpoints are how a changed column order looks from
/// the inside, and `import` prints it so an operator sees it without turning
/// logging up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table1209k {
    pub rows: Vec<Row1209k>,
    pub skipped: usize,
}

/// The rows of the 1209k server table, as HTML.
///
/// See [`parse_1209k_table`], which this is the common case of: the rows
/// alone, for a caller that does not report what it could not read.
pub fn parse_1209k(html: &str) -> Result<Vec<Row1209k>> {
    Ok(parse_1209k_table(html)?.rows)
}

/// The 1209k server table, parsed out of the page.
///
/// Hand-rolled over `<tr>` and `<td>` rather than through an HTML crate,
/// because the page is machine-generated PHP output with one table of twelve
/// columns and one of two; a parser that finds the tags, strips whatever
/// markup is inside a cell and decodes the entities `htmlspecialchars` can
/// have put there is the whole job, and an HTML crate is a dependency that
/// would otherwise be pulled in for one import command.
///
/// Tolerant by design, because the page is somebody else's and will change:
/// a row with fewer than three cells is not a server row at all -- the
/// chain index at the foot of the page is two columns -- and a row whose
/// first three cells do not form an [`Endpoint`] is skipped and counted
/// rather than failing the import. What is *not* tolerated is a page with no
/// server rows in it, which is the shape a redesign or an error page has, and
/// which would otherwise import nothing and report success.
pub fn parse_1209k_table(html: &str) -> Result<Table1209k> {
    let (rows, skipped) = parse_rows(html);
    if rows.is_empty() {
        bail!(
            "no server rows in the 1209k page: {skipped} rows were not endpoints, \
             out of {} bytes -- the page's layout is not the one this parser knows",
            html.len()
        );
    }
    debug!(
        target: TARGET_SEEDS,
        rows = rows.len(),
        skipped,
        "1209k table parsed",
    );
    Ok(Table1209k { rows, skipped })
}

/// The column positions in the `<thead>` of 2026-11-20: Host, Port, Proto,
/// UTXO Root, Height, Blocktime, Version, Protocol, Connection,
/// ConnectionTime, Status, Uptime.
const COL_HOST: usize = 0;
const COL_PORT: usize = 1;
const COL_PROTO: usize = 2;
const COL_VERSION: usize = 6;
const COL_PROTOCOL: usize = 7;
const COL_STATUS: usize = 10;

/// How many cells a row needs before it is read as a server at all.
const COLUMNS_MIN: usize = 3;

/// The rows and the count of the ones that were not endpoints.
fn parse_rows(html: &str) -> (Vec<Row1209k>, usize) {
    let mut rows = Vec::new();
    let mut skipped = 0;
    for row in elements(html, "tr") {
        let cells: Vec<String> = elements(row, "td").map(cell_text).collect();
        if cells.len() < COLUMNS_MIN {
            continue;
        }
        let Some(endpoint) = endpoint_of(&cells[COL_HOST], &cells[COL_PORT], &cells[COL_PROTO])
        else {
            skipped += 1;
            continue;
        };
        rows.push(Row1209k {
            endpoint,
            version: field(&cells, COL_VERSION),
            protocol: field(&cells, COL_PROTOCOL),
            status: field(&cells, COL_STATUS),
        });
    }
    (rows, skipped)
}

/// The first three cells as an endpoint, or `None` when they are not one.
///
/// Built as the canonical spelling and handed to [`Endpoint`], so that the
/// rules are the ones every other source is held to: the port has to be a
/// port, the host has to be a hostname or an address, and a `.onion` host has
/// to be a v3 address. 1209k's onion rows are v3 and are kept -- a Tor-only
/// server is a server, and whether a session is opened to it is
/// `tor.enabled`'s business and not the importer's.
fn endpoint_of(host: &str, port: &str, proto: &str) -> Option<Endpoint> {
    format!("{proto}://{host}:{port}").parse().ok()
}

/// A column that is there and not empty.
fn field(cells: &[String], index: usize) -> Option<String> {
    cells.get(index).filter(|text| !text.is_empty()).cloned()
}

/// The contents of every `<name>` element, outer tags removed.
///
/// Attributes are allowed on the opening tag and ignored, nesting of the same
/// element is not expected and not handled -- there is none in a table of
/// text -- and an element that is never closed is dropped rather than
/// swallowing the rest of the document.
fn elements<'a>(html: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    // Tag names are matched without regard to case, so the search is done on
    // a lowercased copy and the slices are taken from the original.
    // `to_ascii_lowercase` leaves every byte's length alone, so the offsets
    // mean the same thing in both.
    let lower = html.to_ascii_lowercase();
    let open = format!("<{name}");
    let close = format!("</{name}");
    let mut at = 0;
    std::iter::from_fn(move || {
        loop {
            let found = at + lower.get(at..)?.find(&open)?;
            // `<trumpet>` is not a `<tr>`: the character after the name has
            // to end it.
            let after_name = found + open.len();
            let ends = lower.as_bytes().get(after_name).copied();
            if !matches!(
                ends,
                Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
            ) {
                at = after_name;
                continue;
            }
            // An element that is never closed ends the iteration: whatever
            // follows is not a row, and swallowing the rest of the document
            // into one cell would turn a truncated page into a server.
            let tag_end = lower.get(after_name..).and_then(|rest| rest.find('>'))?;
            let start = after_name + tag_end + 1;
            let end = lower.get(start..).and_then(|rest| rest.find(&close))?;
            at = start + end + close.len();
            return Some(&html[start..start + end]);
        }
    })
}

/// A cell's text: whatever is not a tag, with entities decoded and the ends
/// trimmed.
///
/// A `>` that is not closing a tag is text and is kept: HTML allows it
/// unescaped, a version string may well have one in it, and swallowing it
/// would mean a cell that starts one byte off still looked like a plausible
/// hostname.
fn cell_text(cell: &str) -> String {
    let mut text = String::with_capacity(cell.len());
    let mut in_tag = false;
    for character in cell.chars() {
        match (character, in_tag) {
            ('<', _) => in_tag = true,
            ('>', true) => in_tag = false,
            (_, true) => {}
            (character, false) => text.push(character),
        }
    }
    decode_entities(text.trim()).into_owned()
}

/// The entities a table of hostnames and version strings can contain.
///
/// Not an HTML entity table: the page is generated by `htmlspecialchars`,
/// which produces exactly these, and a server whose version string contains
/// an ampersand is the only way any of them appears at all. Anything else is
/// left as it was written, because a literal `&` in a cell is far more likely
/// than an entity this list is missing.
fn decode_entities(text: &str) -> Cow<'_, str> {
    if !text.contains('&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let replacement = ENTITIES.iter().find(|(entity, _)| tail.starts_with(entity));
        match replacement {
            Some((entity, decoded)) => {
                out.push_str(decoded);
                rest = &tail[entity.len()..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The entities, longest first where one is a prefix of another.
const ENTITIES: &[(&str, &str)] = &[
    ("&amp;", "&"),
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", "\""),
    ("&apos;", "'"),
    ("&#039;", "'"),
    ("&#39;", "'"),
    ("&nbsp;", " "),
];

/// How long the whole fetch may take, TLS and body included.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches the 1209k server table for `chain`.
///
/// Blocking, and called from the `import` subcommand rather than from the
/// collector: it is one request a person asked for, not something a run
/// depends on.
///
/// Mainnet only. The site serves other chains under other `chain` parameters
/// -- `tbtc`, `tbtc4` and a few dozen altcoins are linked at the foot of the
/// page -- but which of them is this crate's `testnet3` and which is its
/// `testnet4` is a guess until somebody checks against a server, and an
/// import that guesses wrong fills `servers` with another chain's hosts that
/// every session would then disable for a genesis mismatch. So the other
/// chains are an error that says to use `import file` instead.
pub fn fetch_1209k(chain: Chain) -> Result<String> {
    let url = url_1209k(chain)?;
    // A User-Agent that names the tool and its version, because this is a
    // small site being scraped by a daemon's operator: whoever reads those
    // logs should be able to tell what asked and where to complain about it.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(FETCH_TIMEOUT))
        .user_agent(format!("electrum-observer/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let html = agent
        .get(&url)
        .call()
        .with_context(|| format!("fetching {url}"))?
        .body_mut()
        .read_to_string()
        .with_context(|| format!("reading the body of {url}"))?;
    debug!(target: TARGET_SEEDS, url, bytes = html.len(), "1209k page fetched");
    Ok(html)
}

/// The page this chain's servers are listed on.
fn url_1209k(chain: Chain) -> Result<String> {
    match chain {
        Chain::Mainnet => Ok("https://1209k.com/bitcoin-eye/ele.php?chain=btc".to_string()),
        other => bail!(
            "1209k import is mainnet only, and the configured chain is {}: \
             use `import file` with a list for that chain",
            format!("{other:?}").to_lowercase()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    /// The live page, fetched on 2026-11-20 and committed beside the tests.
    ///
    /// The parser is tested against this and never against the network: a
    /// test that fetches is a test that fails when a site is down, and the
    /// thing being tested is this crate's reading of a page and not the
    /// page's availability.
    const FIXTURE: &str = include_str!("../tests/fixtures/1209k-btc-2026-11-20.html");

    /// Writes a file in a temporary directory and returns its path.
    fn file(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut handle = std::fs::File::create(&path).expect("a writable temporary directory");
        handle.write_all(body.as_bytes()).expect("a short write");
        path
    }

    /// Both spellings, because both are what people have in their files.
    #[test]
    fn a_file_is_read_in_either_spelling() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = file(
            &dir,
            "servers.txt",
            "ssl://electrum.blockstream.info:50002\nbitcoin.lu.ke:50002:s\ntcp://1.2.3.4:50001\n",
        );

        let endpoints = from_file(&path).expect("a file of endpoints");

        let printed: Vec<String> = endpoints.iter().map(Endpoint::to_string).collect();
        assert_eq!(
            printed,
            [
                "ssl://electrum.blockstream.info:50002",
                "ssl://bitcoin.lu.ke:50002",
                "tcp://1.2.3.4:50001",
            ]
        );
    }

    /// Comments, blank lines and trailing whitespace are nothing, including a
    /// comment on the end of a line that is also an endpoint.
    #[test]
    fn comments_and_blank_lines_are_not_endpoints() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = file(
            &dir,
            "servers.txt",
            "# the ones from thread #167\n\
             \n   \n\
             ssl://bitcoin.grey.pw:50002   # the positive control\n\
             \t\n\
             #ssl://disabled.example:50002\n\
             tcp://fulcrum.grey.pw:50001\n",
        );

        let endpoints = from_file(&path).expect("a file of endpoints");

        let printed: Vec<String> = endpoints.iter().map(Endpoint::to_string).collect();
        assert_eq!(
            printed,
            ["ssl://bitcoin.grey.pw:50002", "tcp://fulcrum.grey.pw:50001"]
        );
    }

    /// A file of nothing but comments is no endpoints and not an error.
    #[test]
    fn a_file_of_comments_is_empty() {
        assert_eq!(parse_file("# nothing\n\n# here\n").expect("a parse"), []);
    }

    /// The error names the line number and the text, which is what it takes
    /// to find the line in an editor.
    #[test]
    fn a_bad_line_names_its_number_and_its_text() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = file(
            &dir,
            "servers.txt",
            "ssl://good.example:50002\n\n# a comment\nhttp://bad.example:50002\n",
        );

        let error = from_file(&path).expect_err("a bad line is an error");

        let message = format!("{error:#}");
        assert!(message.contains("line 4"), "{message}");
        assert!(message.contains("http://bad.example:50002"), "{message}");
        assert!(message.contains("servers.txt"), "{message}");
    }

    /// A file that is not there names itself rather than a line.
    #[test]
    fn a_missing_file_is_an_error_about_the_file() {
        let error = from_file("/nonexistent/servers.txt").expect_err("no such file");

        let message = format!("{error:#}");
        assert!(message.contains("/nonexistent/servers.txt"), "{message}");
    }

    /// The mainnet list is the eight servers Sparrow ships, and every entry
    /// of every chain's list parses.
    #[test]
    fn the_sparrow_lists_are_endpoints() {
        assert_eq!(sparrow(Chain::Mainnet).len(), 8);
        assert_eq!(sparrow(Chain::Testnet3).len(), 2);
        assert_eq!(sparrow(Chain::Testnet4).len(), 2);
        assert_eq!(sparrow(Chain::Signet).len(), 1);
        assert_eq!(sparrow(Chain::Regtest), []);

        for chain in [
            Chain::Mainnet,
            Chain::Testnet3,
            Chain::Testnet4,
            Chain::Signet,
        ] {
            for endpoint in sparrow(chain) {
                // Round trips, which is the parse having normalised nothing
                // away: these are written canonically in the list above.
                let printed = endpoint.to_string();
                assert_eq!(
                    printed.parse::<Endpoint>().expect("a canonical endpoint"),
                    endpoint
                );
            }
        }
        assert!(
            sparrow(Chain::Mainnet)
                .iter()
                .any(|e| e.to_string() == "ssl://blockstream.info:700"),
            "the shortest port in the list is not dropped"
        );
    }

    /// The fixture is the whole table: every row of it is an endpoint, and
    /// the ones that make the page worth parsing at all are in it.
    #[test]
    fn the_fixture_parses_into_the_whole_table() {
        let table = parse_1209k_table(FIXTURE).expect("the fixture is the 1209k page");

        assert!(
            table.rows.len() >= 300,
            "the page lists hundreds of servers, not {}",
            table.rows.len()
        );
        assert_eq!(table.skipped, 0, "every server row of the fixture parses");

        let printed: Vec<String> = table
            .rows
            .iter()
            .map(|row| row.endpoint.to_string())
            .collect();
        assert!(
            printed.contains(&"ssl://electrum.blockstream.info:50002".to_string()),
            "a server everyone knows is in the table"
        );
        assert!(
            printed.iter().any(|text| text.starts_with("tcp://")),
            "the table has plain TCP ports as well as TLS ones"
        );
        assert!(
            table
                .rows
                .iter()
                .any(|row| row.endpoint.network() == crate::endpoint::Network::Onion),
            "the onion rows are kept"
        );
    }

    /// The columns beside the endpoint, which are what makes a row readable
    /// afterwards.
    #[test]
    fn the_fixture_rows_carry_the_version_columns() {
        let rows = parse_1209k(FIXTURE).expect("the fixture is the 1209k page");

        for software in ["Fulcrum", "ElectrumX", "electrs"] {
            assert!(
                rows.iter().any(|row| {
                    row.version
                        .as_deref()
                        .is_some_and(|version| version.contains(software))
                }),
                "{software} is one of the implementations the table lists"
            );
        }
        assert!(
            rows.iter()
                .any(|row| row.protocol.as_deref() == Some("1.4")),
            "the protocol column is the negotiated version"
        );
        assert!(
            rows.iter().any(|row| row.status.as_deref() == Some("OK")),
            "the status column is read from the eleventh cell"
        );
        assert!(
            rows.iter()
                .any(|row| row.status.as_deref() == Some("CLOSED")),
            "a server that was not answering is still a row"
        );
        assert!(
            rows.iter().any(|row| row.version.is_none()),
            "an empty cell is None rather than an empty string"
        );
    }

    /// A minimal table of the shape the page has, with a header, a junk row
    /// and the two-column chain index at the foot.
    const MINIMAL: &str = "\
<html><body><h3>Monitored Servers</h3>
<table border='0'>
<thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>UTXO Root</th><th>Height</th>\
<th>Blocktime</th><th>Version</th><th>Protocol</th><th>Connection</th>\
<th>ConnectionTime</th><th>Status</th><th>Uptime</th></tr></thead>
<tbody><tr><td>electrum.example</td><td>50002</td><td>ssl</td><td>00000000</td><td>976686</td>\
<td>2026-11-20 04:55:31</td><td>Fulcrum 2.1.4</td><td>1.4</td><td>open</td>\
<td>2026-11-20 04:57:41</td><td>OK</td><td>1.0000 1.0000 0.9998</td></tr>
<tr><td>not a host at all</td><td>banana</td><td>ssl</td><td>00000000</td><td>976686</td>\
<td>2026-11-20 04:55:31</td><td>Fulcrum 2.1.4</td><td>1.4</td><td>open</td>\
<td>2026-11-20 04:57:41</td><td>OK</td><td>1.0000 1.0000 0.9998</td></tr>
<tr><td>tcp.example</td><td>50001</td><td>tcp</td><td>00000000</td><td>976686</td>\
<td>2026-11-20 04:55:31</td><td></td><td>1.4</td><td>open</td>\
<td>2026-11-20 04:57:41</td><td>CLOSED</td><td>0.0000 0.0000 0.5000</td></tr>
</tbody></table>
<table><tbody><tr><td><a href='ele.php?chain=ltc'>ltc</a></td><td>19</td></tr>
</tbody></table></body></html>";

    /// The junk row is skipped and counted; the chain index at the foot is
    /// not a server row and is not counted as one.
    #[test]
    fn a_junk_row_is_skipped_and_counted() {
        let table = parse_1209k_table(MINIMAL).expect("a table with two good rows");

        let printed: Vec<String> = table
            .rows
            .iter()
            .map(|row| row.endpoint.to_string())
            .collect();
        assert_eq!(
            printed,
            ["ssl://electrum.example:50002", "tcp://tcp.example:50001"]
        );
        assert_eq!(
            table.skipped, 1,
            "the junk row is counted, the index is not"
        );
        assert_eq!(table.rows[1].version, None, "an empty cell is no version");
        assert_eq!(table.rows[1].status.as_deref(), Some("CLOSED"));
    }

    /// A page with no server rows is an error rather than an empty import:
    /// that is the shape a redesign, an error page or a wrong URL has.
    #[test]
    fn a_page_without_server_rows_is_an_error() {
        let error = parse_1209k("<html><body><p>down for maintenance</p></body></html>")
            .expect_err("nothing to import");
        let message = format!("{error:#}");
        assert!(message.contains("no server rows"), "{message}");

        let only_index = "<table><tr><td><a href='ele.php?chain=ltc'>ltc</a></td><td>19</td></tr>\
                          </table>";
        assert!(
            parse_1209k(only_index).is_err(),
            "two columns is not a server"
        );
    }

    /// Attributes, uppercase tags, nested markup inside a cell and whitespace
    /// around it: the page is somebody else's and may grow any of them.
    #[test]
    fn cells_are_read_through_tags_and_whitespace() {
        let html = "<TABLE><TR CLASS='odd'><TD> electrum.example </TD><TD>50002</TD>\
                    <TD><b>ssl</b></TD><TD>x</TD><TD>x</TD><TD>x</TD>\
                    <TD><span title='v'>Fulcrum 2.1.4</span></TD><TD>1.4</TD><TD>open</TD>\
                    <TD>x</TD><TD>OK</TD><TD>1.0</TD></TR></TABLE>";

        let rows = parse_1209k(html).expect("one row");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].endpoint.to_string(), "ssl://electrum.example:50002");
        assert_eq!(rows[0].version.as_deref(), Some("Fulcrum 2.1.4"));
    }

    /// A cell's text begins after its opening tag and keeps a `>` that is not
    /// closing one: a cell read a byte early would otherwise still look like a
    /// hostname, and an unescaped `>` in a version string is legal HTML.
    #[test]
    fn a_cell_starts_after_its_tag_and_keeps_a_stray_angle_bracket() {
        assert_eq!(cell_text(" electrum.example "), "electrum.example");
        assert_eq!(cell_text(">electrum.example"), ">electrum.example");
        assert_eq!(cell_text("Fulcrum > 2.0"), "Fulcrum > 2.0");
        assert_eq!(cell_text(" <b>ssl</b> "), "ssl");
    }

    /// An element that is never closed ends the parse rather than swallowing
    /// the document, and a tag whose name merely starts with one of ours is
    /// not one of ours.
    #[test]
    fn unclosed_and_lookalike_tags_are_not_rows() {
        assert!(parse_1209k("<table><tr><td>a</td><td>b</td><td>c</td>").is_err());
        assert!(
            parse_1209k("<trumpet><td>electrum.example</td><td>50002</td><td>ssl</td></trumpet>")
                .is_err()
        );
    }

    /// Entity decoding, which is what a version string with an ampersand in
    /// it would arrive as.
    #[test]
    fn entities_in_a_cell_are_decoded() {
        let html = "<tr><td>electrum.example</td><td>50002</td><td>ssl</td><td>x</td><td>x</td>\
                    <td>x</td><td>Fulcrum &amp; friends &lt;2&gt; &quot;beta&quot; &#39;rc&#039; \
                    &apos;z&apos;&nbsp;&notanentity;</td><td>1.4</td><td>open</td><td>x</td>\
                    <td>OK</td><td>1.0</td></tr>";

        let rows = parse_1209k(html).expect("one row");

        assert_eq!(
            rows[0].version.as_deref(),
            Some("Fulcrum & friends <2> \"beta\" 'rc' 'z' &notanentity;")
        );
    }

    /// Text without an ampersand is returned as it was, which is the common
    /// case and the reason for the borrow.
    #[test]
    fn text_without_entities_is_not_copied() {
        assert!(matches!(
            decode_entities("Fulcrum 2.1.4"),
            Cow::Borrowed("Fulcrum 2.1.4")
        ));
    }

    /// A column that is not there is `None` rather than a panic: the page
    /// could lose a column tomorrow.
    #[test]
    fn a_short_row_keeps_the_endpoint_and_drops_the_rest() {
        let rows = parse_1209k("<tr><td>electrum.example</td><td>50002</td><td>ssl</td></tr>")
            .expect("three columns are an endpoint");

        assert_eq!(rows[0].endpoint.to_string(), "ssl://electrum.example:50002");
        assert_eq!(rows[0].version, None);
        assert_eq!(rows[0].protocol, None);
        assert_eq!(rows[0].status, None);
    }

    /// A row of two cells is the chain index and is not an endpoint however
    /// much it looks like one.
    #[test]
    fn two_cells_are_not_a_server() {
        let (rows, skipped) = parse_rows("<tr><td>electrum.example</td><td>50002</td></tr>");
        assert_eq!(rows, []);
        assert_eq!(skipped, 0);
    }

    /// Every way the first three cells can fail to be an endpoint, because
    /// each of them is a row the live page has had at some point.
    #[test]
    fn the_three_columns_have_to_be_an_endpoint() {
        assert!(endpoint_of("electrum.example", "50002", "ssl").is_some());
        assert!(endpoint_of("electrum.example", "50002", "tcp").is_some());
        assert!(endpoint_of("electrum.example", "50002", "wss").is_none());
        assert!(endpoint_of("electrum.example", "0", "ssl").is_none());
        assert!(endpoint_of("electrum.example", "", "ssl").is_none());
        assert!(endpoint_of("", "50002", "ssl").is_none());
        assert!(endpoint_of("not a host", "50002", "ssl").is_none());
        // A v3 onion is a server; a v2 one names nothing that can be reached.
        assert!(
            endpoint_of(
                "kittycp2gatrqhlwpmbczk5rblw62enrpo2rzwtkfrrr27hq435d4vid.onion",
                "50001",
                "tcp"
            )
            .is_some()
        );
        assert!(endpoint_of("kittycp2gatrqhlw.onion", "50001", "tcp").is_none());
    }

    /// Mainnet is the only chain whose page parameter has been checked.
    #[test]
    fn the_url_is_the_mainnet_table() {
        let url = url_1209k(Chain::Mainnet).expect("mainnet is served");
        assert!(
            url.starts_with("https://1209k.com/bitcoin-eye/ele.php"),
            "{url}"
        );
        assert!(url.ends_with("chain=btc"), "{url}");

        for chain in [
            Chain::Testnet3,
            Chain::Testnet4,
            Chain::Signet,
            Chain::Regtest,
        ] {
            let error = url_1209k(chain).expect_err("1209k import is mainnet only");
            let message = format!("{error:#}");
            assert!(message.contains("mainnet only"), "{message}");
            assert!(
                message.contains(&format!("{chain:?}").to_lowercase()),
                "{message} names {chain:?}"
            );
        }
    }
}
