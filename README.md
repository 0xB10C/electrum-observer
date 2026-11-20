# electrum-observer

Connects to public Electrum servers, keeps the connections open, and records
everything they answer into one SQLite database. The question behind it is
whether servers that look independent -- different hostnames, different
addresses, different operators -- are in fact the same infrastructure: several
public endpoints in front of one `bitcoind`, which is what an adversary who
wants to see the addresses Electrum wallets ask about would cheaply build.
The signals that could answer it are timing (when each server first announces
a new block, and when it changes its mind during a chain split), identity
(certificates, resolved addresses, banners, advertised peers, versions) and
response equality (fee histograms, fee estimates, verbatim error strings).
This collects all of them with one clock and one schema; the pairwise analysis
is then an offline question for SQL, DuckDB or Python.

Background: [0xB10C/project-ideas#11](https://github.com/0xB10C/project-ideas/issues/11),
[Electrum server monitoring](https://bnoc.xyz/t/electrum-server-monitoring/135)
and [header propagation and shared infrastructure](https://bnoc.xyz/t/electrum-server-monitoring-header-propagation-and-shared-infrastructure/167).

Nothing in this database is evidence of anything on its own. Two servers
answering identically may share a backend, or may both be running the same
software with the same defaults; two servers announcing a block milliseconds
apart may share a node, or may be two well-connected nodes in the same city.
The tool collects signals and does not judge them.

## What is collected

Every timestamp is an integer of microseconds since the Unix epoch, taken
where the bytes arrived rather than where the row was written: the whole
method is a difference of tens of milliseconds between two servers, so a
stamp that meant "when the writer got round to it" would be the measurement
rather than the data.

- **Header announcements.** The reply to `blockchain.headers.subscribe` and
  every later notification is a `header_events` row -- which server, which
  hash, which height, when, and whether the server contradicted its own
  previous announcement (`reorg`). `blocks` is the cross-server block book:
  one row per hash, with who was first with it and when.
- **Divergence polling.** When two hashes show up at one height, every
  session polls `blockchain.block.header` for that height until the window
  closes, into `tip_checks`. A subscription says when a server announces a new
  tip; only polling says when it switched to the other branch.
- **Probe sets**, in `probes`. One row per set asked at one moment, with
  `params`, the result and the errors aligned by index. The sets are the fee
  set (`mempool.get_fee_histogram`, `blockchain.estimatefee` at the ordinary
  confirmation targets plus the edge cases and the `mode` variants,
  `blockchain.relayfee`, `mempool.get_info`), the identity set
  (`server.features`, `server.banner`, `server.donation_address`,
  `server.peers.subscribe`) and the fingerprint set: nine deliberately odd
  requests -- an unknown method, a negative height, a string where a number
  belongs, a batch, a second `server.version` -- whose verbatim error strings
  differ between implementations.
- **Probe results**, content-addressed in `blobs`. Identical answers across
  servers and over time share one row, so "did these two answer the same
  thing" is an equality of two `result_blob` values rather than a JSON
  comparison.
- **Advertised peers**, in `peer_edges`: `server.peers.subscribe` normalised
  to one row per advertised peer, written whether or not that peer is ever
  connected to, because who advertises whom is its own graph.
- **Latency**, in `pings`. `server.ping` keeps ElectrumX from dropping an idle
  connection, and its round trip is the baseline any header delta has to be
  read against.
- **Connections**, in `connections`: one row per dial, successful or not, so a
  dial that never connected is how downtime is counted. It carries the remote
  address, the `server.version` strings, the negotiated TLS version and
  cipher, and why the connection ended.
- **Names and certificates.** `dns_resolutions` keeps every address a lookup
  returned and not only the one that was dialed; `tls_certs` keeps each
  presented certificate once by SHA-256, whole, because the question is not
  what the subject says but which hostnames presented this exact certificate.

`src/store/schema.sql` is the schema with a comment on every table and every
column that needs one.

## How it works

One persistent connection per enabled server, held open for the life of the
process: the handshake, the initial probes (whose `server.features` answer is
checked against the configured chain's genesis hash), the header
subscription, then the cadence timers. `sessions_per_server` opens more than
one connection to the same endpoint; those extra sessions do headers and pings
only, and they are the noise floor -- two connections to one server announcing
the same block some milliseconds apart is the resolution limit that a delta
between two different servers has to beat. Servers are discovered from
`server.peers.subscribe` and enabled up to `discovery.max_servers`, past which
a new peer is still recorded, just not connected to. Onion servers go through
an in-process arti client, so no tor daemon and no SOCKS proxy has to exist on
the host, and a bootstrap that fails costs the onion servers rather than the
run. Everything is written by one writer task into a SQLite database in WAL
mode, which means the database can be queried while the collector is running.

## Running it

```sh
cargo build --release
# or: nix build
```

The binary is then `./target/release/electrum-observer` or
`./result/bin/electrum-observer`. Fill the `servers` table with it, check what
is in it, and collect:

```sh
electrum-observer import sparrow      # the list Sparrow Wallet ships
electrum-observer import 1209k        # the server table at 1209k.com, mainnet
electrum-observer import file ./my-servers.txt
electrum-observer servers             # one tab-separated line per known server
electrum-observer run
```

`import` is idempotent and never re-enables anything, so a server disabled by
hand stays disabled across imports. `--config <path>` is global and defaults
to `config.yaml` in the working directory; `config-example.yaml` is every key
with its default, and the defaults shown there are what the daemon does when
it is handed an empty file. A key it does not know is a startup error rather
than a line that is ignored. `run` stops on SIGTERM (and on Ctrl-C): the
sessions are closed, what is in flight is written, and the process exits.

The flake has a NixOS module for the daemon:

```nix
{
  imports = [ inputs.electrum-observer.nixosModules.default ];

  services.electrum-observer = {
    enable = true;
    seeds.importOnStart = [ "sparrow" "1209k" ];
    seeds.serverFiles = [ ./my-servers.txt ];
    settings = {
      chain = "mainnet";
      sessions_per_server = 2;
      discovery.max_servers = 400;
    };
  };
}
```

`settings` is freeform, so every key of `config-example.yaml` is accepted;
`database` defaults into the service's state directory under
`/var/lib/electrum-observer` and arti's state goes next to it. Each entry of
`seeds.importOnStart` and `seeds.serverFiles` is one import before the daemon
starts, because a fresh deployment with an empty `servers` table would connect
to nothing and discovery would have no peer list to learn from.

## Example queries

Plain SQLite -- `sqlite3 observer.sqlite`, or DuckDB over the same file -- and
the database can be read while the collector is writing it. The server ids
below are whatever `electrum-observer servers` printed.

**Who was first with a block, and by how much.** Each server's first
announcement of one block, as a delta from the earliest announcement of it:

```sql
SELECT s.transport || '://' || s.host || ':' || s.port AS endpoint,
       MIN(e.at) - (SELECT MIN(at) FROM header_events WHERE hash = b.hash) AS behind_us
  FROM header_events e
  JOIN servers s ON s.id = e.server_id
  JOIN blocks b ON b.hash = e.hash
 WHERE b.hash = (SELECT hash FROM blocks ORDER BY height DESC, first_seen_at DESC LIMIT 1)
 GROUP BY e.server_id
 ORDER BY behind_us;
```

**The median delta of one pair across every block.** One block proves nothing;
the distribution over many is the signal. Substitute the two server ids:

```sql
WITH first_seen AS (
    SELECT hash, server_id, MIN(at) AS at
      FROM header_events
     WHERE server_id IN (1, 2)
     GROUP BY hash, server_id
), pair AS (
    SELECT a.hash, a.at - b.at AS delta_us
      FROM first_seen a
      JOIN first_seen b ON b.hash = a.hash
     WHERE a.server_id = 1 AND b.server_id = 2
)
SELECT COUNT(*) AS blocks,
       (SELECT delta_us FROM pair
         ORDER BY delta_us
         LIMIT 1 OFFSET (SELECT COUNT(*) / 2 FROM pair)) AS median_us
  FROM pair;
```

**Which side of a split each server was on.** Heights where two hashes were
booked, and which servers announced each of them -- the minority hash is the
small group:

```sql
WITH split AS (
    SELECT height FROM blocks GROUP BY height HAVING COUNT(*) > 1
), side AS (
    SELECT e.height, e.hash, e.server_id, MIN(e.at) AS at
      FROM header_events e
      JOIN split ON split.height = e.height
     GROUP BY e.height, e.hash, e.server_id
)
SELECT height, hash, COUNT(*) AS servers, GROUP_CONCAT(server_id) AS server_ids
  FROM side
 GROUP BY height, hash
 ORDER BY height, servers;
```

**When each of them switched.** The polling during those windows, which is
where a server that was on the losing branch changes its answer (both of these
return nothing in a database in which no split has been seen yet):

```sql
SELECT server_id, at, height, hash, error
  FROM tip_checks
 WHERE height IN (SELECT height FROM blocks GROUP BY height HAVING COUNT(*) > 1)
 ORDER BY height, server_id, at;
```

**Servers that answered the same fee histogram in the same minute.** Grouping
by `result_blob` is an exact-equality cluster; the minute is what keeps it from
comparing answers taken at different mempool states:

```sql
SELECT strftime('%Y-%m-%d %H:%M', p.sent_at / 1000000, 'unixepoch') AS minute,
       substr(p.result_blob, 1, 12) AS answer,
       COUNT(DISTINCT p.server_id) AS servers,
       GROUP_CONCAT(DISTINCT p.server_id) AS server_ids
  FROM probes p
 WHERE p.kind = 'fee_histogram' AND p.result_blob IS NOT NULL
 GROUP BY minute, p.result_blob
HAVING servers > 1
 ORDER BY servers DESC, minute;
```

**The same, for `server.features`.** No minute here, because a features object
changes rarely; a byte-identical one across hosts includes their genesis hash,
hosts block, pruning and version:

```sql
SELECT substr(p.result_blob, 1, 12) AS answer,
       COUNT(DISTINCT p.server_id) AS servers,
       GROUP_CONCAT(DISTINCT s.host) AS hosts
  FROM probes p
  JOIN servers s ON s.id = p.server_id
 WHERE p.kind = 'features' AND p.result_blob IS NOT NULL
 GROUP BY p.result_blob
HAVING servers > 1
 ORDER BY servers DESC;
```

**Certificates presented by more than one host.** The least ambiguous signal
here, and the one that needs no statistics:

```sql
SELECT c.sha256, c.subject, COUNT(DISTINCT s.host) AS hosts,
       GROUP_CONCAT(DISTINCT s.host) AS which
  FROM tls_certs c
  JOIN connections n ON n.tls_cert_id = c.id
  JOIN servers s ON s.id = n.server_id
 GROUP BY c.sha256
HAVING hosts > 1
 ORDER BY hosts DESC;
```

**Hostnames that resolve to the same address.** Every A and AAAA of every
lookup is kept as a JSON array, so `json_each` unpacks them:

```sql
SELECT a.value AS address,
       COUNT(DISTINCT s.host) AS hosts,
       GROUP_CONCAT(DISTINCT s.host) AS which
  FROM dns_resolutions d
  JOIN servers s ON s.id = d.server_id
  JOIN json_each(d.addresses) a
 GROUP BY a.value
HAVING hosts > 1
 ORDER BY hosts DESC;
```

**Who advertises whom.** The peer graph as the servers themselves describe it,
including peers that are never connected to:

```sql
SELECT s.host AS advertiser, e.peer_host, e.peer_ip, COUNT(*) AS seen
  FROM peer_edges e
  JOIN servers s ON s.id = e.from_server_id
 GROUP BY advertiser, e.peer_host, e.peer_ip
 ORDER BY seen DESC, advertiser;
```

**Uptime per server.** From the probing session of each server: how often it
was dialed, how often that failed, and how long it was connected in total:

```sql
SELECT s.transport || '://' || s.host || ':' || s.port AS endpoint,
       COUNT(*) AS attempts,
       SUM(c.connected_at IS NULL) AS failed,
       SUM(COALESCE(c.ended_at, CAST(strftime('%s', 'now') AS INTEGER) * 1000000)
           - c.connected_at) / 1000000 AS connected_secs
  FROM connections c
  JOIN servers s ON s.id = c.server_id
 WHERE c.session_index = 0
 GROUP BY c.server_id
 ORDER BY connected_secs DESC;
```

**Error-string fingerprints by version.** The fingerprint set's errors,
verbatim, grouped by what the server said it was: a version whose peers all
answer identically tells you the set is reading the implementation, and an
answer that does not match its declared version is the interesting row:

```sql
SELECT c.server_version,
       p.error,
       COUNT(DISTINCT p.server_id) AS servers
  FROM probes p
  JOIN connections c ON c.id = p.connection_id
 WHERE p.kind = 'fingerprint'
 GROUP BY c.server_version, p.error
 ORDER BY c.server_version, servers DESC;
```

## What this does not tell you

- **First-seen timing measures when a server exposes a tip, not when Bitcoin
  propagated it.** Between the block arriving at a backend and the
  notification reaching us there is the server software's own indexing and
  notification path, its load, and the network between it and this host. A
  delta is a statement about two Electrum endpoints, not about two nodes.
- **One vantage point.** Every session is dialed from one host, so the route
  to each server is part of every timing it produces, and a server that is
  simply nearer looks faster. Collecting from several hosts and comparing the
  per-pair distributions is the way around that, and it is not something one
  database can do for you.
- **Electrum servers rate-limit.** ElectrumX charges a connection for what it
  asks and disconnects one that costs too much, which is why the cadences
  default to minutes and the fingerprint set to once a day. Raising them buys
  resolution and risks being dropped, and a server that drops us measures our
  own impatience.
- **The fee histogram comparison is dominated by implementation defaults.**
  Two servers binning the same mempool with the same software produce the same
  histogram without sharing anything, so an identical-histogram cluster is a
  weak signal on its own and is worth something mainly where it agrees with
  the certificates, the addresses or the timing.
- **Discovery is a stranger's list of strangers.** Peer lists are partly
  stale, partly wrong and partly whatever a server feels like saying; a
  `servers` row proves only that something advertised that endpoint.

## Licence

MIT.
