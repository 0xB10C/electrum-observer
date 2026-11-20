-- electrum-observer, schema version 1.
--
-- Every table the collector writes. This is a migration and not a
-- description: it is applied to a database at version 0 and the version is
-- bumped in the same transaction, so a column is never added here once this
-- file has shipped -- a change is a new file in `MIGRATIONS` and a bumped
-- `SCHEMA_VERSION`.
--
-- Every timestamp is INTEGER microseconds since the Unix epoch, taken from
-- `SystemTime` where the bytes arrived rather than where the row was written.
-- The whole method is a difference of tens of milliseconds between two
-- servers, so a timestamp that means "when the writer got round to it" would
-- be the measurement rather than the data.
--
-- Text is used for enumerations -- `transport`, `network`, `kind`,
-- `end_reason` -- because this database is read by hand, in sqlite3 and in
-- DuckDB, by whoever is looking for the shared backend, and an integer code
-- would need this file open beside the query.

-- The servers that are known, whether or not they are connected to.
CREATE TABLE servers (
    id              INTEGER PRIMARY KEY,
    -- The endpoint, split into the columns a query groups by. `host` is the
    -- canonical spelling of `Endpoint::host` -- lowercased, IPv6 bracketed --
    -- so `transport || '://' || host || ':' || port` is the identity that
    -- appears in the config file and in the logs.
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    transport       TEXT    NOT NULL,  -- tcp | ssl
    network         TEXT    NOT NULL,  -- clearnet | onion
    -- config, 1209k, sparrow, or peers:<server_id>: which server advertised
    -- it, which is what makes the discovery graph readable without joining
    -- `peer_edges`.
    source          TEXT    NOT NULL,
    added_at        INTEGER NOT NULL,
    enabled         INTEGER NOT NULL,  -- whether sessions are opened to it
    disabled_reason TEXT,              -- cap | genesis_mismatch | operator
    -- One row per endpoint. The transport is part of it because the TCP and
    -- SSL ports of one host are two servers to this tool on purpose: they
    -- are certainly one backend, which makes them the positive control every
    -- other pair's delta is read against.
    UNIQUE (host, port, transport)
);

-- Every lookup of a server's hostname, with every record it returned and not
-- only the one that was dialed: a name that round-robins over several
-- addresses is a hint about how many machines are behind it, and several
-- names that resolve to one address is a stronger one.
CREATE TABLE dns_resolutions (
    id        INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers (id),
    at        INTEGER NOT NULL,
    addresses TEXT    NOT NULL,  -- JSON array of addresses, [] on failure
    error     TEXT
);

-- The certificates that were presented, by fingerprint. The whole DER is
-- kept because the query that matters is not "what is the subject" but
-- "which hostnames presented this exact certificate".
CREATE TABLE tls_certs (
    id         INTEGER PRIMARY KEY,
    sha256     TEXT NOT NULL UNIQUE,
    subject    TEXT,
    issuer     TEXT,
    sans       TEXT,  -- JSON array
    not_before INTEGER,
    not_after  INTEGER,
    der        BLOB NOT NULL
);

-- One row per connection attempt, successful or not: a dial that never
-- connected is a row with `connected_at` null, which is how downtime is
-- counted. Nothing else records uptime.
CREATE TABLE connections (
    id               INTEGER PRIMARY KEY,
    server_id        INTEGER NOT NULL REFERENCES servers (id),
    -- Which of this server's sessions: 0 is the one that probes, and the
    -- others exist to measure the noise floor between two connections to the
    -- same endpoint.
    session_index    INTEGER NOT NULL,
    started_at       INTEGER NOT NULL,
    connected_at     INTEGER,
    ended_at         INTEGER,
    end_reason       TEXT,
    remote_ip        TEXT,
    tls_cert_id      INTEGER REFERENCES tls_certs (id),
    tls_version      TEXT,
    tls_cipher       TEXT,
    dns_id           INTEGER REFERENCES dns_resolutions (id),
    server_version   TEXT,
    protocol_version TEXT
);

-- One row per header a server told us about, as the reply to
-- blockchain.headers.subscribe or as a later notification. This is the
-- first-seen timing data; the per-pair delta matrix is one self-join away.
CREATE TABLE header_events (
    id            INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections (id),
    server_id     INTEGER NOT NULL REFERENCES servers (id),
    at            INTEGER NOT NULL,
    kind          TEXT    NOT NULL,  -- subscribe | notification
    height        INTEGER NOT NULL,
    hash          TEXT    NOT NULL,
    prev_hash     TEXT,
    header_hex    TEXT    NOT NULL,
    -- Set when this server changed its mind rather than extended its chain:
    -- the announced prev_hash is not its own last hash at height - 1, or the
    -- height did not increase.
    reorg         INTEGER NOT NULL
);

-- The cross-server block book: which server was first with each block, and
-- -- when two hashes appear at one height -- that there is a split at all,
-- which is what arms the sessions' divergence polling.
CREATE TABLE blocks (
    hash                 TEXT PRIMARY KEY,
    height               INTEGER NOT NULL,
    prev_hash            TEXT,
    header_hex           TEXT    NOT NULL,
    first_seen_at        INTEGER NOT NULL,
    first_seen_server_id INTEGER NOT NULL REFERENCES servers (id)
);

-- blockchain.block.header polls while a divergence window is open. A
-- subscription says when a server announces a new tip; only polling says
-- when it switches to the other branch, which is the measurement thread
-- #167 could not take.
CREATE TABLE tip_checks (
    server_id     INTEGER NOT NULL REFERENCES servers (id),
    connection_id INTEGER NOT NULL REFERENCES connections (id),
    at            INTEGER NOT NULL,
    height        INTEGER,
    hash          TEXT,
    rtt_us        INTEGER,
    error         TEXT
);

-- server.ping, which keeps ElectrumX from dropping an idle connection and
-- whose round trip is the baseline latency any header delta is read against.
CREATE TABLE pings (
    connection_id INTEGER NOT NULL REFERENCES connections (id),
    at            INTEGER NOT NULL,
    rtt_us        INTEGER NOT NULL
);

-- One row per probe *set*, not per request: everything that goes out at one
-- moment lands in one row whose `params` and result are aligned by index,
-- because a set asked at one moment is the unit that is compared across
-- servers.
CREATE TABLE probes (
    id            INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections (id),
    server_id     INTEGER NOT NULL REFERENCES servers (id),
    kind          TEXT    NOT NULL,
    params        TEXT    NOT NULL,  -- JSON
    sent_at       INTEGER NOT NULL,
    recv_at       INTEGER,
    rtt_us        INTEGER,
    result_blob   TEXT REFERENCES blobs (sha256),
    error         TEXT               -- JSON
);

-- Content-addressed probe results. Fee histograms, server.features and
-- banners repeat endlessly and across servers, so storing them by hash keeps
-- the database small; more usefully, "did these two servers answer the same
-- thing" becomes an equality of two `result_blob` values rather than a JSON
-- comparison.
CREATE TABLE blobs (
    sha256 TEXT PRIMARY KEY,
    json   TEXT NOT NULL
);

-- server.peers.subscribe normalised to one row per advertised peer: who
-- advertises whom, over time, which is its own graph. Written whether or not
-- the peer is connected to.
CREATE TABLE peer_edges (
    probe_id       INTEGER NOT NULL REFERENCES probes (id),
    from_server_id INTEGER NOT NULL REFERENCES servers (id),
    peer_host      TEXT    NOT NULL,
    peer_ip        TEXT,
    features       TEXT               -- JSON array
);

-- The database's own facts: schema_version, config_sha256, started_at.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The indexes are the analysis queries this database exists for, written
-- down: which servers announced this block (hash), what this server announced
-- over time (server_id, at), the fee sets of one server in order (server_id,
-- kind, sent_at), who else answered this exact thing (result_blob), this
-- server's connection history (server_id, started_at), the branch each server
-- was on at a height (height, at), and the latency baseline of a connection
-- (connection_id, at). Nothing is indexed here that no named query uses:
-- every index is paid for on every insert, and this is a write-heavy
-- database.
CREATE INDEX idx_header_events_hash ON header_events (hash);
CREATE INDEX idx_header_events_server_at ON header_events (server_id, at);
CREATE INDEX idx_probes_server_kind_sent ON probes (server_id, kind, sent_at);
CREATE INDEX idx_probes_result_blob ON probes (result_blob);
CREATE INDEX idx_connections_server_started ON connections (server_id, started_at);
CREATE INDEX idx_tip_checks_height_at ON tip_checks (height, at);
CREATE INDEX idx_pings_connection_at ON pings (connection_id, at);
-- The divergence detector asks for the hashes at one height on every header
-- it books, so this one is on the write path as well as the read path.
CREATE INDEX idx_blocks_height ON blocks (height);
