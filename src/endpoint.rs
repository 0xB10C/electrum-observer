//! A server address: what is dialed, and the name the database knows it by.
//!
//! Every server this crate touches arrives as text and is kept as text: a
//! line of `servers_file`, a row of the 1209k table, a feature string in
//! someone else's `server.peers.subscribe` reply, an `overrides` key in the
//! configuration. [`Endpoint`] is where those spellings meet. It parses the
//! two that exist in the wild and prints exactly one of them, and that one
//! printed form is the identity of a server in the `servers` table, so two
//! sources naming the same server have to arrive at the same string or the
//! database grows two rows for one machine.
//!
//! The two spellings:
//!
//! - `ssl://host:port` and `tcp://host:port`, the canonical form, the one
//!   [`Display`] writes and the one a human writes in a config file. IPv6
//!   addresses are bracketed, as in a URL, because `::1:50002` has no
//!   defensible reading.
//! - `host:port:s` and `host:port:t`, Electrum's own, where the trailing
//!   letter is the transport. The 1209k server table and the feature strings
//!   of `server.peers.subscribe` are written this way, so the importers need
//!   it; nothing in this crate ever writes it back.
//!
//! Normalisation is part of parsing rather than something callers remember to
//! do: hostnames are lowercased, because DNS is case-insensitive and
//! `Electrum.org` and `electrum.org` are one server; a port of zero is
//! refused, because it is not a port anything listens on and it reaches the
//! dial as a connection to "whatever the kernel picks"; and a `.onion`
//! hostname has to be a v3 address, because v2 was switched off in the Tor
//! network in 2021 and an address with the old shape names nothing that can
//! be reached any more.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// How the bytes get to the server.
///
/// Both are plain Electrum over a stream; `Ssl` wraps it in TLS, which is
/// also where the certificate chain comes from that `tls_certs` stores. The
/// names are the ones the protocol and the config file use, and the ones the
/// `servers.transport` column holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// Plain TCP, Electrum's `t` ports.
    Tcp,
    /// TLS, Electrum's `s` ports.
    Ssl,
}

impl Transport {
    /// The scheme in the canonical form, and the `servers.transport` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Ssl => "ssl",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which network the host is reachable over.
///
/// Derived from the host rather than configured, because it is a property of
/// the address and not a choice: a `.onion` name can only be dialed through
/// Tor, and anything else cannot be. It decides whether a session waits for
/// the arti bootstrap and whether discovery is allowed to keep the address at
/// all, and it is the `servers.network` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    /// Reachable over the ordinary internet, directly or through Tor.
    Clearnet,
    /// A Tor onion service, reachable only through Tor.
    Onion,
}

impl Network {
    /// The `servers.network` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Clearnet => "clearnet",
            Network::Onion => "onion",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the address names.
///
/// The three clearnet shapes are kept apart rather than all being a string,
/// because they are dialed differently and because they mean different things
/// to the question this crate exists to ask: a literal address is one machine,
/// while a name is however many machines its records point at today, which is
/// why every A and AAAA of every lookup is recorded. Onion is its own variant
/// for the same reason the [`Network`] exists -- it is the one host kind that
/// cannot be resolved or dialed at all without Tor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// A DNS name, lowercased on parse.
    Name(String),
    /// A literal IPv4 address.
    Ipv4(Ipv4Addr),
    /// A literal IPv6 address.
    Ipv6(Ipv6Addr),
    /// A v3 onion address, including the `.onion` suffix, lowercased.
    Onion(String),
}

impl Host {
    /// The network this host can be reached over.
    pub fn network(&self) -> Network {
        match self {
            Host::Onion(_) => Network::Onion,
            Host::Name(_) | Host::Ipv4(_) | Host::Ipv6(_) => Network::Clearnet,
        }
    }
}

impl fmt::Display for Host {
    /// The host as it appears in the canonical form, so IPv6 in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(name) | Host::Onion(name) => f.write_str(name),
            Host::Ipv4(address) => write!(f, "{address}"),
            Host::Ipv6(address) => write!(f, "[{address}]"),
        }
    }
}

/// One Electrum server: a host, a port, and how to talk to it.
///
/// The fields are public because they are the whole value and there is
/// nothing to hide behind accessors, but the invariants are established by
/// [`FromStr`] alone: a parsed endpoint has a nonzero port, a lowercased
/// host, and a `.onion` host that is a v3 address. Code that builds one by
/// hand -- the tests, mostly -- is responsible for the same.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// What to resolve or dial.
    pub host: Host,
    /// The port, never zero.
    pub port: u16,
    /// Plain or TLS.
    pub transport: Transport,
}

impl Endpoint {
    /// The network this endpoint is reached over, from its host.
    pub fn network(&self) -> Network {
        self.host.network()
    }
}

impl fmt::Display for Endpoint {
    /// The canonical form, `ssl://host:port`, which is this server's identity
    /// everywhere: the `servers` row, the `overrides` key, the log field.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.transport, self.host, self.port)
    }
}

/// Why a piece of text is not an endpoint.
///
/// Carries the text as well as the reason, because these are read by whoever
/// wrote the config file or by whoever is looking at a skipped row of an
/// imported server list, and "missing the port" on its own does not say which
/// of six hundred lines it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseEndpointError {
    input: String,
    reason: String,
}

impl ParseEndpointError {
    fn new(input: &str, reason: impl Into<String>) -> Self {
        Self {
            input: input.to_string(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ParseEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a server address: {}",
            self.input, self.reason
        )
    }
}

impl std::error::Error for ParseEndpointError {}

/// The shapes that are accepted, quoted in the errors that are about shape.
const SHAPES: &str = "expected ssl://host:port, tcp://host:port, host:port:s or host:port:t";

impl FromStr for Endpoint {
    type Err = ParseEndpointError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // The scheme decides the spelling, so it is looked for first and an
        // unknown one is reported as a scheme rather than being handed to the
        // Electrum branch, which would otherwise blame the port. Matched
        // without regard to case, like the host: a config file written with
        // `SSL://` names the same server as one written with `ssl://`.
        if let Some((scheme, rest)) = text.split_once("://") {
            let transport = if scheme.eq_ignore_ascii_case("ssl") {
                Transport::Ssl
            } else if scheme.eq_ignore_ascii_case("tcp") {
                Transport::Tcp
            } else {
                return Err(ParseEndpointError::new(
                    text,
                    format!("{scheme:?} is not a transport: {SHAPES}"),
                ));
            };
            return canonical(text, rest, transport);
        }
        electrum(text)
    }
}

/// `ssl://host:port`, where an IPv6 address has to be bracketed.
fn canonical(text: &str, rest: &str, transport: Transport) -> Result<Endpoint, ParseEndpointError> {
    let (host_text, bracketed, port_text) = split_host_port(text, rest)?;
    assemble(text, host_text, bracketed, port_text, transport, true)
}

/// `host:port:s`, Electrum's own form, as the 1209k rows and the feature
/// strings of `server.peers.subscribe` are written.
///
/// Bare IPv6 is accepted here, unlike in the canonical form: the transport
/// letter and the port are taken off the right-hand end first, so what is
/// left is unambiguously the host however many colons it has.
fn electrum(text: &str) -> Result<Endpoint, ParseEndpointError> {
    let Some((host_port, letter)) = text.rsplit_once(':') else {
        return Err(ParseEndpointError::new(
            text,
            format!("missing the port: {SHAPES}"),
        ));
    };
    let transport = if letter.eq_ignore_ascii_case("s") {
        Transport::Ssl
    } else if letter.eq_ignore_ascii_case("t") {
        Transport::Tcp
    } else {
        return Err(ParseEndpointError::new(
            text,
            format!("{letter:?} is not a transport letter: {SHAPES}"),
        ));
    };
    let (host_text, bracketed, port_text) = split_host_port(text, host_port)?;
    assemble(text, host_text, bracketed, port_text, transport, false)
}

/// Splits `host:port` into its two halves, honouring brackets.
///
/// Returns the host with its brackets removed and whether there were any,
/// because the brackets are both a syntax to strip and the statement "this is
/// an IPv6 address", and the caller needs the second part.
fn split_host_port<'a>(
    text: &str,
    host_port: &'a str,
) -> Result<(&'a str, bool, &'a str), ParseEndpointError> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err(ParseEndpointError::new(text, "the bracket is never closed"));
        };
        let Some(port_text) = after.strip_prefix(':') else {
            return Err(ParseEndpointError::new(
                text,
                format!("missing the port: {SHAPES}"),
            ));
        };
        return Ok((inside, true, port_text));
    }
    // From the right: a hostname cannot contain a colon, and a bare IPv6
    // address is all colons, so the last one is the port separator either way.
    match host_port.rsplit_once(':') {
        Some((host_text, port_text)) => Ok((host_text, false, port_text)),
        None => Err(ParseEndpointError::new(
            text,
            format!("missing the port: {SHAPES}"),
        )),
    }
}

/// The two halves, checked and normalised into an [`Endpoint`].
///
/// The port is checked before the host, because a text that is one colon out
/// -- `ssl://host:50002:s`, the two spellings mixed -- has a host half that
/// looks like a botched IPv6 address, and "that is not a port number" says
/// more about it than anything said about the host would.
///
/// `brackets_required` is the canonical form's rule: `ssl://::1:50002` could
/// be `[::1]:50002` or the address `::1:50002` with no port, and a server
/// list that meant one of those is not improved by this crate picking the
/// other. Electrum's form does not need the rule -- the transport letter and
/// the port come off the right-hand end first, so what is left is
/// unambiguously the host however many colons it has.
fn assemble(
    text: &str,
    host_text: &str,
    bracketed: bool,
    port_text: &str,
    transport: Transport,
    brackets_required: bool,
) -> Result<Endpoint, ParseEndpointError> {
    let port: u16 = port_text.parse().map_err(|_| {
        ParseEndpointError::new(text, format!("{port_text:?} is not a port number"))
    })?;
    // Not a port a server listens on: to `connect` it means "whatever the
    // kernel picks", which would be a dial to a random port recorded as the
    // address the file named.
    if port == 0 {
        return Err(ParseEndpointError::new(text, "the port is zero"));
    }
    if brackets_required && !bracketed && host_text.contains(':') {
        return Err(ParseEndpointError::new(
            text,
            "an IPv6 address needs brackets here, as in ssl://[2001:db8::1]:50002",
        ));
    }
    let host = parse_host(text, host_text, bracketed)?;
    Ok(Endpoint {
        host,
        port,
        transport,
    })
}

/// The host half: an address literal, an onion name, or a DNS name.
fn parse_host(text: &str, host_text: &str, bracketed: bool) -> Result<Host, ParseEndpointError> {
    if bracketed {
        return host_text.parse::<Ipv6Addr>().map(Host::Ipv6).map_err(|_| {
            ParseEndpointError::new(text, format!("{host_text:?} is not an IPv6 address"))
        });
    }
    if let Ok(address) = host_text.parse::<Ipv4Addr>() {
        return Ok(Host::Ipv4(address));
    }
    if let Ok(address) = host_text.parse::<Ipv6Addr>() {
        return Ok(Host::Ipv6(address));
    }
    // DNS is case-insensitive and so is base32, so the comparison that
    // decides whether two sources named the same server is done on one case.
    let name = host_text.to_ascii_lowercase();
    if let Some(label) = name.strip_suffix(".onion") {
        return onion(text, name.as_str(), label);
    }
    check_hostname(text, &name)?;
    Ok(Host::Name(name))
}

/// A `.onion` host, which has to be a v3 address.
///
/// v3 is 56 characters of base32 -- 32 bytes of ed25519 public key, a
/// checksum and a version byte. v2 was 16, and the Tor network stopped
/// routing to v2 services in 2021, so an address of any other length does not
/// name something that can be reached: refusing it here turns a dead entry in
/// an imported server list into a line that says so, rather than a `servers`
/// row that fails to connect forever.
fn onion(text: &str, name: &str, label: &str) -> Result<Host, ParseEndpointError> {
    if label.len() != 56 {
        return Err(ParseEndpointError::new(
            text,
            format!(
                "{name:?} is not a v3 onion address: {} characters before .onion, expected 56",
                label.len()
            ),
        ));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b"234567".contains(&b))
    {
        return Err(ParseEndpointError::new(
            text,
            format!("{name:?} is not a v3 onion address: it is not base32"),
        ));
    }
    Ok(Host::Onion(name.to_string()))
}

/// What a DNS name is allowed to look like.
///
/// Deliberately narrow: letters, digits and hyphens in labels of 1 to 63
/// characters, 253 characters in all. The point is not to be the authority on
/// what a resolver would accept but to catch the text that is not a hostname
/// at all -- a copied line with a comment on it, a row of a table that was
/// parsed one column off -- at the moment it is read, rather than as a
/// resolution failure hours into a run.
fn check_hostname(text: &str, name: &str) -> Result<(), ParseEndpointError> {
    let bad = |reason: &str| {
        ParseEndpointError::new(text, format!("{name:?} is not a hostname: {reason}"))
    };
    if name.is_empty() {
        return Err(bad("it is empty"));
    }
    if name.len() > 253 {
        return Err(bad("it is longer than 253 characters"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(bad("it has an empty label"));
        }
        if label.len() > 63 {
            return Err(bad("it has a label longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(bad("a label starts or ends with a hyphen"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(bad(
                "a label has a character that is not a letter, a digit or a hyphen",
            ));
        }
    }
    Ok(())
}

impl Serialize for Endpoint {
    /// As the canonical string, which is what the `overrides` key in the
    /// config file and the `servers` row in the database both hold: an
    /// endpoint serialised as a struct would be a second spelling to keep in
    /// step with [`Display`].
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(host: &str) -> Host {
        Host::Name(host.to_string())
    }

    fn onion_host(host: &str) -> Host {
        Host::Onion(host.to_string())
    }

    /// A v3 address: 56 base32 characters. Tor's own directory service.
    const V3: &str = "sdmzuu6ktcrw4b5kcveqgpvmqv2ppkqpxdvtmyjwlsv7nw7weqgqjrqd";

    /// Every spelling of every host kind, and what it has to come out as.
    ///
    /// One table rather than a test each, because what is being checked is
    /// the same sentence every time -- this text parses to this value, and
    /// that value prints back as the canonical form -- and because a host
    /// kind added without a row here is then visibly missing.
    #[test]
    fn every_spelling_round_trips_through_the_canonical_form() {
        let cases: &[(&str, Host, u16, Transport, &str)] = &[
            // The canonical form, both transports.
            (
                "ssl://electrum.example:50002",
                name("electrum.example"),
                50002,
                Transport::Ssl,
                "ssl://electrum.example:50002",
            ),
            (
                "tcp://electrum.example:50001",
                name("electrum.example"),
                50001,
                Transport::Tcp,
                "tcp://electrum.example:50001",
            ),
            // Electrum's own, which the 1209k rows and the peer features use.
            (
                "electrum.example:50002:s",
                name("electrum.example"),
                50002,
                Transport::Ssl,
                "ssl://electrum.example:50002",
            ),
            (
                "electrum.example:50001:t",
                name("electrum.example"),
                50001,
                Transport::Tcp,
                "tcp://electrum.example:50001",
            ),
            // Literal addresses, both families, both spellings.
            (
                "ssl://18.195.224.155:50002",
                Host::Ipv4(Ipv4Addr::new(18, 195, 224, 155)),
                50002,
                Transport::Ssl,
                "ssl://18.195.224.155:50002",
            ),
            (
                "18.195.224.155:50002:s",
                Host::Ipv4(Ipv4Addr::new(18, 195, 224, 155)),
                50002,
                Transport::Ssl,
                "ssl://18.195.224.155:50002",
            ),
            (
                "ssl://[2001:db8::1]:50002",
                Host::Ipv6("2001:db8::1".parse().expect("a literal address")),
                50002,
                Transport::Ssl,
                "ssl://[2001:db8::1]:50002",
            ),
            (
                "[2001:db8::1]:50002:s",
                Host::Ipv6("2001:db8::1".parse().expect("a literal address")),
                50002,
                Transport::Ssl,
                "ssl://[2001:db8::1]:50002",
            ),
            // Bare IPv6 in Electrum's form: the letter and the port come off
            // the right, so what is left cannot be mistaken for anything.
            (
                "2001:db8::1:50002:t",
                Host::Ipv6("2001:db8::1".parse().expect("a literal address")),
                50002,
                Transport::Tcp,
                "tcp://[2001:db8::1]:50002",
            ),
            // Onion, which only v3 can be.
            (
                &format!("tcp://{V3}.onion:50001"),
                onion_host(&format!("{V3}.onion")),
                50001,
                Transport::Tcp,
                &format!("tcp://{V3}.onion:50001"),
            ),
            (
                &format!("{V3}.onion:50001:t"),
                onion_host(&format!("{V3}.onion")),
                50001,
                Transport::Tcp,
                &format!("tcp://{V3}.onion:50001"),
            ),
            // Case is not part of a name: DNS is insensitive to it, so two
            // sources spelling one server differently are one server.
            (
                "SSL://Electrum.EXAMPLE:50002",
                name("electrum.example"),
                50002,
                Transport::Ssl,
                "ssl://electrum.example:50002",
            ),
            (
                "Electrum.EXAMPLE:50002:S",
                name("electrum.example"),
                50002,
                Transport::Ssl,
                "ssl://electrum.example:50002",
            ),
            (
                &format!("{}.ONION:50001:t", V3.to_ascii_uppercase()),
                onion_host(&format!("{V3}.onion")),
                50001,
                Transport::Tcp,
                &format!("tcp://{V3}.onion:50001"),
            ),
            // The port is a port and not a service name, and the edges of
            // the range are ports like any other.
            (
                "ssl://electrum.example:1",
                name("electrum.example"),
                1,
                Transport::Ssl,
                "ssl://electrum.example:1",
            ),
            (
                "ssl://electrum.example:65535",
                name("electrum.example"),
                65535,
                Transport::Ssl,
                "ssl://electrum.example:65535",
            ),
        ];

        for (input, host, port, transport, canonical) in cases {
            let parsed: Endpoint = input.parse().unwrap_or_else(|e| panic!("{input:?}: {e}"));
            assert_eq!(
                parsed,
                Endpoint {
                    host: host.clone(),
                    port: *port,
                    transport: *transport,
                },
                "{input:?}"
            );
            assert_eq!(&parsed.to_string(), canonical, "{input:?}");
            // And the canonical form parses back to the same value, which is
            // what makes it usable as the identity of a server.
            assert_eq!(
                canonical.parse::<Endpoint>().expect("the canonical form"),
                parsed,
                "{input:?}"
            );
        }
    }

    /// The host decides the network, and nothing else does.
    #[test]
    fn the_network_comes_from_the_host() {
        let onion: Endpoint = format!("ssl://{V3}.onion:50002")
            .parse()
            .expect("a v3 address");
        assert_eq!(onion.network(), Network::Onion);
        assert_eq!(onion.host.network(), Network::Onion);
        assert_eq!(onion.network().as_str(), "onion");

        for clearnet in [
            "ssl://electrum.example:50002",
            "ssl://18.195.224.155:50002",
            "ssl://[2001:db8::1]:50002",
        ] {
            let endpoint: Endpoint = clearnet.parse().expect("a clearnet address");
            assert_eq!(endpoint.network(), Network::Clearnet, "{clearnet}");
            assert_eq!(endpoint.network().as_str(), "clearnet", "{clearnet}");
        }
    }

    /// The transport names are the ones the config file and the database
    /// column use, so they are spelled out rather than derived from the
    /// variant.
    #[test]
    fn the_transports_are_named_tcp_and_ssl() {
        assert_eq!(Transport::Tcp.as_str(), "tcp");
        assert_eq!(Transport::Ssl.as_str(), "ssl");
        assert_eq!(Transport::Tcp.to_string(), "tcp");
        assert_eq!(Transport::Ssl.to_string(), "ssl");
        assert_eq!(Network::Clearnet.to_string(), "clearnet");
        assert_eq!(Network::Onion.to_string(), "onion");
    }

    /// Everything that is not an endpoint, and the word in the message that
    /// says why.
    ///
    /// The message is asserted on, not just the failure: these are read by
    /// whoever wrote the line, and a parser that refuses everything with
    /// "invalid" sends them guessing.
    #[test]
    fn what_is_not_an_endpoint_is_refused_by_name() {
        let long_label = "a".repeat(64);
        let long_name = format!("{}.example", "a".repeat(250));
        let cases: &[(&str, &str)] = &[
            ("ssl://electrum.example:0", "the port is zero"),
            ("electrum.example:0:s", "the port is zero"),
            ("ssl://electrum.example", "missing the port"),
            ("electrum.example", "missing the port"),
            ("electrum.example:50002", "not a transport letter"),
            ("ssl://electrum.example:50002:s", "not a port number"),
            ("ssl://electrum.example:65536", "not a port number"),
            ("ssl://electrum.example:https", "not a port number"),
            ("ws://electrum.example:50002", "\"ws\" is not a transport"),
            ("://electrum.example:50002", "\"\" is not a transport"),
            ("ssl://2001:db8::1:50002", "needs brackets"),
            ("ssl://[2001:db8::1:50002", "bracket is never closed"),
            ("ssl://[2001:db8::1]", "missing the port"),
            ("ssl://[electrum.example]:50002", "not an IPv6 address"),
            ("ssl://[]:50002", "not an IPv6 address"),
            ("ssl://:50002", "it is empty"),
            ("ssl://electrum..example:50002", "empty label"),
            ("ssl://electrum.example.:50002", "empty label"),
            (
                "ssl://-electrum.example:50002",
                "starts or ends with a hyphen",
            ),
            (
                "ssl://electrum-.example:50002",
                "starts or ends with a hyphen",
            ),
            (
                "ssl://electrum example:50002",
                "not a letter, a digit or a hyphen",
            ),
            (
                "ssl://electrum.example#1:50002",
                "not a letter, a digit or a hyphen",
            ),
            ("", "missing the port"),
        ];

        for (input, expected) in cases {
            let error = input
                .parse::<Endpoint>()
                .expect_err("this is not an endpoint");
            assert!(
                error.to_string().contains(expected),
                "{input:?}: {error} does not mention {expected:?}"
            );
            // And the text that was refused is in the message, because these
            // are read one line at a time out of a file of hundreds.
            assert!(
                error.to_string().contains(&format!("{input:?}")),
                "{input:?}: {error} does not quote the input"
            );
        }

        for (input, expected) in [
            (
                format!("ssl://{long_label}.example:50002"),
                "label longer than 63",
            ),
            (format!("ssl://{long_name}:50002"), "longer than 253"),
        ] {
            let error = input
                .parse::<Endpoint>()
                .expect_err("this is not an endpoint");
            assert!(
                error.to_string().contains(expected),
                "{input:?}: {error} does not mention {expected:?}"
            );
        }
    }

    /// The length limits are DNS's own, so a name that is exactly as long as
    /// one is a name and not an error.
    ///
    /// The limits exist to catch text that is not a hostname at all, and a
    /// limit that is one character out would refuse a server for having a
    /// long but perfectly ordinary name.
    #[test]
    fn a_name_at_the_length_limits_is_still_a_name() {
        let label = "a".repeat(63);
        let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(longest.len(), 253, "the longest name DNS allows");

        for host in [format!("{label}.example"), longest] {
            let endpoint: Endpoint = format!("ssl://{host}:50002")
                .parse()
                .unwrap_or_else(|e| panic!("{host:?}: {e}"));
            assert_eq!(endpoint.host, Host::Name(host));
        }
    }

    /// v2 onion addresses are dead and are refused as such.
    ///
    /// The Tor network stopped routing to them in 2021, so a server list that
    /// still carries one carries an address nothing can reach; taking it
    /// would be a `servers` row that fails to connect for as long as the
    /// database exists.
    #[test]
    fn only_v3_onion_addresses_are_taken() {
        for (input, expected) in [
            // A v2 address: 16 characters.
            ("ssl://expyuzz4wqqyqhjn.onion:50002", "expected 56"),
            // The right length, the wrong alphabet: base32 has no 1 or 8,
            // and an address with one is a typo rather than a service.
            (
                &format!("ssl://{}1.onion:50002", &V3[..55]),
                "it is not base32",
            ),
            (&format!("ssl://{}.onion:50002", &V3[..55]), "expected 56"),
            (".onion:50002:s", "expected 56"),
        ] {
            let error = input
                .parse::<Endpoint>()
                .expect_err("not a v3 onion address");
            assert!(
                error.to_string().contains(expected),
                "{input:?}: {error} does not mention {expected:?}"
            );
            assert!(
                error.to_string().contains("onion"),
                "{input:?}: {error} does not say it is about an onion address"
            );
        }
    }

    /// Equality is on the parsed value, so the two spellings of one server
    /// are one key, and the order is stable enough to sort a server list by.
    #[test]
    fn endpoints_compare_and_hash_by_what_they_name() {
        use std::collections::HashSet;

        let url: Endpoint = "ssl://electrum.example:50002".parse().expect("an endpoint");
        let electrum: Endpoint = "Electrum.example:50002:s".parse().expect("an endpoint");
        assert_eq!(url, electrum);
        assert_eq!(url.cmp(&electrum), std::cmp::Ordering::Equal);

        let mut seen = HashSet::new();
        assert!(seen.insert(url.clone()));
        assert!(!seen.insert(electrum), "one server, one entry");

        // The same host over both transports is two servers, and both are
        // kept: they are the positive control of the whole method.
        let tcp: Endpoint = "tcp://electrum.example:50001".parse().expect("an endpoint");
        assert_ne!(url, tcp);
        assert!(seen.insert(tcp.clone()));

        // Ordering: by host first, then port, then transport, which puts the
        // sessions of one host next to each other in a sorted list.
        let other: Endpoint = "ssl://zzz.example:50002".parse().expect("an endpoint");
        let mut sorted = vec![other.clone(), url.clone(), tcp.clone()];
        sorted.sort();
        assert_eq!(sorted, vec![tcp, url, other.clone()]);

        // And a host kind orders before another host kind consistently, so a
        // sort is a sort and not an order that depends on what is in it.
        let ipv4: Endpoint = "ssl://1.2.3.4:50002".parse().expect("an endpoint");
        let ipv6: Endpoint = "ssl://[2001:db8::1]:50002".parse().expect("an endpoint");
        let onion: Endpoint = format!("ssl://{V3}.onion:50002")
            .parse()
            .expect("an endpoint");
        let mut kinds = vec![onion.clone(), ipv6.clone(), ipv4.clone(), other.clone()];
        kinds.sort();
        assert_eq!(kinds, vec![other, ipv4, ipv6, onion]);
    }

    /// serde carries the canonical string and nothing else, which is what the
    /// `overrides` key in the config file holds and what the store will write.
    #[test]
    fn serde_is_the_canonical_string() {
        let endpoint: Endpoint = "electrum.example:50002:s".parse().expect("an endpoint");
        let json = serde_json::to_string(&endpoint).expect("serialising an endpoint");
        assert_eq!(json, "\"ssl://electrum.example:50002\"");
        assert_eq!(
            serde_json::from_str::<Endpoint>(&json).expect("a canonical string"),
            endpoint
        );

        // Either spelling is accepted on the way in, because a config file is
        // written by hand and a server list is not written by us.
        assert_eq!(
            serde_json::from_str::<Endpoint>("\"electrum.example:50002:s\"").expect("either form"),
            endpoint
        );

        // And what is not an endpoint is a deserialisation error that says
        // why, rather than a default or a panic.
        let error = serde_json::from_str::<Endpoint>("\"ssl://electrum.example:0\"")
            .expect_err("a zero port");
        assert!(error.to_string().contains("the port is zero"), "{error}");
        let error = serde_json::from_str::<Endpoint>("50002").expect_err("not even a string");
        assert!(error.to_string().contains("string"), "{error}");
    }
}
