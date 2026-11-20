//! Opening a connection to one server, and recording what that took.
//!
//! Adapted from crawler's `dial.rs`. What is kept is the shape of that
//! module: one attempt and no retry loop of its own, a deadline around the
//! whole thing, and a classification of the failure read off the operating
//! system's own error number rather than off the wording of a message. What
//! is dropped is everything that belongs to a crawler rather than to this
//! collector -- the protocol-version negotiation, the SOCKS proxy, the
//! source-address binding and the stop signal -- and what is added is the
//! two things a crawler never has to do: resolve a hostname and keep the
//! answer, and finish a TLS handshake and keep the certificate.
//!
//! Three things here are design decisions rather than mechanics.
//!
//! **Every record of every lookup is kept**, not just the address that was
//! dialed (DESIGN.md section 4, `dns_resolutions`). A hostname that
//! round-robins over several addresses is a hint about how many machines are
//! behind it, and a set of hostnames that resolve to one address is a
//! stronger one; neither survives a resolver that hands back the one address
//! it happened to pick.
//!
//! **The address dialed is chosen at random** among the answers. Not the
//! first, which would be whichever the resolver put in front and would mean
//! one backend of a round-robin name is watched and the rest never are; over
//! the reconnects of a long run, a random choice visits all of them, and the
//! `remote_ip` column then says which one each connection actually reached.
//!
//! **The certificate is recorded, never judged.** The verifier accepts
//! everything. Electrum's `s` ports are overwhelmingly self-signed -- the
//! ecosystem pins nothing and no client checks them -- so a verifier that
//! refused what a browser refuses would collect nothing at all, and what is
//! wanted is the certificate itself: which hostnames present the same one is
//! about as strong a shared-infrastructure signal as this tool can collect
//! (DESIGN.md section 4, `tls_certs`). A certificate x509-parser cannot
//! read is stored by its hash and its bytes with the parsed columns null,
//! for the same reason.
//!
//! Tor is a seam here and is filled by [`crate::tor`]: an [`OnionDialer`] is
//! whatever opens a stream to a name, and with none installed an onion
//! endpoint fails as [`DialError::TorUnavailable`] rather than being dialed
//! over the clearnet. `tor.route_clearnet` installs a second one with
//! [`Dialer::with_clearnet_via`], and then the clearnet endpoints go through
//! Tor as well and this module opens no sockets of its own at all.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::TARGET_DIAL as TARGET;
use crate::endpoint::{Endpoint, Host, Transport};
use crate::settings::{DnsSettings, Settings};
use crate::store::{Micros, TlsInfo, sha256_hex};

/// What a session needs of a connection, whichever transport carried it.
///
/// A trait of its own with a blanket implementation, because
/// `dyn AsyncRead + AsyncWrite` is not a trait object Rust will build: only
/// auto traits may be added to the first one. Nothing implements this by
/// hand and nothing is meant to.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A connection, whichever transport carried it.
///
/// Boxed because the three cases produce three unrelated types -- a
/// `TcpStream`, a `tokio_rustls::client::TlsStream` over one, and whatever
/// arti hands back -- while which one an endpoint needs is a value decided at
/// dial time and not a type the session knows. One allocation per connection
/// buys a single return type for the dialer and a session written once.
pub type BoxStream = Box<dyn Stream>;

/// An onion stream being opened.
///
/// The error is a string rather than arti's own type because this crate does
/// not depend on arti yet: the seam is defined here in step 7 and filled in
/// step 8, and a `String` is what both the stub in the tests below and the
/// real client can produce. It reaches the caller as [`DialError::Tor`].
pub type OpeningStream = Pin<Box<dyn Future<Output = Result<BoxStream, String>> + Send>>;

/// The whole of what this module wants from Tor: open a stream to a name.
///
/// A boxed closure rather than arti's `TorClient`, for crawler's two reasons.
/// The client is generic over its runtime and the runtime arti picks for us
/// is not re-exported by `arti-client`, so writing the type in a signature
/// would mean depending on one more of arti's crates, while inside a closure
/// it is inferred and never written. And a dialer whose whole need of Tor is
/// "open a stream to this name" can be tested against a stand-in that refuses
/// or stalls on command, which no real client can be asked to do without a
/// Tor network to refuse on.
///
/// The host arrives without its port, and the port beside it, because that is
/// what every implementation has to split out anyway.
pub type OnionDialer = Box<dyn Fn(String, u16) -> OpeningStream + Send + Sync>;

/// One lookup, with every record it returned.
///
/// The row of `dns_resolutions` (DESIGN.md section 4), taken at the moment
/// the answer arrived. `addresses` is every A and every AAAA, in the order
/// the resolver gave them; `error` is set when there was no answer at all,
/// and then `addresses` is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResult {
    /// When the answer arrived.
    pub at: SystemTime,
    /// Every A and AAAA record of the lookup.
    pub addresses: Vec<IpAddr>,
    /// Why there was no answer, in the resolver's own words.
    pub error: Option<String>,
}

/// An open connection and everything the attempt learned on the way.
///
/// The fields are what the `connections` row needs filling in with: the
/// address that was really reached, the lookup that chose it, and the
/// certificate the handshake presented (DESIGN.md section 4).
pub struct Dialed {
    /// The connection itself, ready for the JSON-RPC client.
    pub stream: BoxStream,
    /// The address actually connected to. `None` for an onion stream, which
    /// has no IP address at either end of it, and `None` for every stream
    /// under `tor.route_clearnet`: the exit connects and does not say to
    /// what, so even a literal endpoint has no address this process observed.
    pub remote_ip: Option<IpAddr>,
    /// The lookup this attempt used. `None` when there was none: an IP
    /// literal is dialed as it is written, an onion name is resolved by Tor
    /// rather than by us, and under `tor.route_clearnet` the exit does the
    /// resolving and answers with a stream rather than with records.
    pub dns: Option<DnsResult>,
    /// What the TLS handshake presented and negotiated, for an `s` port.
    pub tls: Option<TlsInfo>,
    /// When the connection came up.
    pub connected_at: SystemTime,
}

/// A transport that is up, before anything has been said over it.
///
/// The step between "a socket or a circuit exists" and [`Dialed`]: what the
/// TLS handshake, if there is one, is layered on. Private, because the one
/// thing a caller does with it is the handshake, and that is [`Dialer`]'s.
struct Opened {
    stream: BoxStream,
    remote_ip: Option<IpAddr>,
    dns: Option<DnsResult>,
    /// When the transport came up, which for an `s` port is before the TLS
    /// handshake rather than after it: `connections.connected_at` is when we
    /// reached the server, and the handshake is a conversation with a server
    /// already reached.
    connected_at: SystemTime,
}

/// Why a dial did not produce a connection.
///
/// Every variant is a value of `connections.end_reason` (DESIGN.md section
/// 4), because a failed dial is a row too: that a port refuses, or that a
/// name does not resolve, is the observation.
#[derive(Debug)]
pub enum DialError {
    /// The lookup failed, in the resolver's own words. The same text is what
    /// `dns_resolutions.error` holds for this attempt.
    Dns(String),
    /// The lookup succeeded and answered with no address at all.
    NoAddresses,
    /// The connect timeout ran out. It covers the lookup, the TCP connect
    /// and the TLS handshake together, so this says only that the whole
    /// thing took too long.
    Timeout,
    /// The host is up and the port is not listening.
    Refused,
    /// No route to the host or to its network.
    Unreachable,
    /// Anything else the operating system said.
    Io(io::Error),
    /// The TLS handshake did not finish, in rustls's own words. Never a
    /// rejected certificate: the verifier accepts every one of them.
    Tls(String),
    /// An onion endpoint with no Tor to dial it through.
    TorUnavailable,
    /// Tor was there and would not open the stream.
    Tor(String),
}

impl DialError {
    /// The short name this failure has in `connections.end_reason`.
    ///
    /// Stable text in a column analyses filter on, so renaming one of these
    /// is a change to the output and not a tidy-up.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dns(_) => "dns",
            Self::NoAddresses => "no_addresses",
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::Io(_) => "io",
            Self::Tls(_) => "tls",
            Self::TorUnavailable => "tor_unavailable",
            Self::Tor(_) => "tor",
        }
    }

    /// The value to write into `connections.end_reason`.
    ///
    /// The same string as [`as_str`](Self::as_str), under the name of the
    /// column, so a caller writing the row does not have to know that the
    /// two are the same question.
    pub fn end_reason(&self) -> &'static str {
        self.as_str()
    }
}

impl fmt::Display for DialError {
    /// The name of the failure and, where there is one, what was said about
    /// it. The detail is for the log; the column gets
    /// [`as_str`](Self::as_str) alone.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(detail) | Self::Tls(detail) | Self::Tor(detail) => {
                write!(f, "{}: {detail}", self.as_str())
            }
            Self::Io(err) => write!(f, "io: {err}"),
            Self::NoAddresses => f.write_str("the name resolved to no addresses"),
            Self::Timeout => f.write_str("the connect timeout ran out"),
            Self::Refused => f.write_str("the port refused the connection"),
            Self::Unreachable => f.write_str("there is no route to the host"),
            Self::TorUnavailable => f.write_str("tor is not available for onion endpoints"),
        }
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Opens connections to endpoints: the resolver, the TLS configuration and
/// the deadline, built once and shared by every session.
///
/// One value for the process rather than one per session, because the
/// resolver's cache and the rustls configuration are both worth sharing
/// across 450 of them, and because the Tor seam has to be the same client
/// for all of them.
pub struct Dialer {
    /// Bounds the lookup, the connect and the TLS handshake together, from
    /// `timeouts.connect_secs`.
    connect_timeout: Duration,
    resolver: TokioResolver,
    /// Built once; cloned per TLS dial so that each handshake gets a
    /// certificate verifier of its own to capture into.
    tls: ClientConfig,
    /// `None` unless [`crate::tor`] bootstrapped, and then an onion endpoint
    /// is [`DialError::TorUnavailable`].
    onion: Option<OnionDialer>,
    /// `Some` only for `tor.route_clearnet`, and then every clearnet
    /// endpoint goes through it instead of through a socket of ours.
    clearnet: Option<OnionDialer>,
}

impl Dialer {
    /// The dialer these settings describe.
    ///
    /// Fails only on a resolver that cannot be built at all: a system
    /// configuration that cannot be read, or a `dns.upstream` that is not an
    /// address. Both are startup problems rather than per-dial ones, which
    /// is why they are reported here and not out of every attempt.
    pub fn new(settings: &Settings) -> Result<Self> {
        Ok(Self {
            connect_timeout: settings.timeouts.connect(),
            resolver: resolver(&settings.dns)?,
            tls: client_config(),
            onion: None,
            clearnet: None,
        })
    }

    /// Installs the Tor seam, which is what [`crate::tor::TorHandle`] fills
    /// with a bootstrapped arti client.
    #[must_use]
    pub fn with_onion(mut self, onion: OnionDialer) -> Self {
        self.onion = Some(onion);
        self
    }

    /// Sends clearnet endpoints through Tor too, for `tor.route_clearnet`.
    ///
    /// The same seam as [`with_onion`](Self::with_onion) and a second
    /// installation of it rather than a flag on the first, because the two
    /// are different `StreamPrefs` -- an onion dial is a rendezvous and a
    /// clearnet dial is an exit -- and the dialer should not have to know
    /// that, only which of the two to call.
    ///
    /// What the setting costs is in the rows: the exit does the connecting
    /// and, for a hostname, the resolving, so a connection made this way has
    /// no `remote_ip` and no `dns_resolutions` row. That, and a circuit's
    /// latency on every timing collected, is why it is off by default
    /// (DESIGN.md section 9).
    #[must_use]
    pub fn with_clearnet_via(mut self, clearnet: OnionDialer) -> Self {
        self.clearnet = Some(clearnet);
        self
    }

    /// Opens a connection to `endpoint`.
    ///
    /// The whole attempt is under one deadline -- DNS, TCP and the TLS
    /// handshake together -- because `timeouts.connect_secs` is documented as
    /// the time from the start of the dial to a usable connection
    /// (DESIGN.md section 8), and three deadlines of twenty seconds would be
    /// a minute.
    ///
    /// A failure is a [`DialError`] whose [`as_str`](DialError::as_str) is
    /// the `connections.end_reason` for the attempt. The lookup of a failed
    /// dial is not lost with it: [`DialError::Dns`] carries exactly the text
    /// that `dns_resolutions.error` takes, and a caller that wants the row
    /// either way can call [`resolve`](Self::resolve) itself.
    pub async fn dial(&self, endpoint: &Endpoint) -> Result<Dialed, DialError> {
        match tokio::time::timeout(self.connect_timeout, self.open(endpoint)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!(
                    target: TARGET,
                    endpoint = %endpoint,
                    timeout_secs = self.connect_timeout.as_secs(),
                    "the dial did not finish before the connect timeout",
                );
                Err(DialError::Timeout)
            }
        }
    }

    /// The attempt itself, with the deadline held by [`dial`](Self::dial)
    /// around it.
    ///
    /// The transport is opened first and the TLS handshake is the same step
    /// afterwards whichever opened it, so an `ssl://...onion` endpoint gets
    /// its certificate recorded exactly as a clearnet one does. Rare, but
    /// they exist, and the alternative is a connection whose `tls_cert_id` is
    /// null for no reason a reader of the table could guess.
    async fn open(&self, endpoint: &Endpoint) -> Result<Dialed, DialError> {
        let opened = match (&self.clearnet, clearnet_target(&endpoint.host)) {
            // `tor.route_clearnet`: the three clearnet arms below are
            // replaced by one circuit, and the onion arm is not touched --
            // an onion name goes through the onion seam whatever this
            // setting says, because the two are different preferences.
            (Some(via), Some(target)) => self.open_through(via, target, endpoint.port).await?,
            _ => match &endpoint.host {
                Host::Onion(name) => self.open_onion(name, endpoint.port).await?,
                Host::Name(name) => self.open_name(name, endpoint.port).await?,
                Host::Ipv4(address) => {
                    self.open_address(IpAddr::V4(*address), endpoint.port)
                        .await?
                }
                Host::Ipv6(address) => {
                    self.open_address(IpAddr::V6(*address), endpoint.port)
                        .await?
                }
            },
        };
        let (stream, tls) = match endpoint.transport {
            Transport::Tcp => (opened.stream, None),
            Transport::Ssl => {
                let (stream, tls) = self.handshake(opened.stream, &endpoint.host).await?;
                (stream, Some(tls))
            }
        };
        tracing::debug!(
            target: TARGET,
            endpoint = %endpoint,
            remote_ip = ?opened.remote_ip,
            certificate = tls.as_ref().map(|info| info.sha256.as_str()),
            "connected",
        );
        Ok(Dialed {
            stream,
            remote_ip: opened.remote_ip,
            dns: opened.dns,
            tls,
            connected_at: opened.connected_at,
        })
    }

    /// One hostname: resolve it, keep every record, and dial one of them.
    async fn open_name(&self, name: &str, port: u16) -> Result<Opened, DialError> {
        let dns = self.resolve(name).await;
        if let Some(error) = &dns.error {
            return Err(DialError::Dns(error.clone()));
        }
        let Some(&address) = choose(&dns.addresses) else {
            return Err(DialError::NoAddresses);
        };
        let mut opened = self.open_address(address, port).await?;
        opened.dns = Some(dns);
        Ok(opened)
    }

    /// One literal address, which is also where a resolved name ends up.
    async fn open_address(&self, address: IpAddr, port: u16) -> Result<Opened, DialError> {
        let target = SocketAddr::new(address, port);
        tracing::debug!(target: TARGET, %target, "dialing");
        let stream = TcpStream::connect(target).await.map_err(classify_io)?;
        // Nagle holds a small write back until the previous one is
        // acknowledged, and every message this crate sends is small and
        // followed by a wait for the answer -- so leaving it on would put our
        // own kernel into every round trip the collector measures.
        stream.set_nodelay(true).map_err(classify_io)?;
        Ok(Opened {
            stream: Box::new(stream),
            remote_ip: Some(address),
            dns: None,
            connected_at: SystemTime::now(),
        })
    }

    /// One onion endpoint, through whatever seam is installed.
    async fn open_onion(&self, name: &str, port: u16) -> Result<Opened, DialError> {
        let Some(onion) = &self.onion else {
            tracing::debug!(target: TARGET, %name, "no tor: the onion endpoint is not dialed");
            return Err(DialError::TorUnavailable);
        };
        self.open_through(onion, name.to_owned(), port).await
    }

    /// One target through a Tor seam, whichever of the two it is.
    ///
    /// Shared by the onion dial and by `tor.route_clearnet`, because what is
    /// recorded is the same either way: a stream, and two columns that stay
    /// empty because the circuit did the part they would have described.
    async fn open_through(
        &self,
        via: &OnionDialer,
        target: String,
        port: u16,
    ) -> Result<Opened, DialError> {
        tracing::debug!(target: TARGET, %target, port, "dialing through tor");
        let stream = via(target, port).await.map_err(DialError::Tor)?;
        Ok(Opened {
            stream,
            // A circuit has no address of the far end at this end of it, and
            // reporting the rendezvous point's -- or, for a clearnet target,
            // whatever the exit resolved and did not tell us -- would be a
            // plausible looking lie.
            remote_ip: None,
            // Nor a lookup: an onion descriptor fetch is Tor's and is not a
            // set of A and AAAA records, and a clearnet name routed this way
            // is resolved by the exit, which answers with a stream and not
            // with records.
            dns: None,
            connected_at: SystemTime::now(),
        })
    }

    /// Every A and AAAA record for `name`, and the time the answer arrived.
    ///
    /// Never fails: a lookup that did not answer is a [`DnsResult`] with the
    /// reason in `error` and no addresses, because that is a row of
    /// `dns_resolutions` exactly as a successful one is.
    pub async fn resolve(&self, name: &str) -> DnsResult {
        match self.resolver.lookup_ip(name).await {
            Ok(lookup) => {
                let addresses: Vec<IpAddr> = lookup.iter().collect();
                tracing::debug!(target: TARGET, %name, ?addresses, "resolved");
                DnsResult {
                    at: SystemTime::now(),
                    addresses,
                    error: None,
                }
            }
            Err(err) => {
                let error = err.to_string();
                tracing::debug!(target: TARGET, %name, %error, "the lookup failed");
                DnsResult {
                    at: SystemTime::now(),
                    addresses: Vec::new(),
                    error: Some(error),
                }
            }
        }
    }

    /// The TLS handshake over an open transport, and the certificate it
    /// presented.
    async fn handshake(
        &self,
        stream: BoxStream,
        host: &Host,
    ) -> Result<(BoxStream, TlsInfo), DialError> {
        let name = server_name(host).map_err(DialError::Tls)?;
        // A verifier per handshake, because it is where the chain is
        // captured and two concurrent dials must not capture into the same
        // place. Cloning the configuration is a handful of `Arc` bumps.
        let capture = Arc::new(AcceptAny::new(Arc::clone(self.tls.crypto_provider())));
        let mut config = self.tls.clone();
        config
            .dangerous()
            .set_certificate_verifier(Arc::clone(&capture) as Arc<dyn ServerCertVerifier>);
        let stream = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|err| DialError::Tls(err.to_string()))?;

        let (_, connection) = stream.get_ref();
        // Debug rather than a mapping of our own: rustls spells these
        // `TLSv1_3` and `TLS13_AES_256_GCM_SHA384`, which are the names the
        // registry uses, and a table of ours would be a second one to keep
        // in step with rustls as suites are added.
        let tls_version = connection.protocol_version().map(|v| format!("{v:?}"));
        let tls_cipher = connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()));
        let leaf = capture.leaf();
        Ok((
            Box::new(stream),
            tls_info(leaf.as_deref().unwrap_or(&[]), tls_version, tls_cipher),
        ))
    }
}

/// The certificate columns out of one DER certificate.
///
/// Public because it is the whole of the parsing and because the thing worth
/// testing about it is what it does with a certificate it cannot read: the
/// hash and the bytes are always filled in and the parsed columns go null.
/// Never an error -- refusing to record a certificate because it is strange
/// would lose exactly the certificates worth looking at.
pub fn tls_info(der: &[u8], tls_version: Option<String>, tls_cipher: Option<String>) -> TlsInfo {
    let mut info = TlsInfo {
        sha256: sha256_hex(der),
        subject: None,
        issuer: None,
        sans: Vec::new(),
        not_before: None,
        not_after: None,
        der: der.to_vec(),
        tls_version,
        tls_cipher,
    };
    match X509Certificate::from_der(der) {
        Ok((_, certificate)) => {
            // RFC 4514 strings, which is what x509-parser's `Display` for a
            // name writes: `CN=electrum.example, O=Example`.
            info.subject = Some(certificate.subject().to_string());
            info.issuer = Some(certificate.issuer().to_string());
            info.sans = sans(&certificate);
            let validity = certificate.validity();
            info.not_before = Some(seconds(validity.not_before.timestamp()));
            info.not_after = Some(seconds(validity.not_after.timestamp()));
        }
        Err(err) => {
            tracing::debug!(
                target: TARGET,
                sha256 = %info.sha256,
                %err,
                "a presented certificate did not parse",
            );
        }
    }
    info
}

/// The DNS names and IP addresses of the subjectAltName extension.
///
/// The other general-name kinds -- e-mail addresses, URIs, directory names --
/// are dropped: `tls_certs.sans` is read as "which hostnames does this
/// certificate claim", and a certificate with no extension at all, or one
/// whose extension does not parse, contributes an empty list rather than a
/// failure.
fn sans(certificate: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(extension)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some((*name).to_owned()),
            GeneralName::IPAddress(bytes) => ip_address(bytes).map(|ip| ip.to_string()),
            _ => None,
        })
        .collect()
}

/// An IP address out of the four or sixteen bytes a SAN encodes one as.
fn ip_address(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        ))),
        _ => None,
    }
}

/// A certificate's seconds since the epoch as the microseconds every
/// timestamp in this database is in, saturating rather than wrapping: a
/// certificate claiming to expire in the year 300 000 is a strange
/// certificate and not a panic.
fn seconds(timestamp: i64) -> Micros {
    Micros(timestamp.saturating_mul(1_000_000))
}

/// Which address of the answer this attempt dials.
///
/// At random, so that over the reconnects of a long run every backend behind
/// a round-robin name is seen; see the module documentation. `RandomState`
/// rather than a random-number generator because the crate needs no other
/// randomness and this one is in the standard library: a fresh `RandomState`
/// is seeded differently every time it is built, so hashing a constant
/// through it is a different number on every call.
///
/// `None` for a lookup that answered with no address at all, which the
/// caller reports as [`DialError::NoAddresses`].
fn choose(addresses: &[IpAddr]) -> Option<&IpAddr> {
    if addresses.is_empty() {
        return None;
    }
    let index = RandomState::new().hash_one(0u8) as usize % addresses.len();
    addresses.get(index)
}

/// What a clearnet host goes to Tor as, for `tor.route_clearnet`.
///
/// `None` for an onion name, which is not what the setting is about: an onion
/// endpoint goes through the onion seam whether clearnet is routed or not.
/// A literal address goes as it is written and a name goes unresolved, so
/// that the exit does the lookup -- resolving it here would publish to our own
/// resolver exactly the list of servers the setting exists to hide, and the
/// records would then not be the ones the connection used anyway.
fn clearnet_target(host: &Host) -> Option<String> {
    match host {
        Host::Onion(_) => None,
        // Not `Host`'s `Display`, which brackets an IPv6 address for the
        // canonical `[::1]:50002` form: arti parses the host on its own and
        // takes the port beside it, so brackets would be part of the name.
        Host::Name(name) => Some(name.clone()),
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
}

/// The name to put in the SNI extension and to hand the verifier.
///
/// A hostname for a name and for an onion address -- a `.onion` is a perfectly
/// good DNS name and some onion Electrum servers do serve TLS on it -- and the
/// literal for an address, which rustls spells as an `IpAddress` name rather
/// than sending SNI at all, as RFC 6066 requires.
fn server_name(host: &Host) -> Result<ServerName<'static>, String> {
    match host {
        Host::Name(name) | Host::Onion(name) => ServerName::try_from(name.clone())
            .map_err(|err| format!("{name:?} is not a server name: {err}")),
        Host::Ipv4(address) => Ok(ServerName::IpAddress(IpAddr::V4(*address).into())),
        Host::Ipv6(address) => Ok(ServerName::IpAddress(IpAddr::V6(*address).into())),
    }
}

/// The client configuration every TLS dial starts from.
///
/// The provider is passed in rather than taken from the process-wide default,
/// which is never installed: a default is first-one-wins global state, and a
/// library that installs one decides for whatever else is linked in. `ring`
/// rather than aws-lc-rs for the reasons in `Cargo.toml`.
///
/// The verifier here is a placeholder -- every dial replaces it with one of
/// its own to capture into -- but it is the same accept-everything verifier,
/// so a configuration used without being cloned would still connect.
fn client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        // The provider is `ring`'s own and the versions are rustls's
        // defaults, so there is no combination here that rustls can refuse.
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny::new(provider)))
        .with_no_client_auth()
}

/// The resolver these settings describe.
///
/// `dns.upstream` is `host:port`, or a bare address for port 53. Hickory
/// takes a nameserver as an IP address and not as a name, which is the only
/// shape that can be resolved without a resolver to resolve it with.
fn resolver(dns: &DnsSettings) -> Result<TokioResolver> {
    let mut builder = match &dns.upstream {
        None => {
            TokioResolver::builder_tokio().context("reading the system resolver configuration")?
        }
        Some(upstream) => {
            let address = upstream_address(upstream)?;
            let connections = vec![
                with_port(ConnectionConfig::udp(), address.port()),
                with_port(ConnectionConfig::tcp(), address.port()),
            ];
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![NameServerConfig::new(
                    address.ip(),
                    true,
                    connections,
                )]),
                TokioRuntimeProvider::default(),
            )
        }
    };
    // Both families, every time. Hickory's default asks for AAAA and falls
    // back to A, which would leave a dual-stack server's A records out of
    // `dns_resolutions` -- and those records are the data (DESIGN.md
    // section 4).
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.build().context("building the resolver")
}

/// `dns.upstream` as an address and a port.
fn upstream_address(upstream: &str) -> Result<SocketAddr> {
    if let Ok(address) = upstream.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = upstream.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(anyhow!(
        "dns.upstream {upstream:?} is not an address: expected ip:port or ip, \
         because a nameserver cannot be named by something only a nameserver could resolve"
    ))
}

/// One connection to the upstream, on the configured port.
fn with_port(mut connection: ConnectionConfig, port: u16) -> ConnectionConfig {
    connection.port = port;
    connection
}

/// The failure for a connect the operating system refused.
///
/// Copied from crawler, with its taxonomy collapsed: this crate stores one
/// `end_reason` string and has no use for the difference between a host and a
/// network with no route to it. The number is read before the
/// [`io::ErrorKind`], because the number is what the kernel said and the kind
/// is the standard library's reading of it, and an error with no number at
/// all -- which is how a failure from a layer above the kernel arrives -- is
/// read by its kind.
fn classify_io(err: io::Error) -> DialError {
    match err
        .raw_os_error()
        .and_then(error_of_errno)
        .or_else(|| error_of_kind(err.kind()))
    {
        Some(classified) => classified,
        None => DialError::Io(err),
    }
}

/// The error numbers a connect has a name of its own for.
fn error_of_errno(errno: i32) -> Option<DialError> {
    match errno {
        libc::ECONNREFUSED => Some(DialError::Refused),
        libc::EHOSTUNREACH | libc::ENETUNREACH => Some(DialError::Unreachable),
        libc::ETIMEDOUT => Some(DialError::Timeout),
        _ => None,
    }
}

/// The same names, read off the standard library's own reading of an error.
fn error_of_kind(kind: io::ErrorKind) -> Option<DialError> {
    match kind {
        io::ErrorKind::ConnectionRefused => Some(DialError::Refused),
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            Some(DialError::Unreachable)
        }
        io::ErrorKind::TimedOut => Some(DialError::Timeout),
        _ => None,
    }
}

/// A certificate verifier that accepts everything and keeps what it saw.
///
/// Both halves are the point. Accepting everything is the only policy that
/// collects anything at all from a population of self-signed certificates
/// nobody validates; keeping the chain is what the collection is for. The
/// signature callbacks accept too, because a handshake stopped at the
/// signature would be a certificate not recorded, which is the one outcome
/// this module exists to avoid.
#[derive(Debug)]
struct AcceptAny {
    /// What the handshake presented, leaf first. Empty until one happens,
    /// and written exactly once by the handshake that owns this verifier.
    chain: Mutex<Vec<CertificateDer<'static>>>,
    /// For the schemes to advertise, which are the provider's and not a list
    /// of ours.
    provider: Arc<CryptoProvider>,
}

impl AcceptAny {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            chain: Mutex::new(Vec::new()),
            provider,
        }
    }

    /// The leaf of the captured chain, which is the certificate `tls_certs`
    /// stores (DESIGN.md section 4).
    ///
    /// A poisoned lock is read through rather than panicked on: the only
    /// writer is the handshake, and a connection whose certificate was
    /// captured by a task that then panicked is still a certificate.
    fn leaf(&self) -> Option<Vec<u8>> {
        let chain = self
            .chain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        chain.first().map(|der| der.as_ref().to_vec())
    }
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone().into_owned());
        chain.extend(intermediates.iter().map(|der| der.clone().into_owned()));
        *self
            .chain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = chain;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::str::FromStr;

    use rustls::ServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// The name the test certificate is issued for, and the name the test
    /// dials: a server that answered with a certificate for something else
    /// would still be accepted, so the SAN assertion is what says the
    /// handshake really reached this server.
    const NAME: &str = "localhost";

    /// A dialer on the defaults, which is what a run with an empty
    /// configuration file gets.
    fn dialer() -> Dialer {
        Dialer::new(&Settings::default()).expect("the system resolver configuration is readable")
    }

    /// The same dialer with a one-second connect timeout instead of the
    /// default twenty.
    ///
    /// For the tests whose subject is *which* route was taken. If the route
    /// under test is not taken, what happens instead is a TCP connect to an
    /// address reserved for documentation, which nothing answers for -- and
    /// twenty seconds of that is a test that reads as a hang rather than as
    /// a failure, both to a reader and to `cargo mutants`.
    fn quick_dialer() -> Dialer {
        let mut settings = Settings::default();
        settings.timeouts.connect_secs = 1;
        Dialer::new(&settings).expect("the system resolver configuration is readable")
    }

    fn endpoint(text: &str) -> Endpoint {
        Endpoint::from_str(text).expect("the test endpoint parses")
    }

    /// A listener on loopback with nothing behind it yet.
    async fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback is bindable");
        let address = listener.local_addr().expect("a bound listener has an addr");
        (listener, address)
    }

    /// Loopback listeners on both families sharing one port.
    ///
    /// `localhost` resolves to `127.0.0.1` and `::1` on an ordinary host and
    /// the dialer picks between them at random, so a test that served only
    /// one of the two would fail about half the time.
    async fn dual_listeners() -> (u16, TcpListener, TcpListener) {
        for _ in 0..64 {
            let (v4, address) = listener().await;
            let port = address.port();
            if let Ok(v6) = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await {
                return (port, v4, v6);
            }
        }
        panic!("no loopback port was free on both families");
    }

    /// A self-signed certificate for `NAME` and its DER, which is what the
    /// fingerprint is checked against.
    fn certificate() -> (Vec<u8>, PrivateKeyDer<'static>) {
        let key = rcgen::generate_simple_self_signed([NAME.to_owned()])
            .expect("rcgen issues a self-signed certificate");
        let der = key.cert.der().as_ref().to_vec();
        let private =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        (der, private)
    }

    /// A rustls acceptor presenting `der`, on the `ring` provider the client
    /// side uses, restricted to `versions`.
    fn acceptor(
        der: &[u8],
        key: PrivateKeyDer<'static>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> TlsAcceptor {
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .expect("ring supports the protocol versions the tests ask for")
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(der.to_vec())], key)
                .expect("the generated certificate and key match");
        TlsAcceptor::from(Arc::new(config))
    }

    /// Accepts one connection, finishes the handshake and echoes a greeting,
    /// so that the test can tell a handshake that completed from one that
    /// merely returned.
    fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor) {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("a connection arrives");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("the handshake finishes");
            stream
                .write_all(b"electrum")
                .await
                .expect("the write lands");
            stream.flush().await.expect("the flush lands");
        });
    }

    /// A plain dial reaches the listener, reports the address it used, and
    /// hands back a stream that really is the connection.
    ///
    /// All three together, because a stream that is not the connection and an
    /// address that is not the one dialed are both invisible in a test that
    /// only asserts the dial returned.
    #[tokio::test]
    async fn a_tcp_dial_reaches_the_listener_and_reports_the_address() {
        let (listener, address) = listener().await;
        let accepted = tokio::spawn(async move { listener.accept().await });

        let started = SystemTime::now();
        let mut dialed = dialer()
            .dial(&endpoint(&format!("tcp://127.0.0.1:{}", address.port())))
            .await
            .expect("loopback accepts the connection");

        assert_eq!(dialed.remote_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(dialed.dns, None, "an ip literal is not resolved");
        assert!(dialed.tls.is_none(), "a t port has no certificate");
        assert!(
            dialed.connected_at >= started,
            "the connect time is taken at the connect",
        );

        dialed.stream.write_all(b"hello").await.expect("it writes");
        let (mut server, _) = accepted
            .await
            .expect("the accept task does not panic")
            .expect("a connection arrived");
        let mut buffer = [0u8; 5];
        server
            .read_exact(&mut buffer)
            .await
            .expect("the bytes arrive");
        assert_eq!(&buffer, b"hello");
    }

    /// An IPv6 literal is dialed over IPv6, which is its own arm: a dial that
    /// built the wrong address family would not get off the host.
    #[tokio::test]
    async fn an_ipv6_literal_is_dialed_over_ipv6() {
        let listener = TcpListener::bind("[::1]:0")
            .await
            .expect("loopback v6 is bindable");
        let address = listener.local_addr().expect("a bound listener has an addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let dialed = dialer()
            .dial(&endpoint(&format!("tcp://[::1]:{}", address.port())))
            .await
            .expect("loopback v6 accepts the connection");

        assert_eq!(dialed.remote_ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(dialed.dns, None, "an ip literal is not resolved");
        let _ = accepted.await.expect("the accept task does not panic");
    }

    /// A TLS dial records the certificate the server presented: the
    /// fingerprint is the hash of exactly those bytes, the parsed columns are
    /// filled in, and the negotiated version is recorded.
    #[tokio::test]
    async fn a_tls_dial_records_the_presented_certificate() {
        let (der, key) = certificate();
        let (port, v4, v6) = dual_listeners().await;
        serve_tls(
            v4,
            acceptor(&der, key.clone_key(), rustls::DEFAULT_VERSIONS),
        );
        serve_tls(v6, acceptor(&der, key, rustls::DEFAULT_VERSIONS));

        let mut dialed = dialer()
            .dial(&endpoint(&format!("ssl://{NAME}:{port}")))
            .await
            .expect("the loopback tls server accepts the connection");

        let tls = dialed.tls.expect("an s port records a certificate");
        assert_eq!(
            tls.sha256,
            sha256_hex(&der),
            "the fingerprint is the hash of the certificate the server sent",
        );
        assert_eq!(tls.der, der, "the certificate is stored whole");
        assert!(
            tls.sans.contains(&NAME.to_owned()),
            "the subjectAltName of the test certificate is {NAME}: {:?}",
            tls.sans,
        );
        assert!(tls.subject.is_some(), "the subject is parsed");
        assert!(tls.issuer.is_some(), "a self-signed issuer is still parsed");
        let now = Micros::now();
        let not_before = tls.not_before.expect("a certificate has a validity");
        let not_after = tls.not_after.expect("a certificate has a validity");
        assert!(
            not_before <= now && now <= not_after,
            "the test certificate is valid now: {not_before:?} <= {now:?} <= {not_after:?}",
        );
        assert_eq!(
            tls.tls_version.as_deref(),
            Some("TLSv1_3"),
            "two rustls ends negotiate 1.3",
        );
        assert!(
            tls.tls_cipher
                .is_some_and(|suite| suite.starts_with("TLS13")),
            "the negotiated suite is recorded",
        );

        // The handshake really finished: the server's greeting arrives
        // through the stream the dial handed back.
        let mut greeting = [0u8; 8];
        dialed
            .stream
            .read_exact(&mut greeting)
            .await
            .expect("the server's greeting arrives");
        assert_eq!(&greeting, b"electrum");

        // A name was dialed, so the lookup is recorded with every record it
        // answered, and the address used is one of them.
        let dns = dialed.dns.expect("a name is resolved");
        assert!(dns.error.is_none(), "{dns:?}");
        assert!(
            dns.addresses.contains(&dialed.remote_ip.expect("an ip")),
            "the address dialed is one of the answers: {dns:?}",
        );
    }

    /// An IP literal over TLS sends no SNI, which rustls spells as an
    /// `IpAddress` server name: a client that sent the literal as a hostname
    /// instead is refused by rustls before a byte goes out.
    #[tokio::test]
    async fn a_tls_dial_to_an_ip_literal_needs_no_sni() {
        let (der, key) = certificate();
        let (listener, address) = listener().await;
        serve_tls(listener, acceptor(&der, key, rustls::DEFAULT_VERSIONS));

        let dialed = dialer()
            .dial(&endpoint(&format!("ssl://127.0.0.1:{}", address.port())))
            .await
            .expect("a literal address is dialed without a lookup");

        assert_eq!(dialed.dns, None, "an ip literal is not resolved");
        let tls = dialed.tls.expect("an s port records a certificate");
        assert_eq!(tls.sha256, sha256_hex(&der));
    }

    /// A server that only speaks TLS 1.2 is connected to and its certificate
    /// recorded just the same, and the negotiated version says 1.2.
    ///
    /// Not a curiosity: a good share of the `s` ports in the wild have never
    /// offered 1.3, and 1.2 takes a different path through the verifier --
    /// the signature over the key exchange rather than the one in
    /// `CertificateVerify` -- so a verifier that accepted only the 1.3 one
    /// would collect nothing from exactly those servers.
    #[tokio::test]
    async fn a_tls_1_2_only_server_is_recorded_too() {
        let (der, key) = certificate();
        let (listener, address) = listener().await;
        serve_tls(listener, acceptor(&der, key, &[&rustls::version::TLS12]));

        let dialed = dialer()
            .dial(&endpoint(&format!("ssl://127.0.0.1:{}", address.port())))
            .await
            .expect("a 1.2 server is connected to");

        let tls = dialed.tls.expect("an s port records a certificate");
        assert_eq!(tls.tls_version.as_deref(), Some("TLSv1_2"));
        assert_eq!(tls.sha256, sha256_hex(&der));
    }

    /// Without the Tor seam an onion endpoint is refused rather than leaked
    /// to the clearnet resolver, and refused under its own name so the
    /// `connections` row says why.
    #[tokio::test]
    async fn an_onion_endpoint_without_tor_is_refused() {
        let onion = "ssl://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion:50002";
        let error = dialer()
            .dial(&endpoint(onion))
            .await
            .err()
            .expect("there is no tor");

        assert_eq!(error.as_str(), "tor_unavailable");
    }

    /// With a seam installed, the onion endpoint is dialed through it and the
    /// stream it opened is the one handed back.
    ///
    /// The stub is a `duplex` pair, which is what step 8's arti client is a
    /// bigger version of: something that returns a stream for a name.
    #[tokio::test]
    async fn an_onion_endpoint_uses_the_installed_seam() {
        let (asked_host, asked_port) = (
            Arc::new(Mutex::new(String::new())),
            Arc::new(Mutex::new(0u16)),
        );
        let (host_seen, port_seen) = (Arc::clone(&asked_host), Arc::clone(&asked_port));
        let seam: OnionDialer = Box::new(move |host, port| {
            *host_seen.lock().expect("not poisoned") = host;
            *port_seen.lock().expect("not poisoned") = port;
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut theirs = theirs;
                    theirs.write_all(b"onion").await.expect("the write lands");
                });
                Ok(Box::new(ours) as BoxStream)
            })
        });

        let name = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";
        let mut dialed = dialer()
            .with_onion(seam)
            .dial(&endpoint(&format!("tcp://{name}:50001")))
            .await
            .expect("the seam opens the stream");

        assert_eq!(*asked_host.lock().expect("not poisoned"), name);
        assert_eq!(*asked_port.lock().expect("not poisoned"), 50001);
        assert_eq!(dialed.remote_ip, None, "a circuit has no address");
        assert_eq!(dialed.dns, None, "tor resolves onion names, not us");
        assert!(dialed.tls.is_none());

        let mut said = [0u8; 5];
        dialed
            .stream
            .read_exact(&mut said)
            .await
            .expect("the stub's stream is the one handed back");
        assert_eq!(&said, b"onion");
    }

    /// An `ssl://` onion endpoint gets its certificate recorded too: the
    /// handshake is the same step whichever transport opened the stream, and
    /// the SNI is the onion name.
    ///
    /// Rare in the wild but not impossible, and the alternative is a
    /// connection whose `tls_cert_id` is null for no reason a reader of the
    /// table could guess.
    #[tokio::test]
    async fn an_ssl_onion_endpoint_is_handshaken_over_the_seam() {
        let (der, key) = certificate();
        let acceptor = acceptor(&der, key, rustls::DEFAULT_VERSIONS);
        let seam: OnionDialer = Box::new(move |_, _| {
            let acceptor = acceptor.clone();
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(8 * 1024);
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(theirs).await.expect("the handshake ends");
                    stream.write_all(b"electrum").await.expect("it writes");
                    stream.flush().await.expect("it flushes");
                });
                Ok(Box::new(ours) as BoxStream)
            })
        });

        let name = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";
        let mut dialed = dialer()
            .with_onion(seam)
            .dial(&endpoint(&format!("ssl://{name}:50002")))
            .await
            .expect("the handshake runs over the onion stream");

        let tls = dialed.tls.expect("an s port records a certificate");
        assert_eq!(tls.sha256, sha256_hex(&der));
        assert_eq!(dialed.remote_ip, None, "a circuit has no address");

        let mut greeting = [0u8; 8];
        dialed
            .stream
            .read_exact(&mut greeting)
            .await
            .expect("the greeting arrives through the tls stream");
        assert_eq!(&greeting, b"electrum");
    }

    /// A seam that refuses carries its reason through as `tor`, so that a
    /// rendezvous that could not be made is a row and not a silent retry.
    #[tokio::test]
    async fn a_seam_that_refuses_is_reported_as_a_tor_failure() {
        let seam: OnionDialer =
            Box::new(|_, _| Box::pin(async { Err("no descriptor".to_owned()) }));
        let name = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";
        let error = dialer()
            .with_onion(seam)
            .dial(&endpoint(&format!("tcp://{name}:50001")))
            .await
            .err()
            .expect("the seam refused");

        assert_eq!(error.as_str(), "tor");
        assert!(error.to_string().contains("no descriptor"), "{error}");
    }

    /// A seam that records what it was asked for and hands back a stream
    /// saying "tor", which is how the tests below tell a circuit from a
    /// socket.
    fn recording_seam(seen: Arc<Mutex<Vec<(String, u16)>>>) -> OnionDialer {
        Box::new(move |host, port| {
            seen.lock().expect("not poisoned").push((host, port));
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut theirs = theirs;
                    theirs.write_all(b"tor").await.expect("the write lands");
                });
                Ok(Box::new(ours) as BoxStream)
            })
        })
    }

    /// `tor.route_clearnet`: a clearnet endpoint goes through the circuit and
    /// not through a socket, the name goes to the exit unresolved, and the
    /// two columns the circuit swallowed are null.
    ///
    /// The name is one nothing here can resolve, so a dialer that fell back
    /// to a socket would fail rather than quietly pass.
    #[tokio::test]
    async fn route_clearnet_sends_a_clearnet_endpoint_through_tor() {
        let seen = Arc::new(Mutex::new(Vec::new()));

        let mut dialed = quick_dialer()
            .with_clearnet_via(recording_seam(Arc::clone(&seen)))
            .dial(&endpoint("tcp://electrum.example.invalid:50001"))
            .await
            .expect("the circuit opens the stream");

        assert_eq!(
            *seen.lock().expect("not poisoned"),
            vec![("electrum.example.invalid".to_owned(), 50001)],
            "the name went to the exit unresolved",
        );
        assert_eq!(dialed.remote_ip, None, "the exit did the connecting");
        assert_eq!(dialed.dns, None, "the exit did the resolving");

        let mut said = [0u8; 3];
        dialed.stream.read_exact(&mut said).await.expect("it reads");
        assert_eq!(&said, b"tor");
    }

    /// A literal address goes through the circuit as it is written -- without
    /// the brackets the canonical form puts round an IPv6 one, because arti
    /// takes the host and the port separately.
    #[tokio::test]
    async fn route_clearnet_passes_a_literal_address_as_written() {
        for (written, expected) in [
            ("tcp://192.0.2.1:50001", "192.0.2.1"),
            ("tcp://[2001:db8::1]:50001", "2001:db8::1"),
        ] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let dialed = quick_dialer()
                .with_clearnet_via(recording_seam(Arc::clone(&seen)))
                .dial(&endpoint(written))
                .await
                .expect("the circuit opens the stream");

            assert_eq!(
                *seen.lock().expect("not poisoned"),
                vec![(expected.to_owned(), 50001)],
                "{written}",
            );
            assert_eq!(dialed.remote_ip, None, "{written}: the exit connected");
        }
    }

    /// With both seams installed an onion endpoint still goes through the
    /// onion one. They are different `StreamPrefs` -- a rendezvous and an
    /// exit -- so sending an onion name down the clearnet seam would ask an
    /// exit for a name it cannot reach.
    #[tokio::test]
    async fn route_clearnet_leaves_onion_endpoints_to_the_onion_seam() {
        let (onion_seen, clearnet_seen) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let name = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";

        quick_dialer()
            .with_onion(recording_seam(Arc::clone(&onion_seen)))
            .with_clearnet_via(recording_seam(Arc::clone(&clearnet_seen)))
            .dial(&endpoint(&format!("tcp://{name}:50001")))
            .await
            .expect("the onion seam opens the stream");

        assert_eq!(
            *onion_seen.lock().expect("not poisoned"),
            vec![(name.to_owned(), 50001)]
        );
        assert!(clearnet_seen.lock().expect("not poisoned").is_empty());
    }

    /// Without the setting the clearnet seam is not installed and a clearnet
    /// endpoint is dialed from a socket of ours, with the lookup recorded:
    /// the default is off and this is what off looks like.
    #[tokio::test]
    async fn without_route_clearnet_a_clearnet_endpoint_uses_a_socket() {
        let (listener, address) = listener().await;
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("a connection arrives");
            let mut stream = stream;
            stream.write_all(b"tcp").await.expect("the write lands");
        });

        let mut dialed = dialer()
            .with_onion(recording_seam(Arc::new(Mutex::new(Vec::new()))))
            .dial(&endpoint(&format!("tcp://127.0.0.1:{}", address.port())))
            .await
            .expect("the socket connects");

        assert_eq!(dialed.remote_ip, Some(address.ip()));
        let mut said = [0u8; 3];
        dialed.stream.read_exact(&mut said).await.expect("it reads");
        assert_eq!(&said, b"tcp");
    }

    /// Only an onion host is kept out of the clearnet route; every other kind
    /// has a target, and an IPv6 one has no brackets on it.
    #[test]
    fn only_an_onion_host_has_no_clearnet_target() {
        assert_eq!(
            clearnet_target(&Host::Name("electrum.example".to_owned())),
            Some("electrum.example".to_owned())
        );
        assert_eq!(
            clearnet_target(&Host::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            Some("192.0.2.1".to_owned())
        );
        assert_eq!(
            clearnet_target(&Host::Ipv6("2001:db8::1".parse().expect("a literal"))),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            clearnet_target(&Host::Onion(
                "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion".to_owned()
            )),
            None
        );
    }

    /// A name that does not exist is a `dns` failure, and the resolver's own
    /// words are kept -- they are what `dns_resolutions.error` stores.
    ///
    /// `.invalid` is reserved by RFC 2606 and resolves nowhere, so the answer
    /// is NXDOMAIN wherever this runs. On a host with no DNS at all the
    /// lookup fails for a different reason and the text differs, which is
    /// still this failure: the assertion is on the classification and on
    /// there being a reason, not on its wording. A resolver that somehow
    /// answered with no records at all is `no_addresses`, accepted here for
    /// the same reason.
    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_a_dns_failure() {
        let dialer = dialer();
        let error = dialer
            .dial(&endpoint("tcp://nxdomain.invalid:50001"))
            .await
            .err()
            .expect("nxdomain.invalid resolves nowhere");

        assert!(
            matches!(error, DialError::Dns(_) | DialError::NoAddresses),
            "the lookup failure was classified as {error:?}",
        );

        // The same lookup through the public entry point, which is what a
        // session writes the `dns_resolutions` row from.
        let result = dialer.resolve("nxdomain.invalid").await;
        assert!(result.addresses.is_empty(), "{result:?}");
        if let DialError::Dns(reported) = &error {
            assert!(result.error.is_some(), "the reason is recorded: {result:?}",);
            assert!(!reported.is_empty(), "the reason reached the caller");
        }
    }

    /// A lookup that answers is recorded with every record it answered.
    ///
    /// `localhost` is in `/etc/hosts` on every host this runs on, so the
    /// assertion needs no network. Both families are asked for, which is the
    /// `Ipv4AndIpv6` strategy: hickory's own default would stop at AAAA.
    #[tokio::test]
    async fn a_lookup_records_the_records_it_answered() {
        let before = SystemTime::now();
        let result = dialer().resolve(NAME).await;

        assert_eq!(result.error, None, "{result:?}");
        assert!(
            result.addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST))
                || result.addresses.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "localhost resolves to loopback: {result:?}",
        );
        assert!(result.at >= before, "the answer is stamped on arrival");
    }

    /// A port with nothing behind it is `refused`, which is the one failure
    /// that says the host is up: a server that is down and a server that is
    /// gone are different observations.
    #[tokio::test]
    async fn a_closed_port_is_refused() {
        let (listener, address) = listener().await;
        drop(listener);

        let error = dialer()
            .dial(&endpoint(&format!("tcp://127.0.0.1:{}", address.port())))
            .await
            .err()
            .expect("nothing is listening");

        assert_eq!(error.as_str(), "refused");
    }

    /// An address nothing answers for ends at the configured timeout rather
    /// than at the kernel's own, which is minutes of SYN retransmits.
    ///
    /// 192.0.2.0/24 is RFC 5737's documentation range: no network routes it,
    /// so the SYN goes nowhere. The clock is paused, so the twenty seconds of
    /// the default configuration cost nothing -- tokio advances it as soon as
    /// the connect is the only thing left to wait for.
    #[tokio::test(start_paused = true)]
    async fn an_address_nothing_answers_for_ends_at_the_connect_timeout() {
        let error = dialer()
            .dial(&endpoint("tcp://192.0.2.1:50001"))
            .await
            .err()
            .expect("the documentation range routes nowhere");

        assert_eq!(error.as_str(), "timeout");
    }

    /// A certificate x509-parser cannot read is still recorded, by its hash
    /// and its bytes, with the parsed columns null and the negotiated
    /// handshake kept: refusing to store it would lose exactly the
    /// certificates worth looking at.
    #[test]
    fn a_certificate_that_does_not_parse_is_still_recorded() {
        let garbage = b"\x30\x82this is not a certificate".to_vec();
        let info = tls_info(
            &garbage,
            Some("TLSv1_2".to_owned()),
            Some("TLS_SOMETHING".to_owned()),
        );

        assert_eq!(info.sha256, sha256_hex(&garbage));
        assert_eq!(info.der, garbage);
        assert_eq!(info.subject, None);
        assert_eq!(info.issuer, None);
        assert_eq!(info.sans, Vec::<String>::new());
        assert_eq!(info.not_before, None);
        assert_eq!(info.not_after, None);
        assert_eq!(info.tls_version.as_deref(), Some("TLSv1_2"));
        assert_eq!(info.tls_cipher.as_deref(), Some("TLS_SOMETHING"));
    }

    /// A self-signed certificate with exactly `sans` on it.
    fn issued_with(sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = sans;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "electrum.example");
        let key = rcgen::KeyPair::generate().expect("a key is generated");
        params
            .self_signed(&key)
            .expect("the certificate is issued")
            .der()
            .as_ref()
            .to_vec()
    }

    /// A certificate that parses fills in every parsed column; the IP SANs
    /// come out as addresses rather than as the four bytes they are encoded
    /// as, and a general name that is not a host -- an e-mail address here --
    /// contributes nothing, because `tls_certs.sans` is read as "which
    /// hostnames does this certificate claim".
    #[test]
    fn a_certificate_that_parses_fills_in_the_parsed_columns() {
        let der = issued_with(vec![
            rcgen::SanType::DnsName("electrum.example".try_into().expect("an ia5 string")),
            rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            rcgen::SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            rcgen::SanType::Rfc822Name("admin@electrum.example".try_into().expect("an ia5")),
        ]);

        let info = tls_info(&der, None, None);

        assert_eq!(info.subject.as_deref(), Some("CN=electrum.example"));
        assert_eq!(info.issuer.as_deref(), Some("CN=electrum.example"));
        assert_eq!(
            info.sans.iter().collect::<BTreeSet<_>>(),
            ["electrum.example", "127.0.0.1", "::1"]
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
                .iter()
                .collect::<BTreeSet<_>>(),
            "the dns name and the two ip addresses, and nothing else",
        );
        let now = Micros::now();
        assert!(info.not_before.expect("a validity") <= now);
        assert!(info.not_after.expect("a validity") >= now);
        assert_eq!(info.tls_version, None, "a parse knows no handshake");
    }

    /// A certificate with no subjectAltName extension at all is recorded with
    /// an empty list rather than refused: plenty of the self-signed
    /// certificates on Electrum's `s` ports have only a common name.
    #[test]
    fn a_certificate_with_no_sans_is_recorded_with_none() {
        let der = issued_with(Vec::new());

        let info = tls_info(&der, None, None);

        assert_eq!(info.sans, Vec::<String>::new());
        assert_eq!(info.subject.as_deref(), Some("CN=electrum.example"));
        assert_eq!(info.sha256, sha256_hex(&der));
    }

    /// Every failure has its own name, and the names are the ones that go
    /// into `connections.end_reason`: renaming one is a change to the output
    /// that analyses filter on.
    #[test]
    fn every_failure_has_its_own_end_reason() {
        let all = [
            (DialError::Dns("why".to_owned()), "dns"),
            (DialError::NoAddresses, "no_addresses"),
            (DialError::Timeout, "timeout"),
            (DialError::Refused, "refused"),
            (DialError::Unreachable, "unreachable"),
            (DialError::Io(io::Error::other("boom")), "io"),
            (DialError::Tls("why".to_owned()), "tls"),
            (DialError::TorUnavailable, "tor_unavailable"),
            (DialError::Tor("why".to_owned()), "tor"),
        ];
        for (error, name) in &all {
            assert_eq!(error.as_str(), *name);
            assert_eq!(error.end_reason(), *name);
            assert!(!error.to_string().is_empty(), "{name} has a message");
        }
        let names: BTreeSet<&str> = all.iter().map(|(_, name)| *name).collect();
        assert_eq!(names.len(), all.len(), "two failures share a name");
    }

    /// The detail of the three failures that carry one reaches the message,
    /// and an `io` failure keeps the error itself as its source so that
    /// `{:#}` on an `anyhow` chain says what the kernel said.
    #[test]
    fn the_detail_of_a_failure_reaches_its_message() {
        use std::error::Error as _;

        assert!(
            DialError::Dns("nxdomain".to_owned())
                .to_string()
                .contains("nxdomain")
        );
        assert!(
            DialError::Tls("bad record mac".to_owned())
                .to_string()
                .contains("bad record mac")
        );
        assert!(
            DialError::Tor("no descriptor".to_owned())
                .to_string()
                .contains("no descriptor")
        );
        let io = DialError::Io(io::Error::other("boom"));
        assert!(io.to_string().contains("boom"));
        assert!(io.source().is_some(), "an io failure keeps its cause");
        assert!(
            DialError::Timeout.source().is_none(),
            "the others have none",
        );
    }

    /// The classification reads the operating system's number first and the
    /// standard library's kind after, and keeps the error itself for
    /// everything it has no name for.
    ///
    /// Both halves matter: an error that did not come from a syscall has a
    /// kind and no number, and on a platform whose errno mapping is
    /// incomplete an error has a number and the kind `Other`. Each half is
    /// asserted on its own as well as through `classify_io`, because on
    /// Linux the two agree for all four and a reading that used only the
    /// other one would pass every end-to-end assertion here.
    #[test]
    fn the_classification_reads_the_number_first_and_the_kind_after() {
        let by_number = [
            (libc::ECONNREFUSED, "refused"),
            (libc::EHOSTUNREACH, "unreachable"),
            (libc::ENETUNREACH, "unreachable"),
            (libc::ETIMEDOUT, "timeout"),
        ];
        for (errno, name) in by_number {
            assert_eq!(
                error_of_errno(errno).map(|error| error.as_str()),
                Some(name),
                "errno {errno} read as a number",
            );
            assert_eq!(
                classify_io(io::Error::from_raw_os_error(errno)).as_str(),
                name,
                "errno {errno}",
            );
        }
        assert_eq!(error_of_errno(libc::EACCES).map(|e| e.as_str()), None);
        assert_eq!(
            classify_io(io::Error::from_raw_os_error(libc::EACCES)).as_str(),
            "io",
            "an error with no name of ours keeps the system's own",
        );

        let by_kind = [
            (io::ErrorKind::ConnectionRefused, "refused"),
            (io::ErrorKind::HostUnreachable, "unreachable"),
            (io::ErrorKind::NetworkUnreachable, "unreachable"),
            (io::ErrorKind::TimedOut, "timeout"),
        ];
        for (kind, name) in by_kind {
            assert_eq!(
                error_of_kind(kind).map(|error| error.as_str()),
                Some(name),
                "{kind:?} read as a kind",
            );
            assert_eq!(
                classify_io(io::Error::new(kind, "no number")).as_str(),
                name,
                "{kind:?}",
            );
        }
        assert_eq!(
            error_of_kind(io::ErrorKind::PermissionDenied).map(|e| e.as_str()),
            None,
        );
        assert_eq!(
            classify_io(io::Error::other("no number either")).as_str(),
            "io",
        );
    }

    /// The address is chosen at random among the answers, which is what makes
    /// a long run see every backend behind a round-robin name. A dialer that
    /// took the first would only ever reach one of these three.
    #[test]
    fn the_address_dialed_is_chosen_at_random() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ];
        let mut seen = BTreeSet::new();
        for _ in 0..1_000 {
            seen.insert(*choose(&addresses).expect("there are three answers"));
        }
        assert_eq!(
            seen.len(),
            addresses.len(),
            "every address was dialed at least once over a thousand attempts",
        );

        let one = [IpAddr::V6(Ipv6Addr::LOCALHOST)];
        assert_eq!(choose(&one), Some(&one[0]), "one answer is the answer");
        assert_eq!(choose(&[]), None, "no answer is no address to dial");
    }

    /// SNI is a hostname for a name and an address for a literal, which is
    /// RFC 6066: a literal in the SNI extension is not allowed, and rustls
    /// enforces it.
    #[test]
    fn the_server_name_follows_the_host() {
        assert_eq!(
            server_name(&Host::Name("electrum.example".to_owned())).expect("a valid name"),
            ServerName::try_from("electrum.example").expect("a valid name"),
        );
        let onion = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcm32kvxb2jmbbggl6j3ad.onion";
        assert_eq!(
            server_name(&Host::Onion(onion.to_owned())).expect("an onion name is a dns name"),
            ServerName::try_from(onion).expect("a valid name"),
        );
        assert_eq!(
            server_name(&Host::Ipv4(Ipv4Addr::LOCALHOST)).expect("a literal"),
            ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        );
        assert_eq!(
            server_name(&Host::Ipv6(Ipv6Addr::LOCALHOST)).expect("a literal"),
            ServerName::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST).into()),
        );
        // A name no DNS name could be: parsing an endpoint never produces
        // one, but a `Host` built by hand can, and refusing it is a `tls`
        // failure rather than a panic.
        assert!(server_name(&Host::Name("not a name".to_owned())).is_err());
    }

    /// `dns.upstream` takes `ip:port` and a bare address, and refuses a name:
    /// a nameserver named by something only a nameserver could resolve is a
    /// configuration that cannot start.
    #[test]
    fn the_upstream_resolver_is_an_address() {
        assert_eq!(
            upstream_address("9.9.9.9:5353").expect("an ip and a port"),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 5353)),
        );
        assert_eq!(
            upstream_address("9.9.9.9").expect("a bare ip is port 53"),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
        );
        assert_eq!(
            upstream_address("[2620:fe::fe]:5353").expect("a v6 ip and a port"),
            SocketAddr::from((Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe), 5353)),
        );
        assert_eq!(
            upstream_address("2620:fe::fe").expect("a bare v6 ip is port 53"),
            SocketAddr::from((Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe), 53)),
        );
        let error = upstream_address("dns.example:53").expect_err("a name is not an address");
        assert!(error.to_string().contains("dns.example:53"), "{error}");
    }

    /// A configured upstream builds a resolver pointed at it, on the port it
    /// names rather than on 53.
    #[test]
    fn a_configured_upstream_is_the_one_the_resolver_asks() {
        let settings = Settings {
            dns: DnsSettings {
                upstream: Some("127.0.0.53:5353".to_owned()),
            },
            ..Settings::default()
        };
        assert!(
            Dialer::new(&settings).is_ok(),
            "a dialer is built on a configured upstream",
        );

        let bad = Settings {
            dns: DnsSettings {
                upstream: Some("not-an-address".to_owned()),
            },
            ..Settings::default()
        };
        assert!(
            Dialer::new(&bad).is_err(),
            "an upstream that is not an address does not start",
        );

        assert_eq!(with_port(ConnectionConfig::udp(), 5353).port, 5353);
        assert_eq!(with_port(ConnectionConfig::tcp(), 5353).port, 5353);
        assert_eq!(
            ConnectionConfig::udp().port,
            53,
            "the default is the one the port replaces",
        );
    }

    /// The verifier accepts every certificate and keeps the chain it was
    /// shown, leaf first. Tested without a handshake, because the one thing
    /// worth asserting -- that nothing is ever refused -- is hard to see in a
    /// handshake that would have succeeded anyway.
    #[test]
    fn the_verifier_accepts_everything_and_keeps_the_chain() {
        let verifier = AcceptAny::new(Arc::new(rustls::crypto::ring::default_provider()));
        assert_eq!(verifier.leaf(), None, "nothing is captured before a dial");

        let leaf = CertificateDer::from(vec![1u8, 2, 3]);
        let intermediate = CertificateDer::from(vec![4u8, 5, 6]);
        verifier
            .verify_server_cert(
                &leaf,
                &[intermediate],
                &ServerName::try_from("electrum.example").expect("a valid name"),
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(0)),
            )
            .expect("every certificate is accepted");
        assert_eq!(
            verifier.leaf(),
            Some(vec![1u8, 2, 3]),
            "the leaf is the first of the chain",
        );

        assert!(
            !verifier.supported_verify_schemes().is_empty(),
            "the provider's schemes are advertised",
        );
    }

    /// The parsed-out SAN addresses are the ones the encoding can carry, and
    /// anything else contributes nothing rather than a wrong address.
    #[test]
    fn a_san_address_is_four_bytes_or_sixteen() {
        assert_eq!(
            ip_address(&[127, 0, 0, 1]),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        assert_eq!(
            ip_address(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        );
        assert_eq!(ip_address(&[]), None);
        assert_eq!(ip_address(&[1, 2, 3]), None, "a malformed san is dropped");
    }

    /// A certificate's seconds become the microseconds every timestamp in
    /// this database is in, and a validity far outside that range saturates
    /// rather than wrapping into the past.
    #[test]
    fn a_validity_becomes_microseconds() {
        assert_eq!(seconds(0), Micros(0));
        assert_eq!(seconds(1_700_000_000), Micros(1_700_000_000_000_000));
        assert_eq!(seconds(-1), Micros(-1_000_000));
        assert_eq!(seconds(i64::MAX), Micros(i64::MAX));
        assert_eq!(seconds(i64::MIN), Micros(i64::MIN));
    }
}
