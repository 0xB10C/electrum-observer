//! The tracing subscriber and its log field formatting.
//!
//! Copied from crawler's `src/logging.rs`, which took the formatter from
//! p2p-observer: a log these projects can be read with one set of habits is
//! worth more than a formatter of our own. Nothing is changed but the names
//! -- crawler's `log.default` is `log.level` here -- so the diff against the
//! original stays readable.
//!
//! Levels reach the `EnvFilter` from the configuration rather than from the
//! environment: nothing reads `RUST_LOG`, because the config file is the
//! configuration, and once `log.targets` exists one module can be turned up
//! on its own -- `session: trace` while the rest stays at info.

// For `write!` through the escaping adapter; `Writer`'s own `write_fmt` is an
// inherent method and needs no import.
use std::fmt::Write as _;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

use crate::settings::LogSettings;

/// Installs the subscriber the configured levels ask for.
///
/// Separate from the collector because a subscriber is process-wide and can
/// only be installed once: the binary does it at startup, and a test either
/// does it itself or does without. Failing rather than panicking on a second
/// call, so that a test binary that installs one twice says so.
///
/// The settings become one `EnvFilter` string -- `"info"`, or
/// `"info,session=trace"` -- through
/// [`LogSettings::to_filter_string`]; `Settings::validate` has already
/// refused a level that is not one, so a failure here is the second
/// subscriber rather than the config file.
pub fn init(settings: &LogSettings) -> Result<()> {
    let directives = settings.to_filter_string();
    let filter =
        EnvFilter::try_new(&directives).with_context(|| format!("log levels {directives:?}"))?;
    tracing_subscriber::fmt()
        // Stderr, not the default stdout: `import` and `servers` print their
        // result to stdout for a pipe to read, and a log line arriving in
        // the middle of it would be one of the fields. It is also where a
        // daemon's log belongs -- systemd journals both streams, and a
        // `run` whose output is being read at all is being read by a person.
        .with_writer(std::io::stderr)
        // The target is the module name the config file names, so a line can
        // be traced back to the setting that let it through.
        .with_target(true)
        .fmt_fields(PlainFields)
        .with_env_filter(filter)
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("installing the log subscriber")
}

/// Field formatter that writes `key=value` pairs without ANSI italic styling,
/// so fields are plainly greppable while level colors from the event formatter
/// are preserved.
pub(crate) struct PlainFields;

impl<'w> tracing_subscriber::fmt::FormatFields<'w> for PlainFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: tracing_subscriber::fmt::format::Writer<'w>,
        fields: R,
    ) -> std::fmt::Result {
        let mut v = PlainVisitor {
            writer,
            is_first: true,
            result: Ok(()),
        };
        fields.record(&mut v);
        v.result
    }
}

/// Writes through, with control characters escaped.
///
/// A field value can be a server's. A banner, an error string, a peer
/// hostname: all of them arrive from the other end of a socket, all of them
/// are logged as fields, and none of them is checked for anything but being
/// UTF-8. One line per event is the premise of this format, so a value
/// carrying a newline ends the line early and the half after it can be made
/// to look like a record from somewhere else.
///
/// Streaming rather than escaping a formatted string, so nothing is allocated
/// per field: these are trace lines on the message loop.
struct Escaped<W>(W);

impl<W: std::fmt::Write> std::fmt::Write for Escaped<W> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut rest = s;
        while let Some(at) = rest.find(char::is_control) {
            self.0.write_str(&rest[..at])?;
            let c = rest[at..]
                .chars()
                .next()
                .expect("`find` returned a char boundary");
            for escaped in c.escape_debug() {
                self.0.write_char(escaped)?;
            }
            rest = &rest[at + c.len_utf8()..];
        }
        self.0.write_str(rest)
    }
}

struct PlainVisitor<'w> {
    writer: tracing_subscriber::fmt::format::Writer<'w>,
    is_first: bool,
    result: std::fmt::Result,
}

impl PlainVisitor<'_> {
    fn write_field(&mut self, field: &tracing::field::Field, val: &dyn std::fmt::Display) {
        if self.result.is_err() {
            return;
        }
        if !std::mem::replace(&mut self.is_first, false) {
            self.result = write!(self.writer, " ");
            if self.result.is_err() {
                return;
            }
        }
        // The name is ours and the value may not be, so only the value goes
        // through the escaping writer.
        if field.name() != "message" {
            self.result = write!(self.writer, "{}=", field.name());
            if self.result.is_err() {
                return;
            }
        }
        self.result = write!(Escaped(self.writer.by_ref()), "{val}");
    }
}

impl tracing::field::Visit for PlainVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, v: f64) {
        self.write_field(field, &v);
    }
    fn record_i64(&mut self, field: &tracing::field::Field, v: i64) {
        self.write_field(field, &v);
    }
    fn record_u64(&mut self, field: &tracing::field::Field, v: u64) {
        self.write_field(field, &v);
    }
    fn record_bool(&mut self, field: &tracing::field::Field, v: bool) {
        self.write_field(field, &v);
    }
    fn record_str(&mut self, field: &tracing::field::Field, v: &str) {
        self.write_field(field, &v);
    }
    fn record_debug(&mut self, field: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.write_field(field, &format_args!("{v:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// Keeps what the subscriber wrote, so a test can read the line back.
    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Collect {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Collect {
        type Writer = Collect;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// What the formatter writes for one event.
    fn logged(ansi: bool, emit: impl FnOnce()) -> String {
        let out = Collect::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(ansi)
            .without_time()
            .with_level(false)
            .with_target(false)
            .fmt_fields(PlainFields)
            .with_writer(out.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = out
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).expect("the formatter writes utf-8")
    }

    /// The subscriber is installed from the configured levels, and a level
    /// that is not a level is refused rather than quietly dropped by the
    /// filter.
    ///
    /// All three outcomes in one test, because the second one is only true
    /// once per process: a subscriber is global, and a test that installed a
    /// second one would be testing a different thing than it says.
    #[test]
    fn the_subscriber_is_installed_once_from_the_configured_levels() {
        let mut broken = LogSettings::default();
        broken
            .targets
            .insert("session".to_string(), "chatty".to_string());
        let error = init(&broken).expect_err("a level that is not a level");
        assert!(format!("{error:#}").contains("chatty"), "{error:#}");

        let settings = LogSettings::default();
        init(&settings).expect("the first subscriber installs");
        assert!(
            init(&settings).is_err(),
            "a second subscriber would silently replace nothing"
        );
    }

    /// The message comes out bare and the rest as `key=value`, which is what
    /// makes a line greppable by field.
    #[test]
    fn fields_are_plain_key_value_pairs() {
        let line = logged(false, || {
            tracing::info!(peers = 7u64, net = "signet", ok = true, "stats");
        });
        assert_eq!(line.trim_end(), "stats peers=7 net=signet ok=true");
    }

    /// Every kind of value a field can hold reaches the line.
    #[test]
    fn every_value_kind_is_written() {
        let line = logged(false, || {
            tracing::info!(
                a = 1i64,
                b = 2u64,
                c = 0.5f64,
                d = false,
                e = "s",
                f = ?Some(3),
                "m"
            );
        });
        assert_eq!(line.trim_end(), "m a=1 b=2 c=0.5 d=false e=s f=Some(3)");
    }

    /// Field names are not italicised, which is the whole reason this
    /// formatter exists: the default one wraps every name in an ANSI italic
    /// sequence, and a log full of escape codes cannot be grepped by field.
    #[test]
    fn field_names_are_not_italicised() {
        let line = logged(true, || tracing::info!(peers = 7u64, "stats"));
        assert!(
            !line.contains("\u{1b}[3m"),
            "an italic sequence reached the line: {line:?}"
        );
        assert!(line.contains("peers=7"), "{line:?}");
    }

    /// A field value cannot end the line.
    ///
    /// Values are not all ours: a server's banner is whatever its operator
    /// put there, and it is logged as a field. One line per event is the
    /// premise of this format, so a value carrying a newline ends the line
    /// early and the half after it can be made to look like a record from
    /// somewhere else.
    #[test]
    fn a_field_value_cannot_end_the_line() {
        let hostile = "ha\nha\r\nINFO forged";
        let line = logged(false, || {
            tracing::info!(banner = %hostile, "server.banner");
        });
        assert_eq!(
            line.lines().count(),
            1,
            "the value split the line: {line:?}"
        );
        assert!(
            line.contains("banner=ha\\nha\\r\\nINFO forged"),
            "escaped rather than dropped: {line:?}"
        );
    }

    /// And the message itself, which is ours but reaches the same writer.
    #[test]
    fn a_message_cannot_end_the_line() {
        let line = logged(false, || tracing::info!("first\nsecond"));
        assert_eq!(line.lines().count(), 1, "{line:?}");
    }
}
