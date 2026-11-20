# electrum-observer as a package, with its test suite in the check phase.
#
# Built from the flake, which passes the revision it was built from:
#
#     nix build .#electrum-observer
#
# Modelled on crawler's nix/package.nix: the same fileset source, the same
# `cargoLock.lockFile` instead of a `cargoHash`, and the same `gitCommit`
# argument.
{
  lib,
  rustPlatform,
  libredirect,
  # The revision of the tree this was built from, which the flake passes:
  # `self.rev` for a clean tree, `dirtyRev` for one with uncommitted changes,
  # neither for a build of a plain directory. Nothing reads it yet -- unlike
  # crawler, this binary records no build commit anywhere -- so it is accepted
  # and not turned into an environment variable: the day a `meta` row or a
  # startup line wants the commit, the flake already passes it.
  gitCommit ? "unknown",
}:

let
  cargoToml = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;

  # Only what the build and the tests read. `tests/` is in it because the
  # check phase runs the integration tests, and `config-example.yaml` because
  # the settings tests compare it against `Settings::default` -- the test that
  # keeps the documented defaults honest reads that file from
  # `CARGO_MANIFEST_DIR`. `tests/fixtures/` comes with `tests/`, and the 1209k
  # fixture in it is `include_str!`-ed by `src/seeds.rs` as well.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../tests
      ../config-example.yaml
    ];
  };

  # The lockfile rather than a `cargoHash`: every dependency comes from
  # crates.io -- there is no git dependency, so there is no `outputHashes` to
  # keep either -- and nothing in the tree is two versions of one crate from
  # two sources, which is the case `cargoLock` cannot vendor. One hash fewer
  # to update on every dependency bump.
  cargoLock.lockFile = ../Cargo.lock;

  # The unit tests and the integration tests. None of them needs the network:
  # the only subcommand that fetches is `import 1209k`, and that is tested
  # through `seeds`' parser against the committed fixture instead (the header
  # of tests/cli.rs says so), while the session and probe tests dial a mock
  # server on loopback, which the build sandbox has. What the sandbox does
  # not have is a resolver configuration and a route off the host, which is
  # what `preCheck` and the one `checkFlags` entry below are about.
  doCheck = true;

  nativeCheckInputs = [ libredirect ];

  # Everything the dialer's tests do needs a resolver, and a resolver on the
  # default settings is built from the system configuration -- which a build
  # sandbox has no `/etc/resolv.conf` for, and `/etc` in it is read-only, so
  # the file cannot simply be written. libredirect, which is in nixpkgs for
  # exactly this, points the open at one written here instead. The nameserver
  # in it is never asked anything: the only name the tests look up is
  # `localhost`, which comes from `/etc/hosts`, and the sandbox has that one.
  preCheck = ''
    echo "nameserver 127.0.0.1" > "$TMPDIR/resolv.conf"
    export NIX_REDIRECTS="/etc/resolv.conf=$TMPDIR/resolv.conf"
    export LD_PRELOAD="${libredirect}/lib/libredirect.so"
  '';

  postCheck = ''
    unset LD_PRELOAD NIX_REDIRECTS
  '';

  checkFlags = [
    # This one dials 192.0.2.1 to have a SYN that nothing answers, and
    # asserts that the configured connect timeout is what ends the attempt.
    # The sandbox has only a loopback interface, so there is no route to the
    # documentation range and the connect fails at once with
    # `NetworkUnreachable` instead, which is a different classification.
    # Crawler skips its own version of this test for the same reason; the
    # kernel-timeout path is covered by `cargo test` in the dev shell.
    "--skip=dial::tests::an_address_nothing_answers_for_ends_at_the_connect_timeout"
  ];

  meta = {
    description = "Watches public Electrum servers and records what they answer";
    license = lib.licenses.mit;
    mainProgram = "electrum-observer";
    platforms = lib.platforms.unix;
  };
}
