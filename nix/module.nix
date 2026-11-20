# NixOS module for electrum-observer.
#
#   services.electrum-observer = {
#     enable = true;
#     settings = {
#       chain = "mainnet";
#       sessions_per_server = 2;
#       discovery.max_servers = 400;
#     };
#     seeds.importOnStart = [ "sparrow" "1209k" ];
#     seeds.serverFiles = [ ./my-servers.txt ];
#   };
#
# One daemon, not a batch job: it holds a connection to every enabled server
# open for as long as it runs, so this is a single long-running service rather
# than crawler's service-and-timer per chain. The hardening block, the
# `settings` option rendered to YAML and the `defaultText` shape are crawler's
# nix/module.nix and spytrap's nix/module.nix; what differs is `DynamicUser`
# instead of a static user (the database and arti's state are the only state,
# and both live in the `StateDirectory` systemd hands the dynamic user), and
# the `ExecStartPre` imports, because a fresh deployment with an empty
# `servers` table would connect to nothing and discovery would have no peer
# to learn from.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.electrum-observer;
  settingsFormat = pkgs.formats.yaml { };
  configFile = settingsFormat.generate "electrum-observer.yaml" cfg.settings;

  # `/var/lib/electrum-observer`, which systemd creates and chowns to the
  # dynamic user before the service starts. Everything the daemon writes is
  # under it: the SQLite database with its WAL sidecars, and arti's state,
  # which `tor.state_dir = null` puts at `<database dir>/arti` -- one state
  # directory for both.
  stateDirectory = "electrum-observer";
  stateDir = "/var/lib/${stateDirectory}";

  exe = lib.getExe cfg.package;

  # `electrum-observer --config <file> <subcommand>`: `--config` is global and
  # defaulted to `config.yaml` in the working directory, which under
  # `ProtectSystem = strict` is not a file anyone wrote.
  observer =
    args:
    lib.escapeShellArgs (
      [
        exe
        "--config"
        "${configFile}"
      ]
      ++ args
    );

  # The imports that run before the daemon does, one `ExecStartPre` each.
  # Idempotent by construction: `upsert_server` leaves an existing row
  # untouched, so a server disabled by hand stays disabled across restarts and
  # a restart adds nothing it already knows.
  #
  # `1209k` is the one subcommand that makes a request, and it is prefixed
  # with `-` so that a website being down is not a daemon that refuses to
  # start: the servers from the last successful import are in the database
  # already. `sparrow` ships its list in the binary and a server file is a
  # local path, so both of those are allowed to fail the start -- there is no
  # transient reason for them to fail, and a typo in a path should be loud.
  importCommands =
    map (
      source:
      lib.optionalString (source == "1209k") "-"
      + observer [
        "import"
        source
      ]
    ) cfg.seeds.importOnStart
    ++ map (
      file:
      observer [
        "import"
        "file"
        "${file}"
      ]
    ) cfg.seeds.serverFiles;

  # Taken from crawler's module, which took it from p2p-observer's. The daemon
  # makes outbound TCP connections, opens DNS sockets, writes SQLite and
  # listens on nothing, so there is no capability to keep and no address
  # family beyond TCP and the local socket. Two things deliberately absent:
  # any address filtering (`IPAddressDeny` and friends), because arti has to
  # reach the directory authorities and the guards, and any read-only state --
  # `StateDirectory` stays writable for the database and for arti's guards and
  # directory cache.
  hardening = {
    DynamicUser = true;
    NoNewPrivileges = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
    CapabilityBoundingSet = "";
    UMask = "0027";
  };
in
{
  options.services.electrum-observer = {
    enable = lib.mkEnableOption "electrum-observer, which watches public Electrum servers and records what they answer";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.electrum-observer;
      defaultText = lib.literalExpression "electrum-observer.packages.\${system}.electrum-observer";
      description = "The electrum-observer package.";
    };

    settings = lib.mkOption {
      description = ''
        The configuration file, written to YAML and passed as `--config`.
        Every key of `config-example.yaml` is accepted and every key has a
        default, so `{ }` is what that file documents; a key the daemon does
        not know is an error at startup rather than a line that is ignored.

        `database` defaults into the service's `StateDirectory`, and
        `tor.state_dir` is left `null`, which the daemon reads as
        `<database dir>/arti` -- so both of the daemon's state directories are
        under `${stateDir}`, which systemd creates and keeps.

        This lands in the Nix store, which is world-readable.
      '';
      default = { };
      example = lib.literalExpression ''
        {
          chain = "mainnet";
          sessions_per_server = 2;
          overrides = [ { endpoint = "ssl://tool.sh:50002"; sessions = 3; } ];
          discovery.max_servers = 400;
          tor.route_clearnet = true;
          log.targets.session = "debug";
        }
      '';
      type = lib.types.submodule {
        freeformType = settingsFormat.type;
        options = {
          database = lib.mkOption {
            type = lib.types.path;
            default = "${stateDir}/observer.sqlite";
            defaultText = lib.literalExpression ''"${stateDir}/observer.sqlite"'';
            description = ''
              The SQLite database everything is written to, in WAL mode, so it
              can be read with sqlite3 or DuckDB while the daemon runs.

              It has to stay under `${stateDir}`: the service runs with
              `DynamicUser` and `ProtectSystem = "strict"`, under which that
              directory is the only writable place it has.
            '';
          };
        };
      };
    };

    seeds = {
      importOnStart = lib.mkOption {
        type = lib.types.listOf (
          lib.types.enum [
            "1209k"
            "sparrow"
          ]
        );
        default = [ "sparrow" ];
        example = [
          "sparrow"
          "1209k"
        ];
        description = ''
          Seed sources imported into the `servers` table before each start,
          one `electrum-observer import <source>` per entry. Without at least
          one of these a fresh deployment has no server to connect to and
          discovery has no peer list to learn from, which is why `sparrow` --
          the list the binary ships, for the configured chain, needing no
          network -- is the default.

          `1209k` fetches the server table at 1209k.com and is mainnet only.
          It is allowed to fail: a start is not held up by that site being
          down, since whatever a previous import found is in the database.

          Importing is idempotent and never re-enables anything: a server
          disabled by hand stays disabled across restarts.
        '';
      };

      serverFiles = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [ ];
        example = lib.literalExpression "[ ./my-servers.txt ]";
        description = ''
          Files of endpoints imported before each start, one
          `electrum-observer import file <path>` per entry. One endpoint per
          line in either `ssl://host:port` or `host:port:s` form, `#` for
          comments. A line that is not an endpoint fails the import and so the
          start.

          This is `servers_file` done once at import time rather than on every
          startup, which is the difference between a list that becomes rows
          with a source of `file` and a list the daemon re-reads.
        '';
      };
    };

    maxOpenFiles = lib.mkOption {
      type = lib.types.ints.positive;
      default = 65536;
      description = ''
        `LimitNOFILE` of the service. Every monitored server holds its
        connection open for the life of the process, so the daemon needs
        `discovery.max_servers` times `sessions_per_server` descriptors at
        once, plus the 512 it reserves for the database, arti and DNS, and it
        refuses to start if the limit cannot cover that (see `fdlimit`). The
        default clears the default cap of 600 servers many times over.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "${stateDir}/" (toString cfg.settings.database);
        message = ''
          services.electrum-observer.settings.database must be under
          ${stateDir}: the service runs with DynamicUser and
          ProtectSystem = "strict", so its StateDirectory is the only place it
          can write.
        '';
      }
      {
        assertion =
          (cfg.settings.tor.state_dir or null) == null
          || lib.hasPrefix "${stateDir}/" (toString cfg.settings.tor.state_dir);
        message = ''
          services.electrum-observer.settings.tor.state_dir must be under
          ${stateDir}, or null to put arti's state next to the database.
        '';
      }
    ];

    # So that `electrum-observer --config <generated file> servers` and an
    # import can be run by hand; the unit names the generated file. Both read
    # the database, which is owned by the dynamic user, so both want root.
    environment.systemPackages = [ cfg.package ];

    systemd.services.electrum-observer = {
      description = "Electrum server observer";
      wantedBy = [ "multi-user.target" ];
      # Both the imports and the first dials want a resolver and a route, and
      # arti's bootstrap is bounded by `tor.bootstrap_timeout_secs`.
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # A changed configuration is a changed set of servers, cadences and
      # caps; none of it is re-read while running.
      restartTriggers = [ configFile ];

      serviceConfig = hardening // {
        Type = "simple";
        StateDirectory = stateDirectory;
        StateDirectoryMode = "0750";
        ExecStartPre = importCommands;
        ExecStart = observer [ "run" ];
        # The daemon stops on SIGTERM by flipping the flag the sessions and
        # the writer watch, so systemd's default kill signal is the right one
        # and a restart is only for a failure.
        Restart = "on-failure";
        RestartSec = 10;
        LimitNOFILE = cfg.maxOpenFiles;
        # tracing writes to stderr, which systemd puts in the journal; there
        # is no log file to rotate.
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };
  };
}
