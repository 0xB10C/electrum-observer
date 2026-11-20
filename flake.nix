{
  description = "electrum-observer: watches public Electrum servers and records what they answer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      # The module is a NixOS module, so only Linux has one to check.
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      forLinuxSystems = nixpkgs.lib.genAttrs linuxSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          electrum-observer = pkgs.callPackage ./nix/package.nix {
            # The commit this was built from. `self.rev` is only there for a
            # clean tree, `dirtyRev` for a tree with uncommitted changes, and
            # neither for a build of a plain directory. Nothing in the binary
            # reads it yet; the package says why it is passed anyway.
            gitCommit = self.rev or self.dirtyRev or "unknown";
          };
          default = electrum-observer;
        }
      );

      # services.electrum-observer: one long-running collector.
      nixosModules = rec {
        electrum-observer = import ./nix/module.nix self;
        default = electrum-observer;
      };

      checks = forLinuxSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          # A small configuration that uses the module: `enable`, and both
          # seed sources so that the optional and the mandatory
          # `ExecStartPre` are both generated. Everything else is at its
          # default. Only the unit it generates is asked for, so no
          # system is built and no VM is started -- crawler has no VM test
          # (spytrap does, and it is a two-machine regtest run), and a VM for
          # "the service starts" would cost minutes of every `nix flake
          # check` to tell us what this eval tells us for free. The real
          # end-to-end coverage is the integration tests, which the package's
          # check phase runs.
          host = nixpkgs.lib.nixosSystem {
            modules = [
              self.nixosModules.default
              {
                nixpkgs.hostPlatform = system;
                system.stateVersion = "26.05";
                services.electrum-observer = {
                  enable = true;
                  seeds.importOnStart = [
                    "sparrow"
                    "1209k"
                  ];
                  seeds.serverFiles = [ (pkgs.writeText "servers.txt" "ssl://example.com:50002\n") ];
                };
              }
            ];
          };
          # The generated unit as text, with its string context dropped: the
          # text names the store path of the package and of the generated
          # configuration file, and keeping the context would make this check
          # build electrum-observer rather than evaluate the module.
          unit = name: builtins.unsafeDiscardStringContext host.config.systemd.units.${name}.text;
        in
        {
          package = self.packages.${system}.electrum-observer;

          module =
            assert host.config.systemd.services."electrum-observer".enable;
            # The database defaults into the state directory, and
            # `tor.state_dir` is left for the daemon to put beside it. Both
            # are in the generated YAML rather than in the unit, so they are
            # checked here rather than by a grep below.
            assert
              host.config.services.electrum-observer.settings.database
              == "/var/lib/electrum-observer/observer.sqlite";
            assert (host.config.services.electrum-observer.settings.tor.state_dir or null) == null;
            pkgs.runCommand "electrum-observer-module-evaluates"
              {
                service = unit "electrum-observer.service";
              }
              ''
                printf '%s' "$service" > service
                grep -qx 'DynamicUser=true' service
                grep -qx 'StateDirectory=electrum-observer' service
                grep -qx 'ProtectSystem=strict' service
                grep -qx 'Restart=on-failure' service
                grep -qx 'LimitNOFILE=65536' service
                grep -qx 'Wants=network-online.target' service
                grep -q 'ExecStart=.*/bin/electrum-observer --config /nix/store/.*electrum-observer.yaml run' service
                # A seed import per source, and the fetching one may fail
                # without holding up the start.
                grep -q 'ExecStartPre=.*/bin/electrum-observer --config .* import sparrow' service
                grep -q 'ExecStartPre=-.*/bin/electrum-observer --config .* import 1209k' service
                grep -q 'ExecStartPre=.*/bin/electrum-observer --config .* import file /nix/store/.*servers.txt' service
                touch $out
              '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              pkgs.rustc
              pkgs.cargo
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              # Coverage and mutation testing are run per commit, so they
              # belong in the shell rather than in CI alone.
              pkgs.cargo-tarpaulin
              pkgs.cargo-mutants
            ];
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
