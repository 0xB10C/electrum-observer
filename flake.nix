{
  description = "electrum-observer: watches public Electrum servers and records what they answer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # Only a dev shell for now. The package and the NixOS module need a
      # Cargo.lock to build from and a binary worth running as a service;
      # both arrive in step 15 of PLAN.md.
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
