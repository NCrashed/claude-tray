{
  description = "Fail-closed dedicated WireGuard tunnels for Claude Code";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "clippy" "llvm-tools-preview" "rust-src" "rustfmt" ];
        };
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
      in {
        packages.default = rustPlatform.buildRustPackage {
          pname = "claude-tunnel";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.makeWrapper pkgs.pkg-config ];
          buildInputs = [ pkgs.dbus ];
          postInstall = ''
            wrapProgram $out/bin/claude-tunnel \
              --prefix PATH : ${pkgs.lib.makeBinPath [
                pkgs.amneziawg-tools
                pkgs.chromium
                pkgs.iproute2
                pkgs.iptables
                pkgs.procps
                pkgs.sudo
                pkgs.util-linux
                pkgs.wireguard-tools
              ]}
          '';
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.pkg-config rustToolchain ];
          buildInputs = [ pkgs.dbus ];
        };
      });
}
