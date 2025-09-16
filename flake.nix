{
  description = "Rust bindings for libxcrypt";

  inputs = {

    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    systems.url = "github:nix-systems/default";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    pre-commit-hooks-nix = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-compat.follows = "flake-compat";
      };
    };

  };

  outputs =
    inputs@{
      self,
      flake-parts,
      systems,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import systems;

      imports = [ inputs.pre-commit-hooks-nix.flakeModule ];

      perSystem =
        {
          config,
          system,
          pkgs,
          lib,
          ...
        }:
        {
          packages = {
            libxcrypt-rs = pkgs.callPackage ./build.nix { };
            default = config.packages.libxcrypt-rs;
            cross = pkgs.pkgsCross.aarch64-multiplatform.callPackage ./build.nix { };
            static = pkgs.pkgsStatic.callPackage ./build.nix { };
          };

          checks = {
            clippy = config.packages.libxcrypt-rs.overrideAttrs (
              _: previousAttrs: {
                pname = previousAttrs.pname + "-clippy";
                nativeCheckInputs = (previousAttrs.nativeCheckInputs or [ ]) ++ [ pkgs.clippy ];
                checkPhase = "cargo clippy";
              }
            );
            rustfmt = config.packages.libxcrypt-rs.overrideAttrs (
              _: previousAttrs: {
                pname = previousAttrs.pname + "-rustfmt";
                nativeCheckInputs = (previousAttrs.nativeCheckInputs or [ ]) ++ [ pkgs.rustfmt ];
                checkPhase = "cargo fmt --check";
              }
            );
          };

          pre-commit = {
            check.enable = true;

            settings = {
              hooks = {
                nixfmt-rfc-style.enable = true;
                statix.enable = true;
              };
            };
          };

          devShells.default = pkgs.mkShell {
            shellHook = ''
              ${config.pre-commit.installationScript}
            '';

            packages = [
              pkgs.niv
              pkgs.nixfmt-rfc-style
              pkgs.clippy
              pkgs.rustfmt
              pkgs.cargo
              pkgs.cargo-machete
              pkgs.cargo-edit
              pkgs.cargo-bloat
              pkgs.cargo-deny
              pkgs.cargo-cyclonedx
              pkgs.cargo-valgrind
              pkgs.rust-bindgen
            ];

            inputsFrom = [ config.packages.libxcrypt-rs ];

            env = {
              # rust-analyzer
              RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            };

          };

        };
    };
}
