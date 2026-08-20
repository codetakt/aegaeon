{
  description = "Aegaeon — formally verified OAuth 2.0/2.1 identity provider with OpenID Connect Federation";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    verification-nixpkgs = {
      url = "github:nixos/nixpkgs/c6245e83d836d0433170a16eb185cefe0572f8b8";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";
    fenix.url = "github:nix-community/fenix";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    steel = {
      url = "github:fstarlang/steel";
      flake = false;
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      verification-nixpkgs,
      flake-utils,
      crane,
      rust-overlay,
      fenix,
      git-hooks,
      steel,
      ...
    }:
    # nixpkgs 26.11 no longer supports x86_64-darwin.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        overlays = [
          (import rust-overlay)
          (final: prev: {
            cargo-audit = final.rustPlatform.buildRustPackage rec {
              pname = "cargo-audit";
              version = "0.22.0";
              src = final.fetchCrate {
                inherit pname version;
                hash = "sha256-Ha2yVyu9331NaqiW91NEwCTIeW+3XPiqZzmatN5KOws=";
              };
              cargoHash = "sha256-f8nrW1l7UA8sixwqXBD1jCJi9qyKC5tNl/dWwCt41Lk=";
              nativeBuildInputs = [ final.pkg-config ];
              buildInputs = [ final.openssl ];
              doCheck = false;
            };
            cargo-vet = final.rustPlatform.buildRustPackage rec {
              pname = "cargo-vet";
              version = "0.10.2-git-e496a28";
              src = final.fetchFromGitHub {
                owner = "mozilla";
                repo = "cargo-vet";
                rev = "e496a28a2cde71db0d98ef631cf4586f89a7fed6";
                hash = "sha256-mwSe69Zy9dAcLNxrHiS3MRGjr9/3GnNJ74a6WM2a0NY=";
              };
              cargoHash = "sha256-3pfOq2VfHbtohdgv73TT480bjCjdNKPJE+m4SHeXfGA=";
              doCheck = false;
            };
          })
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = {
            allowUnfree = true;
            allowBroken = true; # for tamarin-prover
          };
        };
        inherit (pkgs) lib;
        inherit (pkgs.stdenv.hostPlatform) isLinux;

        rustToolchainConfig = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
        rustChannel = rustToolchainConfig.toolchain.channel;
        rustNightlyDate =
          if lib.hasPrefix "nightly-" rustChannel then
            lib.removePrefix "nightly-" rustChannel
          else
            throw "rust-toolchain.toml must pin a nightly toolchain (nightly-YYYY-MM-DD); got ${rustChannel}";
        rustExtensions = lib.unique (
          (rustToolchainConfig.toolchain.components or [ ]) ++ [ "llvm-tools-preview" ]
        );

        # Use LLVM stdenv explicitly
        llvmPackages = pkgs.llvmPackages_20;
        clangStdenv = pkgs.overrideCC pkgs.stdenv llvmPackages.clang;
        stdenv =
          if pkgs.stdenv.hostPlatform.isDarwin then
            clangStdenv
          else
            pkgs.stdenvAdapters.useMoldLinker clangStdenv;

        rustToolchain = pkgs.rust-bin.nightly.${rustNightlyDate}.default.override {
          extensions = rustExtensions;
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        fenixAsanToolchain = import ./nix/fenix-asan-toolchain {
          inherit system;
          inherit (inputs) fenix;
          patches = [ ./nix/fenix-asan-toolchain/asan-no-static.patch ];
        };

        asanRustToolchain = pkgs.symlinkJoin {
          name = "rust-nightly-asan";
          paths = [ fenixAsanToolchain ];
        };

        sharedCompilerRt = pkgs.callPackage ./nix/compiler-rt-shared.nix {
          inherit llvmPackages;
        };

        asanRuntimeLibDir = "${sharedCompilerRt}/lib/linux";

        haclStar = pkgs.callPackage ./nix/hacl.nix { };
        evercrypt = pkgs.callPackage ./nix/evercrypt { };
        evercryptLib = evercrypt.source;
        evercryptDist = evercrypt.dist;

        wasiTarget = pkgs.pkgsCross.wasi32.stdenv.hostPlatform.config;
        wasiClang = pkgs.pkgsCross.wasi32.buildPackages.clang;
        wasiClangBin = "${wasiClang}/bin/${wasiTarget}-clang";
        wasiLibc = pkgs.pkgsCross.wasi32.libc;
        wasiLibcDev = pkgs.pkgsCross.wasi32.libc.dev;
        wasiSysroot = pkgs.runCommand "wasi-sysroot" { } ''
          mkdir -p "$out"
          ln -s ${wasiLibcDev}/include "$out/include"
          ln -s ${wasiLibc}/lib "$out/lib"
        '';

        verificationPkgs = import verification-nixpkgs { inherit system; };
        verificationOcamlPackages = verificationPkgs.ocaml-ng.ocamlPackages_5_3;
        verificationFstar = verificationPkgs.fstar;
        verificationZ3 = verificationPkgs.z3;

        karamel = verificationPkgs.callPackage ./nix/karamel.nix {
          fstar = verificationFstar;
          ocamlPackages = verificationOcamlPackages;
        };
        everparse = verificationPkgs.callPackage ./nix/everparse.nix {
          inherit karamel;
          z3 = verificationZ3;
          fstar = verificationFstar;
          ocamlPackages = verificationOcamlPackages;
        };

        verifiedCoreWasm = pkgs.callPackage ./nix/verified-core-wasm.nix {
          inherit karamel everparse haclStar;
          fstar = verificationFstar;
          inherit wasiClang;
          inherit wasiClangBin;
          inherit wasiTarget;
          inherit wasiSysroot;
          evercrypt = evercryptLib;
          inherit (pkgs) openssl;
          inherit (pkgs) coreutils;
        };

        dudectCheck = pkgs.callPackage ./nix/dudect.nix { inherit evercryptDist karamel; };

        tamarin-prover' = pkgs.tamarin-prover.overrideAttrs (oldAttrs: {
          postPatch = (oldAttrs.postPatch or "") + ''
            substituteInPlace src/Main/Console.hs \
              --replace 'supportedVersions = ["2.7.1", "3.0", "3.1", "3.2.1", "3.2.2", "3.3", "3.3.1", "3.4", "3.5"]' \
              'supportedVersions = ["2.7.1", "3.0", "3.1", "3.2.1", "3.2.2", "3.3", "3.3.1", "3.4", "3.5", "3.5.1"]'
          '';
        });

        kani' = if isLinux then pkgs.callPackage ./nix/kani { } else null;

        generatedOrLegacyFormatExcludes = [
          "^artifacts/"
          "^generated/"
          "^fstar/"
          "^proofs/tamarin/"
          "^spec/.*\\.json$"
          "^tests/(fixtures|vectors|verified_core_wasm)/"
          "^tests/constant_time/"
          "^tests/docker/prometheus\\.yml$"
          "^scripts/(extraction|sanitizers|verify)/"
          "^scripts/sdk/tools-src/"
          "^scripts/release/generate_sbom\\.sh$"
          "^\\.github/workflows/"
          "^infra/tofu/"
          "^examples/minimal-rp/"
          "^c/dcr_error\\.c$"
          "^c/dudect\\.h$"
          "^LICENSE$"
          "^nix/kani/"
        ];

        preCommitPython = pkgs.python3.withPackages (
          ps: with ps; [
            mypy
            pyjwt
          ]
        );

        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            commitlint = {
              enable = true;
              name = "commitlint";
              entry = "${pkgs.commitlint}/bin/commitlint --edit";
              language = "system";
              package = pkgs.commitlint;
              stages = [ "commit-msg" ];
              always_run = true;
            };
            commitlint-pre-push = {
              enable = true;
              name = "commitlint-pre-push";
              entry = "./scripts/commitlint-pre-push.sh";
              language = "system";
              package = pkgs.commitlint;
              stages = [ "pre-push" ];
              pass_filenames = false;
              always_run = true;
            };
            editorconfig-checker = {
              enable = false;
            };
            end-of-file-fixer = {
              enable = true;
              excludes = generatedOrLegacyFormatExcludes;
            };
            trim-trailing-whitespace = {
              enable = true;
              excludes = generatedOrLegacyFormatExcludes;
            };
            mixed-line-endings.enable = true;
            check-added-large-files = {
              enable = true;
              args = [ "--maxkb=200" ];
              excludes = [
                "^artifacts/conformance/.*/plan-export/export\\.zip$"
                "^artifacts/kani/run_[0-9T]+\\.log$"
                "^generated/openapi/aegaeon-management-api\\.v1\\.json$"
                "^spec/compliance-matrix\\.yaml$"
              ];
            };
            check-case-conflicts.enable = true;
            check-executables-have-shebangs.enable = true;
            check-shebang-scripts-are-executable = {
              enable = true;
              excludes = [ "\\.rs$" ];
            };
            check-symlinks = {
              enable = true;
              excludes = [ "^crates/kani-harness/kani$" ];
            };
            check-vcs-permalinks.enable = true;
            forbid-new-submodules.enable = true;
            check-merge-conflicts.enable = true;
            check-json.enable = true;
            check-toml.enable = true;
            check-yaml.enable = true;
            markdownlint = {
              enable = true;
              package = pkgs.markdownlint-cli2;
              entry = "${pkgs.markdownlint-cli2}/bin/markdownlint-cli2";
            };
            docs-structure = {
              enable = true;
              name = "docs-structure";
              entry = "${preCommitPython}/bin/python scripts/validation/check_docs_structure.py";
              language = "system";
              pass_filenames = false;
              files = "^(docs/.*\\.md|README\\.md|CHANGELOG\\.md|CONTRIBUTING\\.md|AGENTS\\.md|scripts/validation/check_docs_structure\\.py)$";
            };
            typos = {
              enable = true;
              settings.configPath = ".typos.toml";
            };
            # Nix formatting
            nixfmt-rfc-style = {
              enable = true;
              package = pkgs.nixfmt;
            };
            # Nix static analysis
            statix.enable = true;
            # Nix dead code detection
            deadnix = {
              enable = true;
              settings = {
                noLambdaArg = true;
                noLambdaPatternNames = true;
                noUnderscore = true;
              };
            };
            # GitHub Actions linting
            actionlint.enable = true;
            # Shell script analysis
            shellcheck = {
              enable = true;
              name = "shellcheck";
              entry = "${pkgs.shellcheck}/bin/shellcheck --severity=error";
              types = [ "shell" ];
              language = "system";
              pass_filenames = true;
            };
            # Shell script formatting
            shfmt = {
              enable = true;
              excludes = [ "\\.sh\\.tftpl$" ];
            };
            cargo-fmt-check = {
              enable = true;
              name = "cargo-fmt-check";
              entry = "${pkgs.writeShellScript "cargo-fmt-check" ''
                set -euo pipefail
                export PATH=${rustToolchain}/bin:$PATH
                exec ${rustToolchain}/bin/cargo fmt --all -- --check
              ''}";
              language = "system";
              types = [ "rust" ];
              pass_filenames = false;
            };
            # Python linting (check-only, no auto-fix)
            ruff-check = {
              enable = true;
              name = "ruff-check";
              entry = "${pkgs.ruff}/bin/ruff check --no-fix";
              types = [ "python" ];
              language = "system";
              pass_filenames = true;
            };
            ruff-format-check = {
              enable = true;
              name = "ruff-format-check";
              entry = "${pkgs.ruff}/bin/ruff format --check";
              types = [ "python" ];
              language = "system";
              pass_filenames = true;
            };
            mypy-check = {
              enable = true;
              name = "mypy-check";
              entry = "${preCommitPython}/bin/mypy";
              types = [ "python" ];
              language = "system";
              pass_filenames = true;
              require_serial = true;
              files = "^(scripts/validation/.*\\.py|ci/validate_slos\\.py)$";
            };
            ts-lint = {
              enable = true;
              name = "ts-lint";
              entry = "${pkgs.writeShellScript "ts-lint" ''
                set -euo pipefail

                if [ ! -d node_modules ]; then
                  echo "Skipping ts-lint: run 'npm ci' first."
                  exit 0
                fi

                npm run lint:ts
              ''}";
              language = "system";
              pass_filenames = false;
              files =
                "^(package(-lock)?\\.json|eslint\\.config\\.js|tsconfig\\.json|"
                + "scripts/check-strict-types\\.ts|scripts/check-workflow-inventory\\.ts|"
                + "scripts/sdk/check_sdk_strict_types\\.ts|scripts/sdk/tools-src/check-strict-types\\.ts|"
                + "tests/verified_core_wasm/(root_strict_types_policy_test|strict_types_policy_test|workflow_inventory_policy_test)\\.ts)$";
            };
            ts-typecheck = {
              enable = true;
              name = "ts-typecheck";
              entry = "${pkgs.writeShellScript "ts-typecheck" ''
                set -euo pipefail

                if [ ! -d node_modules ]; then
                  echo "Skipping ts-typecheck: run 'npm ci' first."
                  exit 0
                fi

                npm run typecheck:ts
                npm run audit:strict-types
              ''}";
              language = "system";
              pass_filenames = false;
              files =
                "^(package(-lock)?\\.json|tsconfig\\.json|spec/server-strict-types\\.current\\.json|"
                + "scripts/check-strict-types\\.ts|scripts/check-workflow-inventory\\.ts|"
                + "scripts/sdk/check_sdk_strict_types\\.ts|scripts/sdk/tools-src/check-strict-types\\.ts|"
                + "tests/verified_core_wasm/(root_strict_types_policy_test|strict_types_policy_test|workflow_inventory_policy_test)\\.ts)$";
            };
          };
        };

        guardedPreCommitShellHook =
          {
            repoNames,
            marker,
          }:
          hook: ''
            __aeg_repo_top="$(
              git rev-parse --show-toplevel 2>/dev/null || printf '%s' "$PWD"
            )"
            __aeg_repo_name="$(basename "$__aeg_repo_top")"
            case " ${lib.concatStringsSep " " repoNames} " in
              *" $__aeg_repo_name "*)
                if [ -f "$__aeg_repo_top/${marker}" ]; then
                  (
                    cd "$__aeg_repo_top"
                    ${hook}
                  )
                else
                  echo \
                    "Skipping pre-commit hook installation for ${lib.concatStringsSep ", " repoNames}: marker '${marker}' is missing under '$__aeg_repo_top'."
                fi
                ;;
              *)
                echo \
                  "Skipping pre-commit hook installation for ${lib.concatStringsSep ", " repoNames}: current git top-level '$__aeg_repo_top' is outside the target repositories."
                ;;
            esac
            unset __aeg_repo_top __aeg_repo_name
          '';

        verificationTools = [
          verificationZ3
          verificationFstar
          karamel
          everparse
        ]
        ++ (with pkgs; [
          tamarin-prover'
          maude
          evercryptLib
          evercryptDist
          ripgrep
        ]);

        python' = pkgs.python3.withPackages (
          ps: with ps; [
            requests
            pyjwt
            jwcrypto
            pyyaml
            jsonschema
            pytest
            pytest-html
            pytest-json-report
          ]
        );

        devToolsCommon =
          with pkgs;
          [
            cargo-fuzz
            cargo-vet
            cargo-nextest
            cargo-llvm-cov
            cargo-edit
            cargo-watch
            cargo-cyclonedx
            cargo-deny
            cargo-audit
            nixfmt
            statix
            deadnix
            actionlint
            shellcheck
            grype
            trivy
            cargo-geiger
            cargo-udeps
            commitlint
            markdownlint-cli2
            ruff
            mypy
            python'
          ]
          ++ (with pkgs; [
            nodejs_24
            pnpm
            pkg-config
            openssl
            libsodium
            mbedtls
            zlib
            gnumake
            cmake
            llvmPackages.clang
            llvmPackages.bintools
            git
            gnused
            gnugrep
            gawk
            coreutils
            findutils
            diffutils
            bash
            procps
            ripgrep
            fd
            bat
            eza
            jq
            yq-go
            awscli2
            ssm-session-manager-plugin
            opentofu
            atlas
            tmux
            unzip
            which
            act
          ])
          ++ [ evercryptLib ];

        devTools = [ rustToolchain ] ++ devToolsCommon;
        asanDevTools = [ asanRustToolchain ] ++ devToolsCommon;

        commonShellHook = ''
          export PATH=${rustToolchain}/bin:$PATH
          export AEGAEON_DEV_SHELL=1
          export HACL_FSTAR_PATH=${haclStar}/share/hacl-star/fstar
          export STEEL_PATH=${steel}
          export EVERCRYPT_SRC_DIR=${evercryptLib}/share/evercrypt
          export WASI_CLANG=${wasiClangBin}
          export WASI_SYSROOT=${wasiSysroot}
          export AEG_HOST_CC=${llvmPackages.clang}/bin/clang
          export AEG_HOST_CXX=${llvmPackages.clang}/bin/clang++
          export AEG_HOST_BIN="$(dirname "$AEG_HOST_CC")"
          export AEG_HOST_AR=${pkgs.binutils}/bin/ar
          export AEG_HOST_LD=${llvmPackages.bintools}/bin/ld.lld
          export PATH="${karamel}/bin:${verificationFstar}/bin:${everparse}/bin:${verificationZ3}/bin:${llvmPackages.bintools}/bin:$AEG_HOST_BIN:$PATH"
          if [[ "${"CC:-"}" == *"wasm32-unknown-wasi"* ]]; then
            unset CC
          fi
          if [[ "${"CXX:-"}" == *"wasm32-unknown-wasi"* ]]; then
            unset CXX
          fi
          if [[ "${"AR:-"}" == *"wasm32-unknown-wasi"* ]]; then
            unset AR
          fi
          if [[ "${"LD:-"}" == *"wasm32-unknown-wasi"* ]]; then
            unset LD
          fi
          export CC="$AEG_HOST_CC"
          export CXX="$AEG_HOST_CXX"
          export AR="$AEG_HOST_AR"
          export LD="$AEG_HOST_LD"
          export CC_x86_64_unknown_linux_gnu="$AEG_HOST_CC"
          export CXX_x86_64_unknown_linux_gnu="$AEG_HOST_CXX"
          export AR_x86_64_unknown_linux_gnu="$AEG_HOST_AR"
          export LD_x86_64_unknown_linux_gnu="$AEG_HOST_LD"
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$AEG_HOST_CC"
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AEG_HOST_AR"
          actual_cargo="$(type -P cargo || true)"
          actual_rustc="$(type -P rustc || true)"
          if [[ "$actual_cargo" != "${rustToolchain}/bin/cargo" ]]; then
            echo "Aegaeon dev shell error: cargo resolves to '$actual_cargo' instead of '${rustToolchain}/bin/cargo'." >&2
            exit 1
          fi
          if [[ "$actual_rustc" != "${rustToolchain}/bin/rustc" ]]; then
            echo "Aegaeon dev shell error: rustc resolves to '$actual_rustc' instead of '${rustToolchain}/bin/rustc'." >&2
            exit 1
          fi
          if [[ "''${NIX_CC:-}" == *"wasm32-unknown-wasi"* ]]; then
            echo "Aegaeon dev shell error: NIX_CC leaked a WASI wrapper into the native shell: '$NIX_CC'." >&2
            exit 1
          fi
          if [[ "''${NIX_BINTOOLS:-}" == *"wasm32-unknown-wasi"* ]]; then
            echo "Aegaeon dev shell error: NIX_BINTOOLS leaked WASI binutils into the native shell: '$NIX_BINTOOLS'." >&2
            exit 1
          fi
        '';

        kaniShellHook = lib.optionalString isLinux ''
          export PATH=${kani'}/bin:${kani'}/toolchain/bin:$PATH
        '';

        mkApp =
          drv: description: (flake-utils.lib.mkApp { inherit drv; }) // { meta = { inherit description; }; };

        mkShellApp =
          {
            name,
            description,
            runtimeInputs ? devTools,
            text ? null,
            script ? null,
          }:
          let
            scriptText =
              if script != null then
                ''
                  set -euo pipefail
                  exec ${pkgs.bash}/bin/bash ${script} "$@"
                ''
              else
                text;
          in
          assert lib.assertMsg (scriptText != null) "mkShellApp requires text or script";
          mkApp (pkgs.writeShellApplication {
            inherit name;
            text = scriptText;
            runtimeInputs = lib.unique runtimeInputs;
          }) description;

        dockerClient = pkgs.docker-client;
        dockerCompose = pkgs.docker-compose;
        dockerRuntimeInputs = devTools ++ [
          dockerClient
          dockerCompose
        ];
        verificationRuntimeInputs = devTools ++ verificationTools;

        mkAppSpec =
          {
            binName,
            description,
            script,
            runtimeInputs ? devTools,
          }:
          {
            inherit
              binName
              description
              script
              runtimeInputs
              ;
          };

        mkAppFromSpec =
          _appId: spec:
          mkShellApp {
            name = spec.binName;
            inherit (spec) description runtimeInputs script;
          };

        appSpecs = import ./nix/flake/app-specs.nix {
          inherit
            lib
            pkgs
            mkAppSpec
            devTools
            asanDevTools
            sharedCompilerRt
            verificationTools
            verificationRuntimeInputs
            dockerRuntimeInputs
            rustToolchain
            kani'
            verificationFstar
            karamel
            everparse
            python'
            ;
          inherit verificationZ3;
        };

        src = lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            let
              rel = lib.removePrefix "${toString ./.}/" (toString path);
              isTargetPath = rel == "target" || lib.hasPrefix "target/" rel || lib.hasInfix "/target/" rel;
              keepPrefixes = [
                "ci"
                ".github"
                ".cargo"
                "Cargo"
                "crates"
                "db"
                "docs"
                "fstar"
                "generated"
                "proofs"
                "c"
                "include"
                "scripts"
                "spec"
                "xtask"
                "nix"
                "artifacts/ct"
                "artifacts/karamel"
              ];
              keepFiles = [
                "Cargo.toml"
                "Cargo.lock"
                "deny.toml"
                "kani.toml"
                "rust-toolchain.toml"
              ];
            in
            (!isTargetPath)
            && (
              lib.cleanSourceFilter path type
              || builtins.any (p: rel == p || lib.hasPrefix "${p}/" rel) keepPrefixes
              || builtins.elem rel keepFiles
            );
        };

        cargoArtifacts = craneLib.buildDepsOnly {
          pname = "aegaeon-cargo-artifacts";
          version = "0.0.0";
          inherit src;
          stdenv = p: stdenv;
          cargoToml = ./Cargo.toml;
          cargoLock = ./Cargo.lock;
          cargoHash = "sha256-hWQWYH4GbZD5aT+Dr592uzsYP8NdLuggu9EzToA9I3w=";
          nativeBuildInputs = [
            llvmPackages.clang
            llvmPackages.bintools
            pkgs.pkg-config
            karamel
          ];
          buildInputs = [
            pkgs.mbedtls
            pkgs.libsodium
            evercryptDist
          ];
        };

        mkVerification =
          name: scriptPath: extraInputs:
          pkgs.runCommand name
            {
              nativeBuildInputs = lib.unique (
                verificationTools
                ++ extraInputs
                ++ (with pkgs; [
                  bash
                  findutils
                  gnugrep
                  gawk
                  coreutils
                  gnused
                  llvmPackages.clang
                ])
                ++ [
                  python'
                ]
              );
            }
            ''
              export HOME="$TMPDIR"
              export HACL_FSTAR_PATH=${haclStar}/share/hacl-star/fstar
              export STEEL_PATH=${steel}
              export EVERCRYPT_DIST=${evercryptDist}
              cp -r ${src} source
              chmod -R u+w source
              cd source
              mkdir -p "$out"
              OUT_DIR="$out" ${pkgs.bash}/bin/bash ${scriptPath}
              touch "$out/success"
            '';

        # Lightweight variant without heavy verification tools (fstar, tamarin,
        # z3, etc.).  Suitable for Python-only validation scripts.
        mkLightVerification =
          name: scriptPath: extraInputs:
          pkgs.runCommand name
            {
              nativeBuildInputs = lib.unique (
                extraInputs
                ++ (with pkgs; [
                  bash
                  findutils
                  gnugrep
                  gawk
                  coreutils
                  gnused
                  perl
                ])
                ++ [
                  python'
                ]
              );
            }
            ''
              export HOME="$TMPDIR"
              cp -r ${src} source
              chmod -R u+w source
              cd source
              mkdir -p "$out"
              OUT_DIR="$out" ${pkgs.bash}/bin/bash ${scriptPath}
              touch "$out/success"
            '';

        verifyFstar =
          pkgs.runCommand "verify-fstar"
            {
              nativeBuildInputs = [
                verificationFstar
                verificationZ3
                pkgs.bash
                pkgs.coreutils
                pkgs.findutils
                pkgs.gnugrep
                pkgs.gnused
                pkgs.python3
                haclStar
                karamel
              ];
            }
            ''
              export HOME="$TMPDIR"
              cp -r ${src} source
              chmod -R u+w source
              cd source
              export HACL_FSTAR_PATH="${haclStar}/share/hacl-star/fstar"
              export KRMLLIB_PATH="${karamel}/lib/krml"
              export STEEL_PATH="${steel}"
              export EVERPARSE_FSTAR_PATH="${everparse}/share/everparse"
              export EVERPARSE_PRELUDE_PATH="${everparse}/share/everparse/prelude"
              export EVERPARSE_LOWPARSER_PATH="${everparse}/lib/lowparse"
              OUT_DIR="$out" ${pkgs.bash}/bin/bash ${./scripts/flake/verify_fstar.sh}
            '';

        verifyTamarin = mkVerification "verify-tamarin" ./scripts/flake/verify_tamarin.sh [ ];

        verifyDudect = mkVerification "verify-dudect" ./scripts/flake/verify_dudect.sh [ ];

        verifyJose = craneLib.mkCargoDerivation {
          pname = "verify-jose";
          version = "0.0.0";
          inherit src cargoArtifacts;
          stdenv = p: stdenv;
          cargoToml = ./Cargo.toml;
          cargoLock = ./Cargo.lock;
          nativeBuildInputs = verificationRuntimeInputs;
          buildPhaseCargoCommand = ''
            export HOME="$TMPDIR"
            export HACL_FSTAR_PATH=${haclStar}/share/hacl-star/fstar
            export STEEL_PATH=${steel}
            export EVERCRYPT_DIST=${evercryptDist}
            mkdir -p "$out"
            export OUT_DIR="$out"
            ${pkgs.bash}/bin/bash ${./scripts/flake/verify_jose_check.sh}
          '';
          checkPhaseCargoCommand = "";
          installPhaseCommand = ''
            mkdir -p $out
            touch $out/success
          '';
          doInstallCargoArtifacts = false;
        };

        verifyFstarAbstract =
          mkVerification "verify-fstar-abstract" ./scripts/flake/verify_fstar_abstract.sh
            [ ];

        verifyKani =
          if isLinux then
            craneLib.mkCargoDerivation {
              pname = "verify-kani";
              version = "0.0.0";
              inherit src cargoArtifacts;
              stdenv = p: stdenv;
              cargoToml = ./Cargo.toml;
              cargoLock = ./Cargo.lock;
              nativeBuildInputs = [
                kani'
                rustToolchain
                pkgs.python3
                verificationFstar
                verificationZ3
                karamel
                everparse
                llvmPackages.clang
                llvmPackages.bintools
              ];
              buildPhaseCargoCommand = ''
                ${pkgs.bash}/bin/bash ${./scripts/flake/verify_kani_check.sh}
              '';
              checkPhaseCargoCommand = "";
              installPhaseCommand = ''
                mkdir -p $out
                touch $out/success
              '';
              doInstallCargoArtifacts = false;
            }
          else
            null;

        aegaeon-workspace = craneLib.buildPackage {
          inherit src cargoArtifacts;
          stdenv = p: stdenv;
          pname = "aegaeon-workspace";
          version = "0.0.0";
          cargoToml = ./Cargo.toml;
          cargoLock = ./Cargo.lock;
          cargoExtraArgs = "--workspace --locked";
          meta = {
            mainProgram = "aegaeon-server";
          };
          nativeBuildInputs = [
            llvmPackages.clang
            llvmPackages.bintools
            pkgs.pkg-config
            karamel
          ];
          buildInputs = [
            pkgs.mbedtls
            pkgs.libsodium
            evercryptDist
          ];
          doCheck = false;
        };

        aegaeonDockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "aegaeon";
          tag = "latest";
          contents = [
            aegaeon-workspace
            pkgs.cacert
          ];
          config = {
            WorkingDir = "/opt/aegaeon";
            Entrypoint = [ "${aegaeon-workspace}/bin/aegaeon-server" ];
            Cmd = [
              "--host"
              "0.0.0.0"
              "--port"
              "8080"
            ];
            ExposedPorts = {
              "8080/tcp" = { };
            };
            User = "1000:1000";
          };
          fakeRootCommands = ''
            mkdir -p etc opt/aegaeon tmp var/tmp
            chmod 1777 tmp var/tmp
            cp ${./LICENSE} LICENSE
            echo 'aegaeon:x:1000:1000:Aegaeon:/opt/aegaeon:/sbin/nologin' > etc/passwd
            echo 'aegaeon:x:1000:' > etc/group
            chown -R 1000:1000 opt/aegaeon
          '';
        };

        flakePackages = import ./nix/flake/packages.nix {
          inherit
            mkLightVerification
            lib
            isLinux
            craneLib
            src
            cargoArtifacts
            stdenv
            verifiedCoreWasm
            verifyFstar
            verifyTamarin
            verifyKani
            verifyDudect
            dudectCheck
            verifyJose
            verifyFstarAbstract
            rustToolchain
            asanRustToolchain
            sharedCompilerRt
            everparse
            evercryptLib
            evercryptDist
            kani'
            ;
          aegaeonWorkspace = aegaeon-workspace;
          inherit aegaeonDockerImage;
        };

        flakeChecks = import ./nix/flake/checks.nix {
          inherit
            pkgs
            isLinux
            craneLib
            src
            cargoArtifacts
            pre-commit-check
            mkVerification
            mkLightVerification
            verifyFstar
            verifyTamarin
            verifyKani
            verifyDudect
            verifyJose
            ;
          inherit stdenv;
        };

        flakeDevShells = import ./nix/flake/dev-shells.nix {
          inherit
            pkgs
            lib
            cargoArtifacts
            devTools
            asanDevTools
            verificationTools
            pre-commit-check
            commonShellHook
            kaniShellHook
            guardedPreCommitShellHook
            sharedCompilerRt
            llvmPackages
            rustToolchain
            haclStar
            karamel
            everparse
            verificationFstar
            verificationZ3
            asanRuntimeLibDir
            ;
        };

      in
      {
        packages = flakePackages;

        apps = lib.mapAttrs mkAppFromSpec (
          lib.removeAttrs appSpecs (lib.optional (!isLinux) "verify-kani")
        );

        checks = flakeChecks;

        devShells = flakeDevShells;
      }
    );
}
