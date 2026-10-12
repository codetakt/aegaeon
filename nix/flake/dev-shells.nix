{
  pkgs,
  lib,
  cargoArtifacts,
  devTools,
  asanDevTools,
  verificationTools,
  pre-commit-check,
  commonShellHook,
  kaniShellHook,
  guardedPreCommitShellHook,
  sharedCompilerRt,
  llvmPackages,
  rustToolchain,
  haclStar,
  karamel,
  everparse,
  verificationFstar,
  verificationZ3,
  asanRuntimeLibDir,
}:
let
  toolPathShellHook = ''
    export AEG_TOOL_PATH="${karamel}/bin:${verificationFstar}/bin:${everparse}/bin:${verificationZ3}/bin"
    export AEG_TOOL_PATH="$AEG_TOOL_PATH:${llvmPackages.bintools}/bin:${llvmPackages.clang}/bin"
    export AEG_TOOL_PATH="$AEG_TOOL_PATH:${rustToolchain}/bin"
    export PATH="$AEG_TOOL_PATH:$PATH"
  '';
in
{
  typescript = pkgs.mkShellNoCC {
    packages = [ pkgs.nodejs_24 ];
  };

  docs = pkgs.mkShellNoCC {
    packages = [
      # Expose the pinned compiler without its setup hook changing the compiler
      # environment used by unrelated CI helper fixtures.
      (pkgs.runCommand "ci-helper-native-tools" { } ''
        mkdir -p "$out/bin"
        ln -s ${pkgs.stdenv.cc}/bin/cc "$out/bin/cc"
        ln -s ${pkgs.stdenv.cc}/bin/gcc "$out/bin/gcc"
        ln -s ${llvmPackages.clang}/bin/clang "$out/bin/clang"
        ln -s ${pkgs.stdenv.cc}/bin/c++ "$out/bin/c++"
        ln -s ${pkgs.stdenv.cc.bintools}/bin/ar "$out/bin/ar"
      '')
      (pkgs.python3.withPackages (pythonPackages: [
        pythonPackages.pyyaml
        pythonPackages.jsonschema
        pythonPackages.pytest
      ]))
      pkgs.markdownlint-cli2
      pkgs.commitlint
      pkgs.gitMinimal
      pkgs.bash
      pkgs.jq
      pkgs.ripgrep
    ];
  };

  integrity = pkgs.mkShellNoCC {
    packages = [
      (pkgs.python3.withPackages (ps: [
        ps.pyyaml
        ps.jsonschema
        ps.pytest
        ps.pyjwt
      ]))
      pkgs.ruff
      pkgs.mypy
      pkgs.jq
      pkgs.ripgrep
    ];
  };

  ci = pkgs.mkShell {
    inputsFrom = [ cargoArtifacts ];
    CC = "${pkgs.stdenv.cc}/bin/cc";
    CXX = "${pkgs.stdenv.cc}/bin/c++";
    packages = lib.unique (
      devTools
      ++ pre-commit-check.enabledPackages
      ++ [
        pkgs.pre-commit
        llvmPackages.clang
        llvmPackages.bintools
        llvmPackages.libclang
      ]
    );
    shellHook =
      commonShellHook
      + kaniShellHook
      + guardedPreCommitShellHook {
        repoNames = [
          "aegaeon"
          "aegaeon-server-ci"
        ];
        marker = "Cargo.toml";
      } pre-commit-check.shellHook
      + toolPathShellHook
      + ''
        echo "Loaded Aegaeon CI environment"
      '';
  };

  default = pkgs.mkShell {
    inputsFrom = [ cargoArtifacts ];
    CC = "${pkgs.stdenv.cc}/bin/cc";
    CXX = "${pkgs.stdenv.cc}/bin/c++";
    packages = lib.unique (
      devTools
      ++ verificationTools
      ++ pre-commit-check.enabledPackages
      ++ [
        pkgs.pre-commit
        llvmPackages.clang
        llvmPackages.bintools
        llvmPackages.libclang
      ]
    );
    shellHook =
      commonShellHook
      + guardedPreCommitShellHook {
        repoNames = [
          "aegaeon"
          "aegaeon-server-ci"
        ];
        marker = "Cargo.toml";
      } pre-commit-check.shellHook
      + toolPathShellHook
      + ''
        echo \
          "Loaded Aegaeon dev environment (Rust nightly ${rustToolchain.version}," \
          "clang ${llvmPackages.clang.version})"
      '';
  };

  asan = pkgs.mkShell {
    inputsFrom = [ cargoArtifacts ];
    CC = "${pkgs.stdenv.cc}/bin/cc";
    CXX = "${pkgs.stdenv.cc}/bin/c++";
    packages = lib.unique (
      asanDevTools
      ++ [
        sharedCompilerRt
        llvmPackages.clang
        llvmPackages.bintools
        llvmPackages.libclang
      ]
    );
    shellHook =
      commonShellHook
      + kaniShellHook
      + toolPathShellHook
      + ''
        export SANITIZER_RUNTIME_DIR='${asanRuntimeLibDir}'
        export ASAN_DIR="$SANITIZER_RUNTIME_DIR"
        unset RUSTFLAGS
        unset RUSTDOCFLAGS
        export SANITIZER_RUSTFLAGS=\
          "-C target-feature=-avx2,-avx512ifma,-avx512vl,-avx512f,-avx512bw,-avx512dq"
        echo \
          "Loaded Aegaeon ASan dev environment" \
          "(fenix ASan toolchain + static ASan runtime, clang ${llvmPackages.clang.version})"
        echo \
          "Use scripts/sanitizers/run_sanitizers.sh" \
          "or SANITIZER_RUSTFLAGS when instrumentation is required"
      '';
  };

  verification = pkgs.mkShell {
    inputsFrom = [ cargoArtifacts ];
    CC = "${pkgs.stdenv.cc}/bin/cc";
    CXX = "${pkgs.stdenv.cc}/bin/c++";
    packages = lib.unique (
      verificationTools
      ++ [
        pkgs.openssl
        pkgs.mbedtls
        pkgs.pkg-config
        rustToolchain
        haclStar
        karamel
        llvmPackages.clang
        llvmPackages.bintools
        llvmPackages.libclang
      ]
    );
    shellHook =
      commonShellHook
      + kaniShellHook
      + toolPathShellHook
      + ''
        echo "Loaded Aegaeon verification environment"
      '';
  };
}
