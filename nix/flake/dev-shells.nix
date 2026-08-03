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
  asanRuntimeLibDir,
}:
let
  toolPathShellHook = ''
    export AEG_TOOL_PATH="${karamel}/bin:${pkgs.fstar}/bin:${everparse}/bin:${pkgs.z3}/bin"
    export AEG_TOOL_PATH="$AEG_TOOL_PATH:${llvmPackages.bintools}/bin:${llvmPackages.clang}/bin"
    export AEG_TOOL_PATH="$AEG_TOOL_PATH:${rustToolchain}/bin"
    export PATH="$AEG_TOOL_PATH:$PATH"
  '';
in
{
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
