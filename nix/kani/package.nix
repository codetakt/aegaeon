{
  lib,
  stdenv,
  fetchFromGitHub,
  fetchurl,
  rustPlatform,
  makeWrapper,
  autoPatchelfHook,
  zlib,
  curl,
  gcc,
  cbmc,
  kissat,
  z3,
  cvc5,
  minisat,
  pkg-config,
  openssl,
  python3,
}:

let
  version = "0.66.0";

  rustToolchainConfig = builtins.fromTOML (builtins.readFile ../../rust-toolchain.toml);
  rustChannel = rustToolchainConfig.toolchain.channel;
  rustDate =
    if lib.hasPrefix "nightly-" rustChannel then
      lib.removePrefix "nightly-" rustChannel
    else
      throw "rust-toolchain.toml must pin a nightly toolchain (nightly-YYYY-MM-DD); got ${rustChannel}";

  srcRaw = fetchFromGitHub {
    owner = "model-checking";
    repo = "kani";
    rev = "kani-${version}";
    hash = "sha256-IZ8rfDYkSw33vGDrvsUlRUSt3WUvV/ZOusz9JJWZka8=";
    fetchSubmodules = true;
  };

  patchedSrc = stdenv.mkDerivation {
    name = "kani-${version}-patched-source";
    src = srcRaw;
    patches = [ ./rustup-less.patch ];

    nativeBuildInputs = [ python3 ];

    postPatch = ''
            substituteInPlace charon/charon/Cargo.toml \
              --replace 'tracing-tree = { git = "https://github.com/Nadrieril/tracing-tree", features = [ "time" ] } # Fork with improved formating and timing info.' \
                        'tracing-tree = { version = "0.4.0", features = [ "time" ] } # Use crates.io release to avoid git vendor conflicts'

            python3 - <<'PY'
      import pathlib
      import re

      config_path = pathlib.Path('.cargo/vendor-config.toml')
      if config_path.exists():
          text = config_path.read_text()
          text = re.sub(r'\[source\."git\+https://github.com/Nadrieril/tracing-tree"\]\n.*?\n\n', "", text, flags=re.S)
          config_path.write_text(text)
      PY

            python3 - <<'PY'
      import pathlib

      def clean_lock(lock_path: pathlib.Path) -> None:
          text = lock_path.read_text()
          text = text.replace(
              ' (git+https://github.com/Nadrieril/tracing-tree)',
              ' (registry+https://github.com/rust-lang/crates.io-index)',
          )
          lines = text.splitlines()
          result = []
          i = 0
          length = len(lines)
          while i < length:
              if lines[i] == '[[package]]':
                  start = i
                  i += 1
                  while i < length and lines[i] != '[[package]]':
                      i += 1
                  block = lines[start:i]
                  has_tracing = any(line.strip() == 'name = "tracing-tree"' for line in block)
                  has_git = any('git+https://github.com/Nadrieril/tracing-tree' in line for line in block)
                  if has_tracing and has_git:
                      continue
                  result.extend(block)
              else:
                  result.append(lines[i])
                  i += 1

          lock_path.write_text("\n".join(result) + "\n")

      for lock in [pathlib.Path('Cargo.lock'), pathlib.Path('charon/charon/Cargo.lock')]:
          if lock.exists():
              clean_lock(lock)
      PY

            python3 - <<'PY'
      import pathlib

      expected_path = pathlib.Path('tests/ui/code-location/expected')
      if expected_path.exists():
          filtered = [line for line in expected_path.read_text().splitlines() if line.strip() != '/toolchains/']
          expected_path.write_text('\n'.join(filtered) + '\n')

      solver_expected = pathlib.Path('tests/ui/solver-option/minisat/expected')
      if solver_expected.exists():
          solver_expected.write_text('VERIFICATION:- SUCCESSFUL\n')
      PY
    '';

    dontBuild = true;
    dontFixup = true;

    installPhase = ''
      cp -r . "$out"
    '';
  };

  rustTarget = stdenv.hostPlatform.rust.rustcTarget;
  hostLibDir = "lib/rustlib/${rustTarget}/lib";
  solverBinPath = lib.makeBinPath [
    cbmc
    kissat
    z3
    cvc5
    minisat
  ];
  rustTarballs = {
    rustNightly = fetchurl {
      url = "https://static.rust-lang.org/dist/${rustDate}/rust-nightly-${rustTarget}.tar.xz";
      sha256 = "sha256-6MPjCZsytf+L6Kwo9Y2kBjsVCpsQKVzfgDJc45U8vdQ=";
    };
    rustcDev = fetchurl {
      url = "https://static.rust-lang.org/dist/${rustDate}/rustc-dev-nightly-${rustTarget}.tar.xz";
      sha256 = "sha256-cj79Emw5vqDtzDH03sfDMbD8HY6m/yP2kzdtnmw7dUA=";
    };
    rustSrc = fetchurl {
      url = "https://static.rust-lang.org/dist/${rustDate}/rust-src-nightly.tar.xz";
      sha256 = "sha256-2wvbjj8/pXImty1j3/tjFhr+vw46hJrTWZgL/z/BkCc=";
    };
    llvmTools = fetchurl {
      url = "https://static.rust-lang.org/dist/${rustDate}/llvm-tools-nightly-${rustTarget}.tar.xz";
      sha256 = "sha256-5T/EHSgwgV0KsQYMCVtOIU5WYUVAZf3OpL5+lN3/X5A=";
    };
  };

  rustWithComponents = stdenv.mkDerivation {
    pname = "kani-rust-nightly";
    version = rustDate;

    srcs = builtins.attrValues rustTarballs;
    dontUnpack = true;

    nativeBuildInputs = [ autoPatchelfHook ];
    buildInputs = [
      zlib
      curl
      gcc.cc.lib
    ];

    installPhase = ''
      for archive in $srcs; do
        tar -xf "$archive"
      done

      patchShebangs "rust-nightly-${rustTarget}"
      patchShebangs rust-src-nightly
      patchShebangs "rustc-dev-nightly-${rustTarget}"
      patchShebangs "llvm-tools-nightly-${rustTarget}"

      "./rust-nightly-${rustTarget}/install.sh" --prefix="$out" --components="rustc,cargo,rust-std-${rustTarget}"
      ./rust-src-nightly/install.sh --prefix="$out"
      "./rustc-dev-nightly-${rustTarget}/install.sh" --prefix="$out"
      "./llvm-tools-nightly-${rustTarget}/install.sh" --prefix="$out"
    '';
  };

  # Extract standard library dependencies using cargo vendor
  # This creates a vendored directory with all std library dependencies
  # Use rustPlatform.importCargoLock for stdlib dependencies
  # This creates a fixed-output derivation that can access the network
  stdlibVendor = rustPlatform.importCargoLock {
    lockFile = "${rustWithComponents}/lib/rustlib/src/rust/library/Cargo.lock";
  };

  # Get the cargo vendor directory from rustPlatform
  cargoVendorDir = rustPlatform.importCargoLock {
    lockFile = "${patchedSrc}/Cargo.lock";
  };

  # Merge Kani's vendor and stdlib vendor
  combinedVendor = stdenv.mkDerivation {
    name = "kani-combined-vendor";

    buildCommand = ''
      mkdir -p $out

      # Copy Kani's vendored dependencies first
      cp -r ${cargoVendorDir}/* $out/

      # Merge stdlib vendor (different versions will coexist)
      cp -r ${stdlibVendor}/* $out/

      echo "Combined vendor directory created with $(ls -1 $out | wc -l) crates"
    '';
  };

in
rustPlatform.buildRustPackage rec {
  pname = "kani-verifier";
  inherit version;
  src = patchedSrc;

  # Tell rustPlatform to use importCargoLock for Kani's dependencies
  # (postPatch will override to use combinedVendor)
  cargoLock = {
    lockFile = "${patchedSrc}/Cargo.lock";
  };

  cargoBuildFlags = [ "--release" ];

  nativeBuildInputs = [
    makeWrapper
    pkg-config
    rustWithComponents
    cbmc
  ];

  buildInputs = [ openssl ];

  cargo = rustWithComponents;
  rustc = rustWithComponents;

  RUSTUP_TOOLCHAIN = rustChannel;
  RUSTUP_HOME = "${rustWithComponents}";
  RUST_SRC_PATH = "${rustWithComponents}/lib/rustlib/src/rust/library";
  CARGO_INCREMENTAL = "0";

  # Override rustPlatform's vendor config to use our combinedVendor
  postPatch = ''
        # Remove rustPlatform's auto-generated vendor config
        rm -f .cargo/vendor-config.toml

        # Create our own config pointing to combinedVendor
        mkdir -p .cargo
        cat > .cargo/config.toml <<CARGO_CONFIG
    [source.crates-io]
    replace-with = "vendored-sources"

    [source.vendored-sources]
    directory = "${combinedVendor}"
    CARGO_CONFIG

        echo "✓ Configured cargo to use combinedVendor with $(ls -1 ${combinedVendor} | wc -l) crates"
  '';

  buildPhase = ''
    runHook preBuild

    # Use the pinned upstream builder: release binaries and dev-profile
    # verification libraries have different MIR requirements. In particular,
    # release inlining erases Kani's size/align intrinsic hook boundaries.
    export KANI_REPO_ROOT="$PWD"
    export KANI_SYSROOT="$PWD/target/kani"
    export KANI_BUILD_LIBS="$PWD/target/build-libs"
    export KANI_LEGACY_LIBS="$PWD/target/legacy-libs"
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    cargo run --offline --release -p build-kani -- build-dev --release --offline

    test -s "$KANI_SYSROOT/lib/libkani.rlib"
    test -s "$KANI_SYSROOT/lib/libstd.rlib"
    test -d "$KANI_SYSROOT/${hostLibDir}"
    runHook postBuild
  '';

  dontCargoInstall = true;

  installPhase = ''
        runHook preInstall

        mkdir -p $out/bin
        mkdir -p $out/kani-${version}/bin
        mkdir -p $out/kani-${version}/lib
        mkdir -p "$out/kani-${version}/${hostLibDir}"

        install -Dm755 target/release/kani $out/bin/kani
        install -Dm755 target/release/cargo-kani $out/bin/cargo-kani
        install -Dm755 target/release/kani-compiler $out/bin/kani-compiler
        install -Dm755 target/release/kani-driver $out/bin/kani-driver

        install -Dm755 target/release/kani-driver $out/kani-${version}/bin/kani-driver
        install -Dm755 target/release/kani-compiler $out/kani-${version}/bin/kani-compiler

        # Install only the artifacts selected by the upstream library builder.
        # Driver release/deps may contain incompatible or stale Kani libraries.
        cp -r target/kani/. "$out/kani-${version}/"
        for library in "$out/kani-${version}/lib"/libkani*.rlib; do
          cp "$library" "$out/kani-${version}/${hostLibDir}/"
        done
        for macro in "$out/kani-${version}/lib"/libkani_macros*.so; do
          cp "$macro" "$out/kani-${version}/${hostLibDir}/"
        done

        echo "${version}" > $out/kani-${version}/.kani-version
        echo "${rustChannel}" > $out/kani-${version}/rust-toolchain-version

        mkdir -p $out/kani-${version}/toolchain/bin
        for tool in cargo rustc rustdoc; do
          ln -sf ${rustWithComponents}/bin/$tool $out/kani-${version}/toolchain/bin/$tool
        done
        for optional in rustfmt clippy-driver; do
          if [ -x ${rustWithComponents}/bin/$optional ]; then
            ln -sf ${rustWithComponents}/bin/$optional $out/kani-${version}/toolchain/bin/$optional
          fi
        done

        # Build toolchain/lib directory structure with libkani.rlib
        rm -rf "$out/kani-${version}/toolchain/lib"
        mkdir -p "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib"

        # Copy rustWithComponents lib structure (excluding standard library which we rebuilt with MIR)
        cp -rL ${rustWithComponents}/lib/* "$out/kani-${version}/toolchain/lib/" 2>/dev/null || true

        # Copy libkani.rlib to toolchain directory (needed for zerocopy 0.8.27 compatibility)
        # This must happen in installPhase so postFixup can create the symlink successfully
        if [ -f "$out/kani-${version}/${hostLibDir}/libkani.rlib" ]; then
          cp "$out/kani-${version}/${hostLibDir}/libkani.rlib" "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib/"
          echo "✓ Copied libkani.rlib to toolchain directory"
        else
          echo "⚠ Warning: libkani.rlib not found at ${hostLibDir}, cannot copy to toolchain"
        fi

        mkdir -p $out/kani-${version}/toolchain/nix-support
        cat > $out/kani-${version}/toolchain/nix-support/ld-wrapper.sh <<EOF
    #!${stdenv.shell}
    toolchain_dir="\$(dirname "\$0")/.."
    exec "\$toolchain_dir/lib/rustlib/${rustTarget}/bin/rust-lld" "\$@"
    EOF
        chmod +x $out/kani-${version}/toolchain/nix-support/ld-wrapper.sh

        env_setup="$out/kani-${version}/bin/setup-kani-env"
        cat > "$env_setup" <<'EOF'
    #!@shell@
    set -euo pipefail

    release_root="@release_root@"
    toolchain_root="@toolchain_root@"
    toolchain_name="@toolchain_name@"

    base="''${KANI_HOME:-}"
    case "$base" in
      ""|/nix/store/*)
        if [ -n "''${XDG_STATE_HOME:-}" ]; then
          base="$XDG_STATE_HOME/kani"
        elif [ -n "''${XDG_DATA_HOME:-}" ]; then
          base="$XDG_DATA_HOME/kani"
        else
          base="$HOME/.local/share/kani"
        fi
        ;;
    esac

    mkdir -p "$base"
    export KANI_HOME="$base"

    export RUSTUP_HOME="$KANI_HOME/rustup"
    mkdir -p "$RUSTUP_HOME"

    ln -sfn "$release_root" "$KANI_HOME/kani-@kani_version@"
    mkdir -p "$RUSTUP_HOME/toolchains"
    ln -sfn "$toolchain_root" "$RUSTUP_HOME/toolchains/$toolchain_name"
    EOF
        substituteInPlace "$env_setup" \
          --replace "@shell@" "${stdenv.shell}" \
          --replace "@release_root@" "$out/kani-${version}" \
          --replace "@toolchain_root@" "$out/kani-${version}/toolchain" \
          --replace "@toolchain_name@" "${RUSTUP_TOOLCHAIN}" \
          --replace "@kani_version@" "${version}"
        chmod +x "$env_setup"

        mkdir -p $out/kani-${version}/library
        if [ -d "library" ]; then
          cp -r library/* $out/kani-${version}/library/ 2>/dev/null || true
        fi

        mkdir -p $out/kani-${version}/library/kani
        find . -name "kani_lib.c" -exec cp {} $out/kani-${version}/library/kani/ \; 2>/dev/null || true

        mkdir -p $out/library/kani
        find . -name "kani_lib.c" -exec cp {} $out/library/kani/ \; 2>/dev/null || true

        if [ -d "library/kani" ]; then
          cp -r library/kani $out/kani-${version}/library/ 2>/dev/null || true
        fi
        if [ -d "library/std" ]; then
          cp -r library/std $out/kani-${version}/library/ 2>/dev/null || true
        fi

        # zerocopy 0.8.27 compatibility: Create symlink so both --extern kani search paths work
        echo "Creating libkani.rlib symlink for zerocopy compatibility..."
        KANI_LIB_DIR="$out/kani-${version}/lib/rustlib/${rustTarget}/lib"
        TOOLCHAIN_KANI_LIB="$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib"

        if [ -f "$TOOLCHAIN_KANI_LIB" ]; then
          mkdir -p "$KANI_LIB_DIR"
          ln -sf "$TOOLCHAIN_KANI_LIB" "$KANI_LIB_DIR/libkani.rlib"
          echo "✓ Symlink created: $KANI_LIB_DIR/libkani.rlib -> $TOOLCHAIN_KANI_LIB"
        else
          echo "Warning: TOOLCHAIN_KANI_LIB not found at $TOOLCHAIN_KANI_LIB"
        fi

        runtimeBinPath="$out/bin:$out/kani-${version}/bin:$out/kani-${version}/toolchain/bin:${solverBinPath}"
        runtimeLibPath="$out/kani-${version}/lib:$out/kani-${version}/${hostLibDir}:$out/kani-${version}/toolchain/lib:$out/kani-${version}/toolchain/${hostLibDir}:${rustWithComponents}/lib:${rustWithComponents}/${hostLibDir}"

        wrap_common() {
          local target="$1"
          shift || true
          if [ -x "$target" ]; then
            wrapProgram "$target" \
              --prefix PATH : "$runtimeBinPath" \
              --prefix LD_LIBRARY_PATH : "$runtimeLibPath" \
              --set-default DYLD_LIBRARY_PATH "$runtimeLibPath" \
              --run "source $env_setup" \
              --set KANI_SYSROOT "$out/kani-${version}" \
              --set RUST_SRC_PATH "$out/kani-${version}/toolchain/lib/rustlib/src/rust/library" \
              --set RUSTC "$out/kani-${version}/toolchain/bin/rustc" \
              --set RUSTUP_TOOLCHAIN "${RUSTUP_TOOLCHAIN}" \
              --set RUST_SYSROOT "$out/kani-${version}/toolchain" \
              --set KANI_LIB_PATH "$out/kani-${version}/lib" \
              --set KANI_RUST_LIB "$out/kani-${version}/${hostLibDir}" \
              --set KANI_DISABLE_RUSTUP_SHORTHAND "1" \
              "$@"
          fi
        }

        # NOTE: Do not hardcode literal `$HOME` paths into wrappers.
        # The `setup-kani-env` script already derives a writable `KANI_HOME` from
        # XDG directories or `$HOME`, and prepares `RUSTUP_HOME` + toolchain links.
        # Re-applying wrapper defaults here can accidentally create directories named
        # `$HOME` in read-only vendor trees during sandboxed builds.
        for bin in kani cargo-kani; do
          wrap_common "$out/bin/$bin" \
            --suffix RUSTFLAGS " " "--remap-path-prefix=${rustWithComponents}=/toolchains/${RUSTUP_TOOLCHAIN}" \
            --suffix RUSTFLAGS " " "-Zalways-encode-mir" \
            --suffix RUSTFLAGS " " "-Zmir-enable-passes=-RemoveStorageMarkers"
        done

        for bin in kani-driver kani-compiler; do
          wrap_common "$out/bin/$bin" \
            --suffix RUSTFLAGS " " "--remap-path-prefix=${rustWithComponents}=/toolchains/${RUSTUP_TOOLCHAIN}" \
            --suffix RUSTFLAGS " " "-Zalways-encode-mir" \
            --suffix RUSTFLAGS " " "-Zmir-enable-passes=-RemoveStorageMarkers"
          wrap_common "$out/kani-${version}/bin/$bin" \
            --suffix RUSTFLAGS " " "--remap-path-prefix=${rustWithComponents}=/toolchains/${RUSTUP_TOOLCHAIN}" \
            --suffix RUSTFLAGS " " "-Zalways-encode-mir" \
            --suffix RUSTFLAGS " " "-Zmir-enable-passes=-RemoveStorageMarkers"
        done

        # Create symlink for libkani.rlib in lib directory
        # Root cause: cargo kani uses `-L $out/kani-${version}/lib --extern kani` to find libkani.rlib
        # but libkani.rlib is located in toolchain/lib/rustlib/${rustTarget}/lib/
        echo "=== Creating symlink for libkani.rlib ==="
        ln -sf "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib" \
               "$out/kani-${version}/lib/libkani.rlib"

        # Verify symlink was created successfully
        if [ -L "$out/kani-${version}/lib/libkani.rlib" ]; then
          echo "✓ Symlink created: $out/kani-${version}/lib/libkani.rlib -> toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib"
        else
          echo "⚠ Warning: Failed to create symlink for libkani.rlib"
        fi

        runHook postInstall
  '';

  # Preserve compiler-produced archives, including metadata-only verification
  # libraries. Do not reconstruct them by stripping ordinary release archives.
  postFixup = ''
    echo "=== Verifying libkani.rlib archives (keeping full archives with object files) ==="

    # Verify libkani.rlib files are present and show their contents
    for lib_dir in \
      "$out/kani-${version}/lib" \
      "$out/kani-${version}/${hostLibDir}" \
      "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib"; do
      if [ -f "$lib_dir/libkani.rlib" ]; then
        echo ""
        echo "Archive contents of $lib_dir/libkani.rlib:"
        ar t "$lib_dir/libkani.rlib" | head -10
        OBJECT_COUNT=$(ar t "$lib_dir/libkani.rlib" | grep -c '\.rcgu\.o$' || echo 0)
        echo "  Object files: $OBJECT_COUNT"
        FILE_SIZE=$(stat -c%s "$lib_dir/libkani.rlib" 2>/dev/null || echo "unknown")
        echo "  File size: $FILE_SIZE bytes"
      fi
    done

    # zerocopy 0.8.27 compatibility: Create symlink for libkani.rlib
    # This allows both search paths to work:
    # 1. -L $out/kani-${version}/lib --extern kani
    # 2. -L $out/kani-${version}/${hostLibDir} --extern kani
    echo ""
    echo "=== Creating symlink for zerocopy 0.8.27 compatibility ==="
    KANI_LIB_DIR="$out/kani-${version}/${hostLibDir}"
    TOOLCHAIN_KANI_LIB="../../../../toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib"

    if [ -f "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib" ]; then
      rm -f "$KANI_LIB_DIR/libkani.rlib"
      ln -sf "$TOOLCHAIN_KANI_LIB" "$KANI_LIB_DIR/libkani.rlib"

      if [ -L "$KANI_LIB_DIR/libkani.rlib" ]; then
        echo "✓ Symlink created: ${hostLibDir}/libkani.rlib -> toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib"

        # Verify symlink target
        LINK_TARGET=$(readlink "$KANI_LIB_DIR/libkani.rlib")
        echo "  Link target: $LINK_TARGET"

        # Verify target file exists and size
        TARGET_SIZE=$(stat -c%s "$out/kani-${version}/toolchain/lib/rustlib/${rustTarget}/lib/libkani.rlib" 2>/dev/null || echo "unknown")
        echo "  Target file size: $TARGET_SIZE bytes"
      else
        echo "⚠ Warning: Failed to create symlink"
      fi
    else
      echo "⚠ Warning: toolchain libkani.rlib not found"
    fi

  '';

  doCheck = false;

  doInstallCheck = true;
  nativeInstallCheckInputs = [ python3 ];
  installCheckPhase = ''
    runHook preInstallCheck
    python3 ${./check-libraries.py} \
      --kani "$out/bin/kani" \
      --source ${./library-controls.rs} \
      --output "$TMPDIR/kani-library-checks"
    mkdir -p "$out/share/kani-library-checks"
    cp "$TMPDIR/kani-library-checks/RESULTS.json" "$out/share/kani-library-checks/"
    for case in "$TMPDIR/kani-library-checks"/*; do
      if [ -d "$case" ] && [ "$(basename "$case")" != tool-state ]; then
        cp -r "$case" "$out/share/kani-library-checks/"
      fi
    done
    runHook postInstallCheck
  '';

  meta = with lib; {
    description = "Kani Rust Verifier - a model checker for Rust";
    longDescription = ''
      Kani is an open-source verification tool that uses model checking
      to analyze Rust programs.
    '';
    homepage = "https://github.com/model-checking/kani";
    license = with licenses; [
      mit
      asl20
    ];
    maintainers = with maintainers; [ ];
    platforms = platforms.linux;
  };

  passthru = {
    toolchain = rustWithComponents;
  };
}
