# Nix derivation for building verified-core WASM from F* source
{
  lib,
  stdenv,
  fstar,
  karamel,
  wasiClang,
  wasiClangBin,
  wasiTarget,
  wasiSysroot,
  haclStar,
  evercrypt,
  everparse,
  openssl,
  coreutils,
}:
let
  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        rel = lib.removePrefix "${toString ../.}/" (toString path);
        isTargetPath = rel == "target" || lib.hasPrefix "target/" rel || lib.hasInfix "/target/" rel;
      in
      (!isTargetPath)
      && (
        type == "directory"
        || lib.hasPrefix "fstar/" rel
        || lib.hasPrefix "c/" rel
        || lib.hasPrefix "include/" rel
      );
  };

  # F* modules to extract (order matters for dependencies)
  # Note: Verified.Crypto.Bridge.fst is NOT extracted — it's marked -library
  # in KaRaMeL and provided as a C implementation (c/crypto_bridge.c).
  # It is available via --include for type-checking.
  modules = [
    "fstar/HashComputation.fst"
    "fstar/pkce/Pkce.Challenge.fst"
    "fstar/pkce/Pkce.fst"
    "fstar/pkce/Pkce.Method_selection.fst"
    "fstar/pkce/Pkce.Verification.fst"
    "fstar/pkce/Pkce.Verifier.fst"
    "fstar/dpop/Dpop.Ath_validation.fst"
    "fstar/dpop/Dpop.Claims.fst"
    "fstar/dpop/Dpop.fst"
    "fstar/dpop/Dpop.Header.fst"
    "fstar/dpop/Dpop.Htm_validation.fst"
    "fstar/dpop/Dpop.Htu_validation.fst"
    "fstar/dpop/Dpop.Iat_validation.fst"
    "fstar/dpop/Dpop.Replay.fst"
    "fstar/dpop/Dpop.Signature.fst"
    "fstar/dpop/Dpop.Token_binding.fst"
    "fstar/dpop/Dpop.Validation.fst"
    "fstar/verifiedcore/api/VerifiedCore.Crypto.Hacl.fst"
    "fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst"
    "fstar/ConstTime.fst"
  ];

in
stdenv.mkDerivation {
  pname = "verified-core-wasm";
  version = "0.1.0";

  inherit src;

  nativeBuildInputs = [
    fstar
    karamel
    wasiClang
    openssl
    coreutils
  ];

  buildInputs = [
    haclStar
    evercrypt
    everparse
  ];

  buildPhase = ''
    runHook preBuild

    export HOME="$TMPDIR"
    mkdir -p "$TMPDIR/krml" "$TMPDIR/c" "$TMPDIR/wasm"

    # Build include flags for F*
    INCLUDE_FLAGS=(
      --include "$PWD/fstar"
      --include "$PWD/fstar/crypto"
      --include "$PWD/fstar/verifiedcore/api"
    )

    # Add HACL* includes (top-level + subdirectories for hash/hmac/ed25519 specs)
    if [ -d "${haclStar}/share/hacl-star/fstar" ]; then
      INCLUDE_FLAGS+=(--include "${haclStar}/share/hacl-star/fstar")
      for subdir in $(find "${haclStar}/share/hacl-star/fstar" -maxdepth 1 -type d | sort); do
        INCLUDE_FLAGS+=(--include "$subdir")
      done
    fi

    # Add EverCrypt includes
    for dir in "${evercrypt}/share/evercrypt/providers/fst" \
               "${evercrypt}/share/evercrypt/specs" \
               "${evercrypt}/share/evercrypt/code"; do
      if [ -d "$dir" ]; then
        INCLUDE_FLAGS+=(--include "$dir")
      fi
    done

    # Add KaRaMeL krmllib includes
    if [ -d "${karamel}/lib/krml" ]; then
      INCLUDE_FLAGS+=(--include "${karamel}/lib/krml")
    fi

    # Add EverParse includes
    for dir in "${everparse}/share/everparse" \
               "${everparse}/lib/lowparse"; do
      if [ -d "$dir" ]; then
        while IFS= read -r subdir; do
          INCLUDE_FLAGS+=(--include "$subdir")
        done < <(find "$dir" -maxdepth 2 -type d | sort)
      fi
    done

    echo "[verified-core] Extracting F* modules to .krml..."
    ${fstar}/bin/fstar.exe \
      --codegen krml \
      --odir "$TMPDIR/krml" \
      --warn_error -274 \
      --extract 'krml:* -Spec -Lib -Hacl -LowStar -C' \
      "''${INCLUDE_FLAGS[@]}" \
      ${lib.concatStringsSep " " modules}

    krml_files=$(find "$TMPDIR/krml" -name '*.krml' | sort)
    if [ -z "$krml_files" ]; then
      echo "[verified-core] No .krml files generated" >&2
      exit 1
    fi
    echo "[verified-core] Generated $(echo "$krml_files" | wc -l) .krml files"

    echo "[verified-core] Running KaRaMeL to generate C..."
    ${karamel}/bin/krml \
      -tmpdir "$TMPDIR/c" \
      -skip-linking \
      -skip-compilation \
      -warn-error -2-9-16-26 \
      -library FStar.UInt8 \
      -library FStar.UInt16 \
      -library FStar.UInt32 \
      -library FStar.UInt64 \
      -library FStar.Int8 \
      -library FStar.Int16 \
      -library FStar.Int32 \
      -library FStar.Int64 \
      -library FStar.Int128 \
      -library FStar.UInt128 \
      -library FStar.Pervasives.Native \
      -library FStar.List.Tot \
      -library FStar.Math.Lemmas \
      -library Verified.Crypto.Bridge \
      -library VerifiedCore.Crypto.Hacl \
      -library Spec \
      -library Lib \
      $krml_files

    # Copy verified_core_exports shim
    if [ -f "c/verified-core/verified_core_exports.c" ]; then
      cp c/verified-core/verified_core_exports.c "$TMPDIR/c/"
    fi
    if [ -f "c/verified-core/verified_core_exports.h" ]; then
      cp c/verified-core/verified_core_exports.h "$TMPDIR/c/"
    fi

    # Copy vc_* public ABI shim
    if [ -f "c/verified_core.c" ]; then
      cp c/verified_core.c "$TMPDIR/c/"
    fi
    if [ -f "include/verified_core.h" ]; then
      cp include/verified_core.h "$TMPDIR/c/"
    fi

    # Copy crypto bridge C shim (implements Verified.Crypto.Bridge functions)
    if [ -f "c/crypto_bridge.c" ]; then
      cp c/crypto_bridge.c "$TMPDIR/c/"
    fi
    if [ -f "c/crypto_bridge.h" ]; then
      cp c/crypto_bridge.h "$TMPDIR/c/"
    fi

    # Copy HACL* bridge for VerifiedCore.Crypto.Hacl (Phase D: maps KaRaMeL
    # externs to HACL* C functions for SHA-256 and Ed25519)
    if [ -f "c/verified-core/hacl_bridge.c" ]; then
      cp c/verified-core/hacl_bridge.c "$TMPDIR/c/"
    fi

    # Copy HACL* dist C sources (verified crypto implementations)
    HACL_DIST="${evercrypt}/share/evercrypt/dist/gcc-compatible"
    if [ -d "$HACL_DIST" ]; then
      echo "[verified-core] Copying HACL* C sources from $HACL_DIST..."
      mkdir -p "$TMPDIR/c/hacl" "$TMPDIR/c/hacl/internal"

      # Copy ALL headers from HACL* dist (needed for cross-file references)
      cp "$HACL_DIST/"*.h "$TMPDIR/c/hacl/" 2>/dev/null || true

      # Core crypto C files needed by the minimal verified-core bridge
      for f in Hacl_Hash_SHA2.c \
               Hacl_Ed25519.c \
               Hacl_EC_Ed25519.c \
               Hacl_Curve25519_51.c \
               Hacl_Hash_Base.c \
               Lib_Memzero0.c; do
        if [ -f "$HACL_DIST/$f" ]; then
          cp "$HACL_DIST/$f" "$TMPDIR/c/hacl/"
        fi
      done

      # Internal headers
      if [ -d "$HACL_DIST/internal" ]; then
        cp "$HACL_DIST/internal/"*.h "$TMPDIR/c/hacl/internal/" 2>/dev/null || true
      fi

      # Config header
      if [ -f "$HACL_DIST/config.h" ]; then
        cp "$HACL_DIST/config.h" "$TMPDIR/c/hacl/"
      fi

      echo "[verified-core] HACL* C sources copied"
    else
      echo "[verified-core] WARNING: HACL* dist not found at $HACL_DIST"
    fi

    echo "[verified-core] Compiling to WASM..."
    # Collect C sources: KaRaMeL-extracted + shims
    c_sources=$(find "$TMPDIR/c" -maxdepth 1 -name '*.c' | sort)
    # Add HACL* C sources
    hacl_sources=$(find "$TMPDIR/c/hacl" -maxdepth 1 -name '*.c' 2>/dev/null | sort)

    compile_flags=(
      --target=${wasiTarget}
      --sysroot="${wasiSysroot}"
      -O2
      -flto
      -nostdlib
      -fvisibility=hidden
      -DAEG_VERIFIED_CORE_WASM_MINIMAL=1
      -include "$PWD/c/wasi-stubs/krml_alloc.h"
      -I"$TMPDIR/c"
      -I"$TMPDIR/c/internal"
      -I"$TMPDIR/c/hacl"
      -I"$TMPDIR/c/hacl/internal"
      -I"${karamel}/include"
      -I"${karamel}/lib/krml/c"
      -I"${karamel}/lib/krml/dist/minimal"
      -I"${karamel}/lib/krml/dist/generic"
      -I"$PWD/c/wasi-stubs"
    )

    ld_flags=(
      -Wl,--allow-undefined
      -Wl,--export-all
      -Wl,--no-entry
      -Wl,--strip-all
      -Wl,--gc-sections
    )

    ${wasiClangBin} \
      "''${compile_flags[@]}" \
      $c_sources \
      $hacl_sources \
      "''${ld_flags[@]}" \
      -o "$TMPDIR/wasm/verified_core.wasm"

    if [ ! -f "$TMPDIR/wasm/verified_core.wasm" ]; then
      echo "[verified-core] WASM compilation failed" >&2
      exit 1
    fi

    echo "[verified-core] WASM compiled successfully"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p "$out"/{wasm,c,krml,include}

    # Install WASM artifact
    install -Dm644 "$TMPDIR/wasm/verified_core.wasm" "$out/wasm/verified_core.wasm"

    # Install public header
    if [ -f "$TMPDIR/c/verified_core.h" ]; then
      install -Dm644 "$TMPDIR/c/verified_core.h" "$out/include/verified_core.h"
    fi

    # Generate checksums
    sha256=$(sha256sum "$out/wasm/verified_core.wasm" | awk '{print $1}')
    printf '%s  verified_core.wasm\n' "$sha256" > "$out/wasm/verified_core.wasm.sha256"

    # Generate SRI hash
    sri_payload=$(openssl dgst -sha256 -binary "$out/wasm/verified_core.wasm" | openssl base64 -A)
    printf 'sha256-%s\n' "$sri_payload" > "$out/wasm/verified_core.wasm.sri"

    # Generate manifest
    size_bytes=$(stat -c%s "$out/wasm/verified_core.wasm")
    cat > "$out/wasm/manifest.json" <<EOF
    {
      "artifact": "verified_core.wasm",
      "size_bytes": $size_bytes,
      "sha256": "$sha256",
      "sri": "sha256-$sri_payload"
    }
    EOF

    # Install intermediate artifacts for debugging
    cp -r "$TMPDIR/c"/* "$out/c/" || true
    cp -r "$TMPDIR/krml"/* "$out/krml/" || true

    echo "[verified-core] Installed to $out"
    runHook postInstall
  '';

  meta = with lib; {
    description = "Formally verified cryptographic core for Aegaeon (WASM)";
    license = licenses.asl20;
    platforms = platforms.unix;
  };
}
