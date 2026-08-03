#!/usr/bin/env bash
#
# Build the verified core artifact and stage it under artifacts/verified-core/.
# This does not sign the artifact; downstream steps are expected to handle
# signatures and SBOM generation.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
EXTRACT_SCRIPT="$ROOT/scripts/extraction/run_verified_core_lowstar.sh"
ARTIFACT_DIR="$ROOT/artifacts/verified-core"
WASM_SOURCE="$ROOT/generated/lowstar/verified-core/wasm/verified_core.wasm"

if [[ -z ${WASI_CLANG:-} || ! -x ${WASI_CLANG:-} ]]; then
	if command -v wasm32-unknown-wasi-clang >/dev/null 2>&1; then
		export WASI_CLANG="$(command -v wasm32-unknown-wasi-clang)"
	else
		candidate="$(find /nix/store -maxdepth 2 -name 'wasm32-unknown-wasi-clang' 2>/dev/null | head -n1 || true)"
		if [[ -n $candidate && -x $candidate ]]; then
			export WASI_CLANG="$candidate"
		else
			cat >&2 <<'ERR'
[package-verified-core] WASI_CLANG not set and wasm32-unknown-wasi-clang not found.
Use 'nix develop' or set WASI_CLANG explicitly.
ERR
			exit 1
		fi
	fi
fi

if [[ -z ${WASI_SYSROOT:-} || ! -d ${WASI_SYSROOT:-} ]]; then
	candidate_sysroot="$(find /nix/store -maxdepth 1 -type d -name '*-wasi-sysroot' 2>/dev/null | head -n1 || true)"
	if [[ -n $candidate_sysroot ]]; then
		export WASI_SYSROOT="$candidate_sysroot"
	else
		cat >&2 <<'ERR'
[package-verified-core] WASI_SYSROOT not set and no wasi-sysroot found.
Use 'nix develop' or set WASI_SYSROOT explicitly.
ERR
		exit 1
	fi
fi

mkdir -p "$ARTIFACT_DIR"

WITH_WASM_BUILD=1 "${EXTRACT_SCRIPT}"

if [[ ! -f $WASM_SOURCE ]]; then
	echo "[package-verified-core] wasm artifact not found at $WASM_SOURCE" >&2
	exit 1
fi

install -m 0644 "$WASM_SOURCE" "$ARTIFACT_DIR/verified_core.wasm"

sha256=$(sha256sum "$ARTIFACT_DIR/verified_core.wasm" | awk '{print $1}')
printf '%s  verified_core.wasm\n' "$sha256" >"$ARTIFACT_DIR/verified_core.wasm.sha256"

sri_payload=$(openssl dgst -sha256 -binary "$ARTIFACT_DIR/verified_core.wasm" | openssl base64 -A | tr -d '\n\r')
printf 'sha256-%s\n' "$sri_payload" >"$ARTIFACT_DIR/verified_core.wasm.sri"

size_bytes=$(stat -c%s "$ARTIFACT_DIR/verified_core.wasm")
timestamp_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
commit_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{
  "artifact": "verified_core.wasm",
  "size_bytes": ${size_bytes},
  "sha256": "${sha256}",
  "sri": "sha256-${sri_payload}",
  "generated_at": "${timestamp_utc}",
  "source_commit": "${commit_sha}",
  "abi_version": 1,
  "modules": [
    "Pkce.Challenge",
    "Pkce.Verifier",
    "Pkce.Method_selection",
    "Pkce.Verification",
    "Dpop.Ath_validation",
    "Dpop.Claims",
    "Dpop.Header",
    "Dpop.Htm_validation",
    "Dpop.Htu_validation",
    "Dpop.Iat_validation",
    "Dpop.Replay",
    "Dpop.Signature",
    "Dpop.Token_binding",
    "Dpop.Validation",
    "VerifiedCore.Api.Claims.Runtime",
    "ConstTime"
  ]
}
EOF

# Optional: sign the artifact if a signing key is available
SIGN_SCRIPT="$ROOT/scripts/sdk/sign_core_artifact.js"
SIGNING_KEY="${VC_SIGNING_KEY:-$ROOT/keys/verified-core-dev.key}"

if [[ -f $SIGN_SCRIPT && -f $SIGNING_KEY ]]; then
	echo "[package-verified-core] Signing artifact with Ed25519..."
	node "$SIGN_SCRIPT" \
		--wasm "$ARTIFACT_DIR/verified_core.wasm" \
		--private-key "$SIGNING_KEY" \
		--out-signature "$ARTIFACT_DIR/verified_core.wasm.sig" \
		--manifest "$ARTIFACT_DIR/manifest.json" \
		--update-manifest
elif [[ -f $SIGN_SCRIPT ]]; then
	echo "[package-verified-core] Signing key not found at $SIGNING_KEY; skipping signature."
	echo "[package-verified-core] Set VC_SIGNING_KEY or place key at keys/verified-core-dev.key"
fi

echo "[package-verified-core] staged verified_core.wasm in $ARTIFACT_DIR"
