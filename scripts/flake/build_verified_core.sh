#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

echo "[verified-core] Building via Nix..."
nix build .#verified-core-wasm --print-build-logs

WASM_SRC="./result/wasm/verified_core.wasm"
ABI_SRC="$ROOT/generated/lowstar/verified-core/verified_core.abi.json"
SDK_DEST="$ROOT/tests/fixtures/verified-core"
DIST_DEST="$ROOT/artifacts/verified-core"
VERSION_ARG=()
SIGNING_ARG=()

if [[ -n ${AEG_VERIFIED_CORE_VERSION:-} ]]; then
	VERSION_ARG=(--version "$AEG_VERIFIED_CORE_VERSION")
fi

if [[ -n ${AEG_VERIFIED_CORE_SIGNING_KEY_PATH:-} ]]; then
	SIGNING_ARG=(--private-key "$AEG_VERIFIED_CORE_SIGNING_KEY_PATH")
fi

copy_replace() {
	local src="$1"
	local dst="$2"
	if [ -e "$dst" ]; then
		chmod u+w "$dst" 2>/dev/null || true
		rm -f "$dst"
	fi
	install -m 0644 "$src" "$dst"
}

if [ ! -f "$WASM_SRC" ]; then
	echo "[verified-core] Build failed - WASM not found" >&2
	exit 1
fi

if [ ! -f "$ABI_SRC" ]; then
	echo "[verified-core] ABI not found: $ABI_SRC" >&2
	exit 1
fi

mkdir -p "$DIST_DEST"
copy_replace "$WASM_SRC" "$DIST_DEST/verified_core.wasm"

echo "[verified-core] Packaging distribution artefacts..."
node scripts/sdk/package_verified_core_dist.js \
	--out "$DIST_DEST" \
	--wasm "$WASM_SRC" \
	--abi "$ABI_SRC" \
	"${VERSION_ARG[@]}" \
	"${SIGNING_ARG[@]}"

mkdir -p "$SDK_DEST"
for file in \
	verified_core.wasm \
	manifest.json \
	verified_core.wasm.sha256 \
	verified_core.wasm.sha512 \
	verified_core.wasm.sri; do
	copy_replace "$DIST_DEST/$file" "$SDK_DEST/$file"
done

if [ -f "$DIST_DEST/verified_core.wasm.sig" ]; then
	copy_replace "$DIST_DEST/verified_core.wasm.sig" "$SDK_DEST/verified_core.wasm.sig"
elif [ -f "$SDK_DEST/verified_core.wasm.sig" ]; then
	rm -f "$SDK_DEST/verified_core.wasm.sig"
fi

echo "[verified-core] Copied packaged artefacts to $DIST_DEST"
echo "[verified-core] Synced test fixtures to $SDK_DEST"
echo "[verified-core] WASM size: $(stat -c%s "$DIST_DEST/verified_core.wasm") bytes"
