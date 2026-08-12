#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

source "$ROOT/scripts/extraction/lib/everparse_postprocess.sh"

OUT_DIR="$ROOT/generated/everparse"
mkdir -p "$OUT_DIR"

SCHEMAS=(
	"fstar/lowparse/JoseHeader.3d"
	"fstar/lowparse/DCR.3d"
	"fstar/lowparse/DcrRegistration.3d"
	"fstar/lowparse/IdTokenSchema.3d"
	"fstar/lowparse/LogoutTokenSchema.3d"
	"fstar/lowparse/RequestObjectSchema.3d"
	"fstar/lowparse/Dpop.3d"
)

for schema in "${SCHEMAS[@]}"; do
	if [[ ! -f $schema ]]; then
		echo "[error] EverParse schema not found: $schema" >&2
		exit 1
	fi
done

if ! command -v nix >/dev/null 2>&1; then
	echo "[error] nix is required (run via Nix flake: nix develop .#verification)" >&2
	exit 1
fi

echo "[everparse] Using Nix-pinned EverParse toolchain"

export AEG_EVERPARSE_OUT_DIR="$OUT_DIR"

nix develop .#verification --command bash -lc '
  set -euo pipefail
  ROOT="$(git rev-parse --show-toplevel)"
  cd "$ROOT"

  OUT_DIR="${AEG_EVERPARSE_OUT_DIR:?}"
  mkdir -p "$OUT_DIR"

  EVERPARSE_BIN=$(command -v everparse)
  KRML_BIN=$(command -v krml)

  # EverParse expects:
  #   - $(KRML_HOME)/krml
  #   - $(KRML_HOME)/krmllib (and /obj)
  # In Nix, KaRaMeL ships krml under bin/ and F* libs under lib/krml, while our
  # EverParse derivation vendors a krmllib layout. Bridge this with a temp home.
  KRML_HOME_TMP=$(mktemp -d /tmp/aeg-krml-home.XXXXXX)
  trap "rm -rf \"$KRML_HOME_TMP\"" EXIT

  ln -s "$KRML_BIN" "$KRML_HOME_TMP/krml"

  EVERPARSE_ROOT=$(dirname "$(dirname "$(readlink -f "$EVERPARSE_BIN")")")
  ln -s "$EVERPARSE_ROOT/krmllib" "$KRML_HOME_TMP/krmllib"

  export KRML_HOME="$KRML_HOME_TMP"

  everparse \
    --odir generated/everparse \
    --batch \
    --skip_c_makefiles \
    --no_clang_format \
    fstar/lowparse/JoseHeader.3d \
    fstar/lowparse/DCR.3d \
    fstar/lowparse/DcrRegistration.3d \
    fstar/lowparse/IdTokenSchema.3d \
    fstar/lowparse/LogoutTokenSchema.3d \
    fstar/lowparse/RequestObjectSchema.3d \
    fstar/lowparse/Dpop.3d
'

nix develop .#verification --command bash -lc '
  set -euo pipefail
  cd "$(git rev-parse --show-toplevel)"
  source scripts/extraction/lib/everparse_postprocess.sh
  postprocess_everparse_dir "${AEG_EVERPARSE_OUT_DIR:?}"
'

echo "[everparse] Generated artefacts under $OUT_DIR"
