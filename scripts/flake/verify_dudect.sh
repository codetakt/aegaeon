#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"
: "${EVERCRYPT_DIST:?EVERCRYPT_DIST not set}"

if [ -f c/dudect_harness.c ]; then
	KARAMEL_BIN="$(command -v krml || true)"
	if [ -z "$KARAMEL_BIN" ]; then
		echo "krml not found in PATH; Karamel include headers are required" >&2
		exit 1
	fi
	KARAMEL_HOME="$(cd "$(dirname "$KARAMEL_BIN")/.." && pwd)"
	KARAMEL_INC="$KARAMEL_HOME/include"
	KARAMEL_C="$KARAMEL_HOME/lib/krml/c"
	KARAMEL_DIST="$KARAMEL_HOME/lib/krml/dist/generic"
	INC="$EVERCRYPT_DIST/include"
	LIB="$EVERCRYPT_DIST/lib"
	clang -O2 \
		-Ic \
		-I "$INC" \
		-I "$KARAMEL_INC" \
		-I "$KARAMEL_C" \
		-I "$KARAMEL_DIST" \
		c/dudect_harness.c \
		-L "$LIB" \
		-levercrypt \
		-lm \
		-o dudect_test
	./dudect_test | tee "$OUT_DIR/dudect.log"
else
	echo "c/dudect_harness.c not found; skipping dudect" >&2
fi
