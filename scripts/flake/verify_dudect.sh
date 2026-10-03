#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"
: "${EVERCRYPT_DIST:?EVERCRYPT_DIST not set}"

for required_input in c/dudect_harness.c c/dudect.h; do
	if [ ! -f "$required_input" ]; then
		echo "Required dudect input not found: $required_input" >&2
		exit 1
	fi
done

KARAMEL_BIN="$(command -v krml || true)"
if [ -z "$KARAMEL_BIN" ]; then
	echo "krml not found in PATH; Karamel include headers are required" >&2
	exit 1
fi
KARAMEL_BIN_DIR="$(dirname "$KARAMEL_BIN")"
KARAMEL_HOME="$(cd "$KARAMEL_BIN_DIR/.." && pwd)"
KARAMEL_INC="$KARAMEL_HOME/include"
KARAMEL_C="$KARAMEL_HOME/lib/krml/c"
KARAMEL_DIST="$KARAMEL_HOME/lib/krml/dist/generic"
INC="$EVERCRYPT_DIST/include"
LIB="$EVERCRYPT_DIST/lib"
if ! rm -f -- dudect_test; then
	echo "Unable to remove prior dudect compiler output: dudect_test" >&2
	exit 1
fi
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
if [ ! -f dudect_test ] || [ ! -s dudect_test ] || [ ! -x dudect_test ]; then
	echo "Required dudect compiler output is not a nonempty executable file: dudect_test" >&2
	exit 1
fi
./dudect_test | tee "$OUT_DIR/dudect.log"
