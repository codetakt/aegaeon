#!/usr/bin/env bash
#
# Prototype extractor for the Verified Core (PKCE / DPoP / JWT) Low* modules.
# This is a scaffold for Sprint A (see docs/specs/verified-core-wasm.md).
#
# Current behaviour:
#   - Validates required toolchain (F*, KaRaMeL).
#   - Prints the canonical module list that will be extracted.
#   - Creates the output staging directories (no krml emission yet).
# TODO:
#   - Invoke fstar.exe with --codegen krml for MODULES[@].
#   - Link EverCrypt + krmllib includes as in run_jose_lowstar.sh.
#   - Emit C sources under generated/lowstar/verified-core/.
#   - Wire into nix build .#verified-core-wasm.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FSTAR_BIN=${FSTAR:-$(command -v fstar.exe || command -v fstar || echo "")}
if [[ -z $FSTAR_BIN ]]; then
	echo "[error] fstar.exe not found. Launch via 'nix develop .#verification' or set FSTAR." >&2
	exit 1
fi

KAMEL_BIN=${KAMEL:-$(command -v kamel || command -v krml || echo "")}
if [[ -z $KAMEL_BIN ]]; then
	echo "[error] KaRaMeL (kamel/krml) not found. Enter the verification shell or set KAMEL." >&2
	exit 1
fi

OUT_DIR="$ROOT/generated/lowstar/verified-core"
TMP_DIR="$(mktemp -d /tmp/aegaeon-verified-core.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$OUT_DIR"

declare -a MODULE_DIRS=(pkce dpop verifiedcore/api)
declare -a EXTRA_MODULES=(
	"ConstTime.fst"
	"crypto/Verified.Crypto.Bridge.fst"
)

declare -a MODULES_FSTI=()
declare -a MODULES_FST=()
declare -A HAS_FSTI=()

for dir in "${MODULE_DIRS[@]}"; do
	while IFS= read -r file; do
		rel="${file#./}"
		MODULES_FSTI+=("fstar/$rel")
		base="fstar/${rel%.fsti}"
		HAS_FSTI["$base"]=1
	done < <(cd "fstar" && find "$dir" -type f -name '*.fsti' | sort)
	while IFS= read -r file; do
		MODULES_FST+=("fstar/${file#./}")
	done < <(cd "fstar" && find "$dir" -type f -name '*.fst' | sort)
done

for extra in "${EXTRA_MODULES[@]}"; do
	if [[ -f "fstar/$extra" ]]; then
		MODULES_FST+=("fstar/$extra")
	fi
	if [[ -f "fstar/${extra}i" ]]; then
		MODULES_FSTI+=("fstar/${extra}i")
		base="fstar/${extra%.fst}"
		HAS_FSTI["$base"]=1
	fi
done

declare -a MODULES=()
declare -A SEEN=()
for file in "${MODULES_FSTI[@]}" "${MODULES_FST[@]}"; do
	base="${file%.fst}"
	if [[ ${file} == *.fst && -n ${HAS_FSTI[$base]:-} ]]; then
		continue
	fi
	if [[ -z ${SEEN[$file]:-} ]]; then
		MODULES+=("$file")
		SEEN[$file]=1
	fi
done

echo "[verified-core] F* binary : $FSTAR_BIN"
echo "[verified-core] KaRaMeL   : $KAMEL_BIN"
echo "[verified-core] Output dir : $OUT_DIR"
echo "[verified-core] Staging    : $TMP_DIR"
echo "[verified-core] Planned modules:"
for m in "${MODULES[@]}"; do
	printf '  - %s\n' "$m"
done

CACHE_DIR="$ROOT/fstar/.cache"
mkdir -p "$CACHE_DIR"

declare -a INCLUDE_FLAGS=(
	--include "$ROOT/fstar"
	--include "$ROOT/fstar/verifiedcore/api"
)

if [[ -z ${EVERCRYPT_SRC_DIR:-} ]]; then
	while IFS= read -r candidate; do
		if [[ -d "$candidate/share/evercrypt/providers" ]]; then
			EVERCRYPT_SRC_DIR="$candidate/share/evercrypt"
			break
		fi
	done < <(ls -d /nix/store/*evercrypt* 2>/dev/null | sort -r)
fi

if [[ -n ${EVERCRYPT_SRC_DIR:-} && -d ${EVERCRYPT_SRC_DIR} ]]; then
	while IFS= read -r dir; do
		INCLUDE_FLAGS+=(--include "$dir")
	done < <(
		find "$EVERCRYPT_SRC_DIR" -maxdepth 2 -type d \
			\( -path "*/providers/fst" -o -path "*/specs" -o -path "*/specs/lemmas" -o -path "*/code" \)
	)
fi

KAMEL_ROOT="$(dirname "$(dirname "$(readlink -f "$KAMEL_BIN")")")"
if [[ -d "$KAMEL_ROOT/lib/krml" ]]; then
	INCLUDE_FLAGS+=(--include "$KAMEL_ROOT/lib/krml")
fi

# HACL* F* sources
if [[ -z ${HACL_FSTAR_PATH:-} ]]; then
	while IFS= read -r candidate; do
		if [[ -d "$candidate/share/hacl-star/fstar" ]]; then
			HACL_FSTAR_PATH="$candidate/share/hacl-star/fstar"
			break
		fi
	done < <(ls -d /nix/store/*hacl-star* 2>/dev/null | sort -r)
fi

if [[ -n ${HACL_FSTAR_PATH:-} && -d ${HACL_FSTAR_PATH} ]]; then
	INCLUDE_FLAGS+=(--include "$HACL_FSTAR_PATH")
fi

# Generated EverParse artefacts (JoseHeader, etc.)
if [[ -z ${EVERPARSE_PREFIX:-} ]]; then
	while IFS= read -r candidate; do
		if [[ -d "$candidate/share/everparse" ]]; then
			EVERPARSE_PREFIX="$candidate"
			break
		fi
	done < <(ls -d /nix/store/*everparse* 2>/dev/null | sort -r)
fi

if [[ -n ${EVERPARSE_PREFIX:-} ]]; then
	if [[ -d "$EVERPARSE_PREFIX/share/everparse" ]]; then
		while IFS= read -r dir; do
			INCLUDE_FLAGS+=(--include "$dir")
		done < <(find "$EVERPARSE_PREFIX/share/everparse" -maxdepth 3 -type d | sort)
	fi
	if [[ -d "$EVERPARSE_PREFIX/src/3d" ]]; then
		while IFS= read -r dir; do
			INCLUDE_FLAGS+=(--include "$dir")
		done < <(find "$EVERPARSE_PREFIX/src/3d" -maxdepth 3 -type d | sort)
	fi
	if [[ -d "$EVERPARSE_PREFIX/lib/lowparse" ]]; then
		while IFS= read -r dir; do
			INCLUDE_FLAGS+=(--include "$dir")
		done < <(find "$EVERPARSE_PREFIX/lib/lowparse" -maxdepth 2 -type d | sort)
	fi
fi

echo "[verified-core] Running F* to generate .krml files..."
set +e
"$FSTAR_BIN" \
	--codegen krml \
	--odir "$TMP_DIR" \
	--cache_dir "$CACHE_DIR" \
	--cache_checked_modules \
	--warn_error -274 \
	"${INCLUDE_FLAGS[@]}" \
	"${MODULES[@]}"
status=$?
set -e

if [[ $status -ne 0 ]]; then
	echo "[verified-core] F* invocation failed (exit $status). Inspect output above." >&2
	exit $status
fi

krml_files=()
while IFS= read -r file; do
	krml_files+=("$file")
done < <(find "$TMP_DIR" -maxdepth 1 -name '*.krml')

if [[ ${#krml_files[@]} -eq 0 ]]; then
	echo "[verified-core] No .krml files generated; check F* output." >&2
	exit 1
fi

mkdir -p "$OUT_DIR/krml"
for file in "${krml_files[@]}"; do
	cp "$file" "$OUT_DIR/krml/"
done

echo "[verified-core] Generated ${#krml_files[@]} .krml files in $OUT_DIR/krml/."

KAMEL_TMP="$TMP_DIR/kamel"
mkdir -p "$KAMEL_TMP"

declare -a KAMEL_INPUTS=("${krml_files[@]}")

echo "[verified-core] Translating to C via KaRaMeL..."
"$KAMEL_BIN" \
	-tmpdir "$KAMEL_TMP" \
	-skip-linking \
	-skip-compilation \
	-warn-error -2-9 \
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
	"${KAMEL_INPUTS[@]}"

if [[ ! -d $KAMEL_TMP ]]; then
	echo "[verified-core] KaRaMeL did not produce output in $KAMEL_TMP" >&2
	exit 1
fi

mkdir -p "$OUT_DIR/c"
shopt -s nullglob
for artifact in "$KAMEL_TMP"/*; do
	base="$(basename "$artifact")"
	case "$base" in
	Makefile.basic | Makefile.include) continue ;;
	krmlinit.c | krmlinit.h) continue ;;
	*) cp -R "$artifact" "$OUT_DIR/c/$base" ;;
	esac
done
shopt -u nullglob

echo "[verified-core] KaRaMeL artifacts written to $OUT_DIR/c/."

# Include shim exports (provides VerifiedCore_* symbols)
if [[ -f "$ROOT/c/verified-core/verified_core_exports.c" ]]; then
	cp "$ROOT/c/verified-core/verified_core_exports.c" "$OUT_DIR/c/verified_core_exports.c"
fi
if [[ -f "$ROOT/c/verified-core/verified_core_exports.h" ]]; then
	cp "$ROOT/c/verified-core/verified_core_exports.h" "$OUT_DIR/c/verified_core_exports.h"
fi

# Include vc_* public ABI shim
if [[ -f "$ROOT/c/verified_core.c" ]]; then
	cp "$ROOT/c/verified_core.c" "$OUT_DIR/c/verified_core.c"
fi
if [[ -f "$ROOT/include/verified_core.h" ]]; then
	cp "$ROOT/include/verified_core.h" "$OUT_DIR/c/verified_core.h"
fi

if [[ -n ${WITH_WASM_BUILD:-} ]]; then
	echo "[verified-core] WITH_WASM_BUILD=1 set; attempting wasm32-wasi compilation..."
	WASI_CLANG_BIN="${WASI_CLANG:-}"
	if [[ -z $WASI_CLANG_BIN || ! -x $WASI_CLANG_BIN ]]; then
		if command -v wasm32-unknown-wasi-clang >/dev/null 2>&1; then
			WASI_CLANG_BIN="$(command -v wasm32-unknown-wasi-clang)"
		else
			candidate="$(
				find /nix/store -maxdepth 2 -name 'wasm32-unknown-wasi-clang' 2>/dev/null |
					head -n1 || true
			)"
			if [[ -n $candidate && -x $candidate ]]; then
				WASI_CLANG_BIN="$candidate"
			fi
		fi
	fi
	if [[ -z $WASI_CLANG_BIN ]]; then
		echo "[verified-core] no clang available (set WASI_CLANG or install wasm32-wasi toolchain)." >&2
		exit 1
	fi

	SYSROOT="${WASI_SYSROOT:-}"
	if [[ -z $SYSROOT ]]; then
		candidate_sysroot="$(
			find /nix/store -maxdepth 1 -type d -name '*-wasi-sysroot' 2>/dev/null |
				head -n1 || true
		)"
		if [[ -n $candidate_sysroot ]]; then
			SYSROOT="$candidate_sysroot"
		fi
	fi
	if [[ -z $SYSROOT ]]; then
		echo "[verified-core] warning: WASI_SYSROOT not set; system headers may not resolve." >&2
	elif [[ ! -d $SYSROOT ]]; then
		echo "[verified-core] warning: WASI_SYSROOT='$SYSROOT' does not exist; ignoring." >&2
		SYSROOT=""
	fi

	WASM_OUT="${OUT_DIR}/wasm"
	mkdir -p "$WASM_OUT"
	mapfile -t c_sources < <(find "$OUT_DIR/c" -maxdepth 1 -name '*.c' | sort)
	if [[ ${#c_sources[@]} -eq 0 ]]; then
		echo "[verified-core] No C sources found under $OUT_DIR/c; skipping wasm build." >&2
	else
		compile_flags=(
			--target=wasm32-unknown-wasi
			-O2
			-flto
			-nostdlib
			-fvisibility=hidden
			"-I$OUT_DIR/c"
			"-I$OUT_DIR/c/internal"
		)
		if [[ -z $SYSROOT || ! -f "$SYSROOT/include/assert.h" ]]; then
			stub_include="$ROOT/c/wasi-stubs"
			compile_flags+=(-isystem "$stub_include")
		fi
		krml_include="$(dirname "$(dirname "$KAMEL_BIN")")/include"
		if [[ -d $krml_include ]]; then
			compile_flags+=("-I$krml_include")
		fi
		krml_lib_root="$(dirname "$(dirname "$KAMEL_BIN")")/lib/krml"
		if [[ -d "$krml_lib_root/c" ]]; then
			compile_flags+=("-I$krml_lib_root/c")
		fi
		for dist_dir in "$krml_lib_root/dist/minimal" "$krml_lib_root/dist/generic"; do
			if [[ -d $dist_dir ]]; then
				compile_flags+=("-I$dist_dir")
			fi
		done
		if [[ -n $SYSROOT ]]; then
			compile_flags+=("--sysroot" "$SYSROOT")
			if [[ -d "$SYSROOT/lib" ]]; then
				compile_flags+=("-L$SYSROOT/lib")
			fi
		fi
		ld_flags=(
			-Wl,--allow-undefined
			-Wl,--export-all
			-Wl,--no-entry
			-Wl,--strip-all
			-Wl,--gc-sections
		)
		"$WASI_CLANG_BIN" \
			"${compile_flags[@]}" \
			"${c_sources[@]}" \
			"${ld_flags[@]}" \
			-o "$WASM_OUT/verified_core.wasm"
		if [[ -f "$WASM_OUT/verified_core.wasm" ]]; then
			echo "[verified-core] wasm artifact: $WASM_OUT/verified_core.wasm"
		else
			echo "[verified-core] clang invocation failed to produce wasm output." >&2
			exit 1
		fi
	fi
fi
