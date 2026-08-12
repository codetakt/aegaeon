#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/everparse_postprocess.sh"

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FSTAR_BIN=${FSTAR:-$(command -v fstar.exe || command -v fstar || echo "")}
if [[ -z $FSTAR_BIN ]]; then
	echo "[error] fstar.exe not found in PATH." \
		"Launch via 'nix develop .#verification' or set FSTAR variable." >&2
	exit 1
fi

EVERPARSE_BIN=${EVERPARSE:-$(command -v everparse || command -v 3d || echo "")}
if [[ -z $EVERPARSE_BIN ]]; then
	if [[ -x "$ROOT/result/bin/everparse" ]]; then
		EVERPARSE_BIN="$ROOT/result/bin/everparse"
	else
		echo "[error] everparse (3d) binary not found." \
			"Run 'nix build .#everparse' or set EVERPARSE variable." >&2
		exit 1
	fi
fi

EVERPARSE_ROOT="$(dirname "$(dirname "$(readlink -f "$EVERPARSE_BIN")")")"

# Allow callers to override the root that contains the EverParse F* sources.
EVERPARSE_SOURCE_ROOT="${EVERPARSE_SOURCE_ROOT:-}"
if [[ -z $EVERPARSE_SOURCE_ROOT ]]; then
	# Scan for a sibling derivation that ships the src/ tree (e.g., ...-source)
	while IFS= read -r candidate; do
		if [[ -d "$candidate/src/3d/prelude" ]]; then
			EVERPARSE_SOURCE_ROOT="$candidate"
			break
		fi
	done < <(ls -d "$(dirname "$EVERPARSE_ROOT")"/*everparse-* 2>/dev/null)
fi

if [[ -z $EVERPARSE_SOURCE_ROOT ]]; then
	EVERPARSE_SOURCE_ROOT="$EVERPARSE_ROOT"
fi

EVERPARSE_SHARE="$EVERPARSE_SOURCE_ROOT/share/everparse"
EVERPARSE_LIB="$EVERPARSE_SOURCE_ROOT/lib"

if [[ ! -d $EVERPARSE_SHARE ]]; then
	echo "[warn] EverParse share directory not found under $EVERPARSE_SOURCE_ROOT/share" >&2
fi

declare -a EVERPARSE_INCLUDE_DIRS=()
declare -a EVERPARSE_INCLUDE_FLAGS=()
declare -a EVERCRYPT_INCLUDE_DIRS=()
declare -a LOWPARSE_SOURCE_DIRS=()
declare -a LOWSTAR_EVERPARSE_INCLUDE_DIRS=()
declare -a LOWSTAR_EVERPARSE_INCLUDE_FLAGS=()

count_checked_files() {
	find "$1" \
		\( -name '*.fst.checked' -o -name '*.fsti.checked' \) |
		wc -l
}

delete_checked_files() {
	find "$1" \
		\( -name '*.fst.checked' -o -name '*.fsti.checked' \) \
		-delete
}

copy_checked_files() {
	find "$1" \
		\( -name '*.fst.checked' -o -name '*.fsti.checked' \) \
		-exec cp -n {} "$2"/ \; 2>/dev/null
}

build_everparse_includes() {
	EVERPARSE_INCLUDE_DIRS=()
	EVERPARSE_INCLUDE_FLAGS=()

	# EverParse vendoring directories for F* extraction
	# Ordered by dependency: prelude components first, then LowParse
	for candidate in \
		"$EVERPARSE_SHARE" \
		"$EVERPARSE_SHARE/prelude" \
		"$EVERPARSE_SHARE/prelude/buffer" \
		"$EVERPARSE_SHARE/prelude/extern" \
		"$EVERPARSE_SOURCE_ROOT/src/3d/prelude" \
		"$EVERPARSE_SOURCE_ROOT/src/3d/prelude/buffer" \
		"$EVERPARSE_SOURCE_ROOT/src/lowparse" \
		"$EVERPARSE_LIB/lowparse" \
		"$EVERPARSE_LIB/lowparse/LowParse" \
		"$EVERPARSE_LIB/lowparse/Spec" \
		"$EVERPARSE_LIB/lowparse/LPC" \
		"$EVERPARSE_SOURCE_ROOT/krmllib" \
		"$EVERPARSE_SOURCE_ROOT/krmllib/obj"; do
		if [[ -d $candidate ]]; then
			EVERPARSE_INCLUDE_DIRS+=("$candidate")
			EVERPARSE_INCLUDE_FLAGS+=(--include "$candidate")
			echo "[everparse] Added include directory: $candidate"
		fi
	done

	if [[ ${#EVERPARSE_INCLUDE_DIRS[@]} -eq 0 ]]; then
		echo "[warn] EverParse vendoring directories not found under" \
			"$EVERPARSE_ROOT; proceeding without extra includes" >&2
		echo "[warn] Expected paths:" >&2
		echo "  - $EVERPARSE_SHARE" >&2
		echo "  - $EVERPARSE_SHARE/prelude" >&2
		echo "  - $EVERPARSE_LIB/lowparse" >&2
	else
		echo "[everparse] Configured ${#EVERPARSE_INCLUDE_DIRS[@]} include" \
			"directories for F* extraction"
	fi
}

build_hint_args() {
	local prefix="$1"
	local -n out_ref="$2"
	shift 2

	local hint_dir="${ROOT}/fstar/.hints"
	local -a missing=()

	out_ref=()

	for source in "$@"; do
		local hint_file="${hint_dir}/$(basename "$source").hints"
		if [[ ! -f $hint_file ]]; then
			missing+=("$(basename "$hint_file")")
		fi
	done

	if [[ ${#missing[@]} -eq 0 ]]; then
		out_ref=(--use_hints --hint_dir "$hint_dir")
		return
	fi

	printf '%s Skipping --use_hints; missing hint files: %s\n' \
		"$prefix" \
		"${missing[*]}"
}

if [[ -d "$EVERPARSE_SOURCE_ROOT/src/lowparse" ]]; then
	LOWPARSE_SOURCE_DIRS+=("$EVERPARSE_SOURCE_ROOT/src/lowparse")
fi
if [[ -d "$EVERPARSE_LIB/lowparse" ]]; then
	LOWPARSE_SOURCE_DIRS+=("$EVERPARSE_LIB/lowparse")
fi

LOWPARSE_LOCAL_DIR=""
USE_LOWPARSE_LOCAL="${AEG_USE_LOWPARSE_LOCAL:-0}"
PRIME_LOWPARSE_CACHE="${AEG_PRIME_LOWPARSE_CACHE:-0}"
USE_EVERPARSE_LOCAL="${AEG_USE_EVERPARSE_LOCAL:-0}"
EVERPARSE_LOCAL_ROOT=""
if [[ -n ${LOWPARSE_LOCAL_ROOT:-} ]]; then
	USE_LOWPARSE_LOCAL=1
fi
if [[ $USE_EVERPARSE_LOCAL == "1" ]]; then
	USE_LOWPARSE_LOCAL=1
fi
if [[ ${#LOWPARSE_SOURCE_DIRS[@]} -gt 0 && $USE_LOWPARSE_LOCAL == "1" ]]; then
	LOWPARSE_LOCAL_DIR="${LOWPARSE_LOCAL_ROOT:-/tmp/aegaeon-lowparse}"
	rm -rf "$LOWPARSE_LOCAL_DIR"
	mkdir -p "$LOWPARSE_LOCAL_DIR"
	cp -a "${LOWPARSE_SOURCE_DIRS[0]}/." "$LOWPARSE_LOCAL_DIR/"
	chmod -R u+rwX "$LOWPARSE_LOCAL_DIR"
	delete_checked_files "$LOWPARSE_LOCAL_DIR"
	echo "[lowparse] Using local LowParse copy at $LOWPARSE_LOCAL_DIR" \
		"(source: ${LOWPARSE_SOURCE_DIRS[0]})"
fi

if [[ $USE_EVERPARSE_LOCAL == "1" ]]; then
	EVERPARSE_LOCAL_ROOT="${AEG_EVERPARSE_LOCAL_ROOT:-/tmp/aegaeon-everparse}"
	rm -rf "$EVERPARSE_LOCAL_ROOT"
	mkdir -p "$EVERPARSE_LOCAL_ROOT/src" "$EVERPARSE_LOCAL_ROOT/lib"
	if [[ -d "$EVERPARSE_SOURCE_ROOT/src/3d" ]]; then
		ln -s "$EVERPARSE_SOURCE_ROOT/src/3d" "$EVERPARSE_LOCAL_ROOT/src/3d"
	fi
	if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
		ln -s "$LOWPARSE_LOCAL_DIR" "$EVERPARSE_LOCAL_ROOT/src/lowparse"
	elif [[ ${#LOWPARSE_SOURCE_DIRS[@]} -gt 0 ]]; then
		cp -a "${LOWPARSE_SOURCE_DIRS[0]}/." "$EVERPARSE_LOCAL_ROOT/src/lowparse"
		delete_checked_files "$EVERPARSE_LOCAL_ROOT/src/lowparse"
	fi
	if [[ -d "$EVERPARSE_LOCAL_ROOT/src/lowparse" ]]; then
		ln -s "$EVERPARSE_LOCAL_ROOT/src/lowparse" "$EVERPARSE_LOCAL_ROOT/lib/lowparse"
	fi
	if [[ -d "$EVERPARSE_SOURCE_ROOT/share" ]]; then
		ln -s "$EVERPARSE_SOURCE_ROOT/share" "$EVERPARSE_LOCAL_ROOT/share"
	fi
	if [[ -d "$EVERPARSE_SOURCE_ROOT/krmllib" ]]; then
		ln -s "$EVERPARSE_SOURCE_ROOT/krmllib" "$EVERPARSE_LOCAL_ROOT/krmllib"
	fi
	EVERPARSE_SOURCE_ROOT="$EVERPARSE_LOCAL_ROOT"
	EVERPARSE_SHARE="$EVERPARSE_SOURCE_ROOT/share/everparse"
	EVERPARSE_LIB="$EVERPARSE_SOURCE_ROOT/lib"
	echo "[everparse] Using local EverParse tree at $EVERPARSE_SOURCE_ROOT"
fi

export EVERPARSE_HOME="$EVERPARSE_SOURCE_ROOT"
build_everparse_includes

for dir in "${EVERPARSE_INCLUDE_DIRS[@]}"; do
	if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
		skip=false
		for src in "${LOWPARSE_SOURCE_DIRS[@]}"; do
			if [[ $dir == "$src"* ]]; then
				skip=true
				break
			fi
		done
		if ! $skip; then
			LOWSTAR_EVERPARSE_INCLUDE_DIRS+=("$dir")
		fi
	else
		LOWSTAR_EVERPARSE_INCLUDE_DIRS+=("$dir")
	fi
done

if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
	add_lowparse=true
	for dir in "${LOWSTAR_EVERPARSE_INCLUDE_DIRS[@]}"; do
		if [[ $dir == "$LOWPARSE_LOCAL_DIR" ]]; then
			add_lowparse=false
			break
		fi
	done
	if $add_lowparse; then
		LOWSTAR_EVERPARSE_INCLUDE_DIRS+=("$LOWPARSE_LOCAL_DIR")
	fi
fi
for dir in "${LOWSTAR_EVERPARSE_INCLUDE_DIRS[@]}"; do
	LOWSTAR_EVERPARSE_INCLUDE_FLAGS+=(--include "$dir")
done

if [[ -z ${EVERCRYPT_SRC_DIR:-} ]]; then
	while IFS= read -r candidate; do
		if [[ -d "$candidate/share/evercrypt/providers" ]]; then
			EVERCRYPT_SRC_DIR="$candidate/share/evercrypt"
			break
		fi
	done < <(ls -d /nix/store/*evercrypt* 2>/dev/null | sort -r)
fi

if [[ -n ${EVERCRYPT_SRC_DIR:-} && -d ${EVERCRYPT_SRC_DIR} ]]; then
	for candidate in \
		"$EVERCRYPT_SRC_DIR/providers" \
		"$EVERCRYPT_SRC_DIR/providers/fst" \
		"$EVERCRYPT_SRC_DIR/specs" \
		"$EVERCRYPT_SRC_DIR/specs/lemmas"; do
		if [[ -d $candidate ]]; then
			EVERCRYPT_INCLUDE_DIRS+=("$candidate")
			echo "[evercrypt] Added include directory: $candidate"
		fi
	done
	if [[ -d "$EVERCRYPT_SRC_DIR/code" ]]; then
		while IFS= read -r code_dir; do
			if find "$code_dir" -maxdepth 1 -type f \
				\( -name '*.fst' -o -name '*.fsti' \) -print -quit | read -r _; then
				EVERCRYPT_INCLUDE_DIRS+=("$code_dir")
				echo "[evercrypt] Added include directory: $code_dir"
			fi
		done < <(find "$EVERCRYPT_SRC_DIR/code" -maxdepth 1 -mindepth 1 -type d | sort)
	fi
	if [[ ${#EVERCRYPT_INCLUDE_DIRS[@]} -eq 0 ]]; then
		echo "[evercrypt] No include directories discovered under $EVERCRYPT_SRC_DIR" >&2
	fi
else
	echo "[evercrypt] EVERCRYPT_SRC_DIR not set or missing; skipping EverCrypt includes" >&2
fi

KAMEL_BIN=${KAMEL:-$(command -v kamel || command -v krml || echo "")}
if [[ -z $KAMEL_BIN ]]; then
	echo "[error] KaRaMeL (kamel/krml) not found in PATH." \
		"Install KaRaMeL or enter the verification shell." >&2
	exit 1
fi

KAMEL_ROOT="$(dirname "$(dirname "$(readlink -f "$KAMEL_BIN")")")"

OUT_DIR="${ROOT}/generated/lowstar/jose"
TMP_DIR="/tmp/aegaeon-lowstar"
EVERPARSE_STAGE="/tmp/everparse-jose"
IDTOKEN_TMP_DIR="/tmp/idtoken-lowstar"
HASH_TMP_DIR=""

cleanup() {
	rm -rf \
		"$TMP_DIR" \
		"$EVERPARSE_STAGE" \
		"$IDTOKEN_TMP_DIR" \
		"$HASH_TMP_DIR" \
		"$LOWPARSE_LOCAL_DIR" \
		"$EVERPARSE_LOCAL_ROOT"
}

trap cleanup EXIT

rm -rf "$OUT_DIR" "$TMP_DIR" "$EVERPARSE_STAGE" "$IDTOKEN_TMP_DIR"
mkdir -p "$OUT_DIR" "$TMP_DIR" "$EVERPARSE_STAGE" "$IDTOKEN_TMP_DIR"
mkdir -p "$ROOT/fstar/.hints" "$ROOT/fstar/.cache"
CACHE_DIR="$ROOT/fstar/.cache"

if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
	if [[ ${AEG_CLEAR_LOWPARSE_CACHE:-0} == "1" || $PRIME_LOWPARSE_CACHE == "1" ]]; then
		find "$CACHE_DIR" -maxdepth 1 \
			\( -name 'LowParse.*.fst.checked' -o -name 'LowParse.*.fsti.checked' \) \
			-delete
	fi
	if [[ ${AEG_CLEAR_LOWPARSE_CACHE:-0} == "1" ]]; then
		find "$CACHE_DIR" -name 'LowParse*.checked' -delete
	fi
fi

# Export cache dir for any nested F* invocation (including everparse --batch)
export FSTAR_CACHE_DIR="$CACHE_DIR"

UPSTREAM_WARNINGS_LOG_DIR="${AEG_UPSTREAM_WARNINGS_LOG_DIR:-}"
UPSTREAM_WARNINGS_CONTEXT="${AEG_UPSTREAM_WARNINGS_CONTEXT:-2}"
UPSTREAM_WARNINGS_LOG=""
UPSTREAM_WARNINGS_FULL_LOG=""

init_upstream_warning_logging() {
	if [[ -z $UPSTREAM_WARNINGS_LOG_DIR ]]; then
		return
	fi
	mkdir -p "$UPSTREAM_WARNINGS_LOG_DIR"
	UPSTREAM_WARNINGS_LOG="$UPSTREAM_WARNINGS_LOG_DIR/upstream-warnings.log"
	UPSTREAM_WARNINGS_FULL_LOG="$UPSTREAM_WARNINGS_LOG_DIR/upstream-warnings-full.log"
	: >"$UPSTREAM_WARNINGS_LOG"
	: >"$UPSTREAM_WARNINGS_FULL_LOG"
	echo "[warn] Upstream warning capture enabled: $UPSTREAM_WARNINGS_LOG"
}

escape_warning_regex() {
	printf '%s' "$1" | sed -e 's/[.[\\^$*+?{}|()]/\\&/g' -e 's#/#\\/#g'
}

upstream_warning_regex() {
	local regex=""
	local root=""
	for root in "$EVERPARSE_LOCAL_ROOT" "$LOWPARSE_LOCAL_DIR"; do
		if [[ -n $root ]]; then
			local escaped
			escaped=$(escape_warning_regex "$root")
			if [[ -n $regex ]]; then
				regex="${regex}|${escaped}"
			else
				regex="$escaped"
			fi
		fi
	done
	if [[ -z $regex ]]; then
		regex="/tmp/aegaeon-(everparse|lowparse)"
	fi
	printf '%s' "$regex"
}

capture_upstream_warnings() {
	local log_file="$1"
	if [[ -z $UPSTREAM_WARNINGS_LOG ]]; then
		return
	fi
	local regex
	regex="$(upstream_warning_regex)"
	if command -v rg >/dev/null 2>&1; then
		rg -n -C "$UPSTREAM_WARNINGS_CONTEXT" "$regex" "$log_file" >>"$UPSTREAM_WARNINGS_LOG" || true
	else
		grep -n -E "$regex" "$log_file" >>"$UPSTREAM_WARNINGS_LOG" || true
	fi
}

run_with_warning_capture() {
	if [[ -z $UPSTREAM_WARNINGS_LOG_DIR ]]; then
		"$@"
		return
	fi
	local tmp_log
	tmp_log="$(mktemp "${TMPDIR:-/tmp}/aegaeon-upstream-warnings.XXXXXX")"
	set +e
	"$@" 2>&1 | tee -a "$UPSTREAM_WARNINGS_FULL_LOG" | tee "$tmp_log"
	local status=${PIPESTATUS[0]}
	set -e
	capture_upstream_warnings "$tmp_log"
	rm -f "$tmp_log"
	return $status
}

run_fstar() {
	run_with_warning_capture "$FSTAR_BIN" "$@"
}

run_everparse() {
	run_with_warning_capture "$EVERPARSE_BIN" "$@"
}

normalize_karamel_sources() {
	local dir="$1"
	local temp_prefix="${2:-}"

	find "$dir" -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \) | while IFS= read -r file; do
		perl -0pi -e 's{\A/\* }{/*}; s/\n+\z/\n/' "$file"
		if [[ -n $temp_prefix ]]; then
			sed -i -E "s#${temp_prefix}\\.[A-Za-z0-9]+#${temp_prefix}#g" "$file"
		fi
		python3 - "$file" <<-'PY'
			from pathlib import Path
			import re
			import sys
			import textwrap
			path = Path(sys.argv[1])
			text = path.read_text()
			match = re.search(r"^  KaRaMeL invocation: (.+)$", text, re.MULTILINE)
			if match is None: raise SystemExit(0)
			wrapped = textwrap.fill(
			match.group(1),
			width=92,
			initial_indent="    ",
			subsequent_indent="    ",
			break_long_words=False,
			break_on_hyphens=False,
			)
			normalized = (
			text[: match.start()]
			+ "  KaRaMeL invocation:\n"
			+ wrapped
			+ text[match.end() :]
			)
			if normalized != text: path.write_text(normalized)
		PY
	done
}

init_upstream_warning_logging

prime_lowparse_cache() {
	local base_dir="$1"
	local -a fsti_files=()
	local -a fst_files=()

	local -a fstar_args=(
		--cache_checked_modules
		--cache_dir "$CACHE_DIR"
		--odir "$CACHE_DIR"
		--warn_error +241
		--expose_interfaces
		--include "$ROOT/fstar"
	)
	if [[ ${AEG_PRIME_LOWPARSE_ADMIT:-1} == "1" ]]; then
		# LowParse is vendored; we only need fresh .checked files for caching.
		fstar_args+=(--admit_smt_queries true)
	fi
	for dir in "${LOWSTAR_EVERPARSE_INCLUDE_DIRS[@]}"; do
		fstar_args+=(--include "$dir")
	done
	for dir in "${EVERCRYPT_INCLUDE_DIRS[@]}"; do
		fstar_args+=(--include "$dir")
	done

	while IFS= read -r -d '' file; do
		if [[ $file == *"/LowParse.Pulse."* ]]; then
			continue
		fi
		fsti_files+=("$file")
	done < <(find "$base_dir" -maxdepth 1 -type f -name 'LowParse.*.fsti' -print0 | sort -z)

	while IFS= read -r -d '' file; do
		if [[ $file == *"/LowParse.Pulse."* ]]; then
			continue
		fi
		fst_files+=("$file")
	done < <(find "$base_dir" -maxdepth 1 -type f -name 'LowParse.*.fst' -print0 | sort -z)

	local total_files=$((${#fsti_files[@]} + ${#fst_files[@]}))
	if [[ $total_files -gt 0 ]]; then
		echo "[lowparse] Priming cache for LowParse modules" \
			"(${#fsti_files[@]} fsti, ${#fst_files[@]} fst)"
		local batch_size="${AEG_LOWPARSE_BATCH_SIZE:-}"
		if [[ -z $batch_size ]]; then
			if [[ ${AEG_PRIME_LOWPARSE_ADMIT:-1} == "0" ]]; then
				batch_size=1
			else
				batch_size=${#fst_files[@]}
			fi
		fi
		if ! [[ $batch_size =~ ^[0-9]+$ ]]; then
			echo "[lowparse] Invalid AEG_LOWPARSE_BATCH_SIZE=$batch_size; defaulting to full batch" >&2
			batch_size=${#fst_files[@]}
		elif ((batch_size <= 0)); then
			batch_size=${#fst_files[@]}
		fi

		run_lowparse_batches() {
			local label="$1"
			shift
			local -a files=("$@")
			if [[ ${#files[@]} -eq 0 ]]; then
				return
			fi
			if ((batch_size >= ${#files[@]})); then
				run_fstar "${fstar_args[@]}" "${files[@]}"
			else
				echo "[lowparse] Using batch size ${batch_size} for ${label}"
				local idx=0
				while ((idx < ${#files[@]})); do
					run_fstar "${fstar_args[@]}" "${files[@]:idx:batch_size}"
					idx=$((idx + batch_size))
				done
			fi
		}

		run_lowparse_batches "LowParse interfaces (.fsti)" "${fsti_files[@]}"
		run_lowparse_batches "LowParse implementations (.fst)" "${fst_files[@]}"
	fi
}

# LowParse cache priming is opt-in; by default we reuse the upstream .checked
# artifacts to avoid re-verifying the external library.
if [[ -n $LOWPARSE_LOCAL_DIR && $PRIME_LOWPARSE_CACHE == "1" ]]; then
	prime_lowparse_cache "$LOWPARSE_LOCAL_DIR"
fi

# Populate cache directory with vendored .checked files so F* can reuse them
for dir in "${EVERPARSE_INCLUDE_DIRS[@]}"; do
	if [[ -d $dir ]]; then
		if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
			skip=false
			for src in "${LOWPARSE_SOURCE_DIRS[@]}"; do
				if [[ $dir == "$src"* ]]; then
					skip=true
					break
				fi
			done
			if $skip; then
				continue
			fi
		fi
		initial_count=$(count_checked_files "$CACHE_DIR")
		while IFS= read -r checked; do
			cp -n "$checked" "$CACHE_DIR"/
		done < <(find "$dir" \( -name '*.fst.checked' -o -name '*.fsti.checked' \) 2>/dev/null)
		final_count=$(count_checked_files "$CACHE_DIR")
		delta=$((final_count - initial_count))
		if [[ $delta -gt 0 ]]; then
			echo "[cache] Imported $delta .checked files from $dir"
		fi
	fi
done

# ---------------------------------------------------------------------------
# Step 1. Regenerate EverParse artefacts (JoseHeaderEntry parser)
# ---------------------------------------------------------------------------
# Copy .checked files from Nix store to the staging directory so F* can find them
# EverParse internally calls F* with --cache_dir pointing to $EVERPARSE_STAGE,
# so F* will look for .checked files there instead of in the Nix store include paths
echo "[everparse] Copying .checked files to staging directory for F* cache"

# Use -n flag to prevent overwriting existing files (avoids Permission denied on read-only files)
if [[ -n $LOWPARSE_LOCAL_DIR ]]; then
	while IFS= read -r checked; do
		cp -n "$checked" "$EVERPARSE_STAGE"/
	done < <(find "$CACHE_DIR" -maxdepth 1 -name 'LowParse*.checked' 2>/dev/null)
	checked_count=$(count_checked_files "$EVERPARSE_STAGE")
	echo "[everparse] Seeded LowParse .checked files from cache (total: $checked_count)"
else
	if [[ -d "$EVERPARSE_SOURCE_ROOT/lib/lowparse" ]]; then
		copy_checked_files "$EVERPARSE_SOURCE_ROOT/lib/lowparse" "$EVERPARSE_STAGE"
		checked_count=$(count_checked_files "$EVERPARSE_STAGE")
		echo "[everparse] Copied LowParse .checked files from lib/lowparse (total: $checked_count)"
	fi

	if [[ -d "$EVERPARSE_SOURCE_ROOT/src/lowparse" ]]; then
		copy_checked_files "$EVERPARSE_SOURCE_ROOT/src/lowparse" "$EVERPARSE_STAGE"
		checked_count=$(count_checked_files "$EVERPARSE_STAGE")
		echo "[everparse] Copied LowParse .checked files from src/lowparse (total: $checked_count)"
	fi
fi

if [[ -d "$EVERPARSE_SOURCE_ROOT/src/3d/prelude" ]]; then
	copy_checked_files "$EVERPARSE_SOURCE_ROOT/src/3d/prelude" "$EVERPARSE_STAGE"
	checked_count=$(count_checked_files "$EVERPARSE_STAGE")
	echo "[everparse] Copied EverParse3d prelude files (total: $checked_count)"
fi

run_everparse_schema() {
	local schema_file="$1"
	local base_name="$2"
	echo "[everparse] Generating ${base_name} parser"
	run_everparse --no_batch --odir "$EVERPARSE_STAGE" "$ROOT/fstar/lowparse/${schema_file}"

	# Copy wrapper/C artifacts if they exist
	if [[ -f "$EVERPARSE_STAGE/${base_name}Wrapper.c" ]]; then
		cp "$EVERPARSE_STAGE/${base_name}Wrapper.c" "$GENERATED_EVERPARSE_DIR/"
	fi
	if [[ -f "$EVERPARSE_STAGE/${base_name}Wrapper.h" ]]; then
		cp "$EVERPARSE_STAGE/${base_name}Wrapper.h" "$GENERATED_EVERPARSE_DIR/"
	fi
	if [[ -f "$EVERPARSE_STAGE/${base_name}.c" ]]; then
		cp "$EVERPARSE_STAGE/${base_name}.c" "$GENERATED_EVERPARSE_DIR/"
	fi
	if [[ -f "$EVERPARSE_STAGE/${base_name}.h" ]]; then
		cp "$EVERPARSE_STAGE/${base_name}.h" "$GENERATED_EVERPARSE_DIR/"
	fi

	if [[ $base_name == "JoseHeader" ]]; then
		ensure_jose_header_error_kind_wrapper
	fi

	if [[ $base_name == "IdTokenSchema" ]]; then
		ensure_id_token_jwt_validator
	fi
}

# EverParse artefacts output directory
GENERATED_EVERPARSE_DIR="$ROOT/generated/everparse"
mkdir -p "$GENERATED_EVERPARSE_DIR"

run_everparse_schema "JoseHeader.3d" "JoseHeader"
run_everparse_schema "DCR.3d" "DCR"
run_everparse_schema "IdTokenSchema.3d" "IdTokenSchema"

canonicalize_everparse_dir "$GENERATED_EVERPARSE_DIR"

if [[ -d $GENERATED_EVERPARSE_DIR ]]; then
	checked_count=$(find "$GENERATED_EVERPARSE_DIR" -name '*.checked' | wc -l)
	if [[ $checked_count -gt 0 ]]; then
		find "$GENERATED_EVERPARSE_DIR" -name '*.checked' -delete
		echo "[everparse] Removed ${checked_count} .checked files from generated/everparse"
	fi
fi

# Generate Low* C stubs for EverParse parsers so their wrappers can link
generate_everparse_lowstar() {
	local base_name="$1"
	local module_name="$2"
	local fst_path="$ROOT/generated/everparse/${base_name}.fst"

	if [[ ! -f $fst_path ]]; then
		echo "[everparse] Skipping Low* generation for ${base_name}; ${fst_path} missing" >&2
		return
	fi

	local gen_tmp
	gen_tmp="$(mktemp -d "${TMPDIR:-/tmp}/everparse-lowstar-${base_name}.XXXXXX")"

	local fstar_args=(
		--use_hints
		--hint_dir "${ROOT}/fstar/.hints"
		--cache_dir "${ROOT}/fstar/.cache"
		--odir "$gen_tmp"
		--codegen krml
	)

	# Make the generated module available along with EverParse includes
	fstar_args+=(--include "${ROOT}/generated/everparse")
	if [[ -d "$KAMEL_ROOT/lib/krml" ]]; then
		fstar_args+=(--include "$KAMEL_ROOT/lib/krml")
	fi
	for dir in "${LOWSTAR_EVERPARSE_INCLUDE_DIRS[@]}"; do
		fstar_args+=(--include "$dir")
	done
	for dir in "${EVERCRYPT_INCLUDE_DIRS[@]}"; do
		fstar_args+=(--include "$dir")
	done

	echo "[everparse] Generating ${base_name}.c via KaRaMeL"
	run_fstar "${fstar_args[@]}" "$fst_path"

	local krml_tmp="$gen_tmp/kamel"
	mkdir -p "$krml_tmp"

	# Generate .krml for core LowParse dependencies that EverParse expects (BitFields, Low.ErrorCode)
	# so that types like LowParse.BitFields.uint_t resolve during translation.
	local dep_root="${LOWPARSE_LOCAL_DIR:-$EVERPARSE_LIB/lowparse}"
	declare -a dep_fsts=(
		"${dep_root}/LowParse.BitFields.fst"
		"${dep_root}/LowParse.Low.ErrorCode.fst"
	)
	for dep in "${dep_fsts[@]}"; do
		if [[ -f $dep ]]; then
			echo "[everparse] Generating krml for dependency: $dep"
			dep_args=(
				--codegen krml
				--warn_error +241
				--cache_dir "$CACHE_DIR"
				--odir "$gen_tmp"
				--hint_dir "${ROOT}/fstar/.hints"
				--include "$ROOT/generated/everparse"
				--include "$ROOT/fstar"
			)
			dep_args+=("${LOWSTAR_EVERPARSE_INCLUDE_FLAGS[@]}")
			for inc in "${EVERCRYPT_INCLUDE_DIRS[@]}"; do
				dep_args+=(--include "$inc")
			done
			run_fstar "${dep_args[@]}" "$dep"
		fi
	done

	local krml_files=()
	while IFS= read -r -d '' file; do
		krml_files+=("$file")
	done < <(find "$gen_tmp" -maxdepth 1 -name '*.krml' -print0)

	if [[ ${#krml_files[@]} -eq 0 ]]; then
		echo "[everparse] No .krml files emitted for ${base_name}; skipping" >&2
		rm -rf "$gen_tmp"
		return
	fi

	# Include core LowParse dependencies that EverParse krml expects (BitFields, ErrorCode)
	declare -a krml_deps=()
	for dep in \
		"$EVERPARSE_LIB/lowparse/LowParse.BitFields.fst" \
		"$EVERPARSE_LIB/lowparse/LowParse.Low.ErrorCode.fst"; do
		if [[ -f $dep ]]; then
			krml_deps+=("$dep")
		fi
	done

	"$KAMEL_BIN" \
		-skip-extraction \
		-skip-compilation \
		-skip-linking \
		-tmpdir "$krml_tmp" \
		-add-include "$EVERPARSE_LIB/lowparse" \
		-dmonomorphization \
		"${krml_files[@]}"

	for artifact in "$module_name.c" "$module_name.h"; do
		if [[ -f "$krml_tmp/$artifact" ]]; then
			cp "$krml_tmp/$artifact" "$GENERATED_EVERPARSE_DIR/"
		else
			echo "[everparse] Expected artifact $artifact not found for ${base_name}" >&2
		fi
	done

	rm -rf "$gen_tmp"
}

if [[ ${GENERATE_EVERPARSE_LOWSTAR:-0} == "1" ]]; then
	generate_everparse_lowstar "JoseHeader" "JoseHeader"
	generate_everparse_lowstar "DCR" "DCR"
	generate_everparse_lowstar "IdTokenSchema" "IdTokenSchema"
else
	echo "[everparse] Skipping Low* C generation for JoseHeader/DCR/IdToken" \
		"(set GENERATE_EVERPARSE_LOWSTAR=1 to enable)"
fi

# ---------------------------------------------------------------------------
# Step 2. Extract Low* code for Jose.LowStar
# ---------------------------------------------------------------------------
INCLUDE_ARGS=()

# Add F* standard library (ulib)
FSTAR_ROOT="$(dirname "$(dirname "$(readlink -f "$FSTAR_BIN")")")"
if [[ -d "$FSTAR_ROOT/lib/fstar/ulib" ]]; then
	INCLUDE_ARGS+=(--include "$FSTAR_ROOT/lib/fstar/ulib")
	echo "[lowstar] Added F* ulib: $FSTAR_ROOT/lib/fstar/ulib"
fi

# Add KaRaMeL library (C.*, LowStar.Lib.*)

if [[ -d "$KAMEL_ROOT/lib/krml" ]]; then
	INCLUDE_ARGS+=(--include "$KAMEL_ROOT/lib/krml")
	echo "[lowstar] Added KaRaMeL lib: $KAMEL_ROOT/lib/krml"
fi

INCLUDE_ARGS+=(--include "${ROOT}/fstar")
INCLUDE_ARGS+=(--include "${ROOT}/fstar/common")
INCLUDE_ARGS+=(--include "${ROOT}/generated/everparse")
INCLUDE_ARGS+=(--include "${ROOT}/fstar/jose")
INCLUDE_ARGS+=(--include "${ROOT}/fstar/jose/LowStar/Json")

if [[ -n ${HACL_FSTAR_PATH:-} ]]; then
	INCLUDE_ARGS+=(--include "$HACL_FSTAR_PATH")
	if [[ -d $HACL_FSTAR_PATH ]]; then
		while IFS= read -r dir; do
			INCLUDE_ARGS+=(--include "$dir")
		done < <(find "$HACL_FSTAR_PATH" -maxdepth 1 -mindepth 1 -type d | sort)
	fi
fi
if [[ -n ${STEEL_PATH:-} ]]; then
	INCLUDE_ARGS+=(--include "$STEEL_PATH")
fi
for dir in "${LOWSTAR_EVERPARSE_INCLUDE_DIRS[@]}"; do
	INCLUDE_ARGS+=(--include "$dir")
done
for dir in "${EVERCRYPT_INCLUDE_DIRS[@]}"; do
	INCLUDE_ARGS+=(--include "$dir")
done
INCLUDE_ARGS+=(--include "${ROOT}/fstar")

echo "[lowstar] Generating .krml via F*"
LOWSTAR_SOURCES=(
	"${ROOT}/fstar/jose/Jose.Context.fst"
	"${ROOT}/fstar/jose/Jose.HeaderParser.Runtime.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Helpers.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Runtime.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Structural.Runtime.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Structural.Types.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Types.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.Structural.fst"
	"${ROOT}/fstar/jose/LowStar/Json/Jose.LowStar.Json.fst"
	"${ROOT}/fstar/jose/Jose.Dcr.fst"
	"${ROOT}/fstar/jose/Jose.LowStar.fst"
)
LOWSTAR_HINT_ARGS=()
build_hint_args "[lowstar]" LOWSTAR_HINT_ARGS "${LOWSTAR_SOURCES[@]}"
run_fstar \
	"${LOWSTAR_HINT_ARGS[@]}" \
	--cache_dir "${ROOT}/fstar/.cache" \
	--odir "$TMP_DIR" \
	--codegen krml \
	"${INCLUDE_ARGS[@]}" \
	--extract_module Jose.Context \
	--extract_module Jose.HeaderParser.Runtime \
	--extract_module Jose.LowStar \
	--extract_module Jose.LowStar.Json.Helpers \
	--extract_module Jose.LowStar.Json.Runtime \
	--extract_module Jose.LowStar.Json.Structural.Runtime \
	--extract_module Jose.LowStar.Json.Structural.Types \
	--extract_module Jose.LowStar.Json.Types \
	--extract_module Jose.LowStar.Json.Structural \
	--extract_module Jose.LowStar.Json \
	--extract_module Jose.Dcr \
	"${LOWSTAR_SOURCES[@]}"

KRML_FILES=("${TMP_DIR}"/*.krml)
if [[ ${#KRML_FILES[@]} -eq 0 ]]; then
	echo "[error] No .krml files were produced by F*." >&2
	exit 1
fi

KAMEL_TMP="${TMP_DIR}/kamel"
mkdir -p "$KAMEL_TMP"

echo "[lowstar] Translating to C via KaRaMeL"
"$KAMEL_BIN" \
	-skip-extraction \
	-skip-compilation \
	-skip-linking \
	-warn-error -2-9 \
	-tmpdir "$KAMEL_TMP" \
	-library FStar.UInt32 \
	-library FStar.List.Tot \
	-library FStar.Pervasives.Native \
	"${KRML_FILES[@]}"

cp -R "$KAMEL_TMP"/* "$OUT_DIR"/
rm -f "$OUT_DIR/Makefile.basic" "$OUT_DIR/Makefile.include"
normalize_karamel_sources "$OUT_DIR"

echo "[lowstar] Extraction artifacts written to $OUT_DIR"

# Extract HashComputation.Low and IdToken runtime artefacts into generated/lowstar/oidc/
OIDC_LOW_DIR="${ROOT}/generated/lowstar/oidc"
rm -rf "$OIDC_LOW_DIR"
mkdir -p "$OIDC_LOW_DIR"
HASH_LOW_DIR="$OIDC_LOW_DIR/hash"
rm -rf "$HASH_LOW_DIR"
mkdir -p "$HASH_LOW_DIR"
IDTOKEN_LOW_DIR="$OIDC_LOW_DIR/id_token"
rm -rf "$IDTOKEN_LOW_DIR"
mkdir -p "$IDTOKEN_LOW_DIR"

rm -rf "$IDTOKEN_TMP_DIR"
mkdir -p "$IDTOKEN_TMP_DIR"

HASH_TMP_DIR="/tmp/hash-lowstar"
rm -rf "$HASH_TMP_DIR"
mkdir -p "$HASH_TMP_DIR"

echo "[lowstar] Generating HashComputation.Low krml"
HASH_SOURCES=(
	"${ROOT}/fstar/HashComputation.Low.fst"
)
HASH_HINT_ARGS=()
build_hint_args "[lowstar]" HASH_HINT_ARGS "${HASH_SOURCES[@]}"
run_fstar \
	"${HASH_HINT_ARGS[@]}" \
	--cache_dir "${ROOT}/fstar/.cache" \
	--odir "$HASH_TMP_DIR" \
	--codegen krml \
	"${INCLUDE_ARGS[@]}" \
	--extract_module HashComputation.Low \
	"${HASH_SOURCES[@]}"

HASH_KRML=("${HASH_TMP_DIR}"/*.krml)
if [[ ${#HASH_KRML[@]} -eq 0 ]]; then
	echo "[error] No HashComputation .krml generated" >&2
	exit 1
fi

HASH_KAMEL_TMP="${HASH_TMP_DIR}/kamel"
mkdir -p "$HASH_KAMEL_TMP"

"$KAMEL_BIN" \
	-skip-extraction \
	-skip-compilation \
	-skip-linking \
	-warn-error -2-9 \
	-tmpdir "$HASH_KAMEL_TMP" \
	-library FStar.UInt32 \
	-library FStar.List.Tot \
	-library FStar.Pervasives.Native \
	"${HASH_KRML[@]}"

cp -R "$HASH_KAMEL_TMP"/* "$HASH_LOW_DIR"/
rm -f "$HASH_LOW_DIR/Makefile.basic" "$HASH_LOW_DIR/Makefile.include"
rm -f "$HASH_LOW_DIR"/krmlinit.c "$HASH_LOW_DIR"/krmlinit.h
normalize_karamel_sources "$HASH_LOW_DIR" "/tmp/hash-lowstar"
python3 - "$HASH_LOW_DIR/HashComputation_Low.h" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
include = '#include "FStar_Bytes.h"\n'
if include in text:
	raise SystemExit(0)
needle = '#include "krmllib.h"\n'
if needle not in text:
	raise SystemExit("HashComputation_Low.h is missing the expected krmllib include")
path.write_text(text.replace(needle, needle + include, 1))
PY

echo "[lowstar] HashComputation.Low artifacts written to $HASH_LOW_DIR"

echo "[lowstar] Generating IdToken/IdToken.Spec/IdToken.Low krml"
IDTOKEN_SOURCES=(
	"${ROOT}/fstar/oidc/IdToken.Low.Runtime.fst"
)
IDTOKEN_HINT_ARGS=()
build_hint_args "[lowstar]" IDTOKEN_HINT_ARGS "${IDTOKEN_SOURCES[@]}"
run_fstar \
	"${IDTOKEN_HINT_ARGS[@]}" \
	--cache_dir "${ROOT}/fstar/.cache" \
	--odir "$IDTOKEN_TMP_DIR" \
	--codegen krml \
	"${INCLUDE_ARGS[@]}" \
	--extract_module IdToken.Low.Runtime \
	"${IDTOKEN_SOURCES[@]}"

IDTOKEN_KRML=("${IDTOKEN_TMP_DIR}"/*.krml)
if [[ ${#IDTOKEN_KRML[@]} -eq 0 ]]; then
	echo "[error] No IdToken .krml generated" >&2
	exit 1
fi

IDTOKEN_KAMEL_TMP="${IDTOKEN_TMP_DIR}/kamel"
mkdir -p "$IDTOKEN_KAMEL_TMP"

"$KAMEL_BIN" \
	-skip-extraction \
	-skip-compilation \
	-skip-linking \
	-warn-error -2-9 \
	-tmpdir "$IDTOKEN_KAMEL_TMP" \
	-library FStar.UInt32 \
	-library FStar.List.Tot \
	-library FStar.Pervasives.Native \
	"${IDTOKEN_KRML[@]}"

cp -R "$IDTOKEN_KAMEL_TMP"/* "$IDTOKEN_LOW_DIR"/
rm -f "$IDTOKEN_LOW_DIR/Makefile.basic" "$IDTOKEN_LOW_DIR/Makefile.include"

# Remove redundant krmlinit artifacts
rm -f "$IDTOKEN_LOW_DIR"/krmlinit.c "$IDTOKEN_LOW_DIR"/krmlinit.h

# Sanitize nondeterministic temp paths in KaRaMeL headers for reproducibility.
normalize_karamel_sources "$IDTOKEN_LOW_DIR" "/tmp/idtoken-lowstar"

echo "[lowstar] IdToken.Low.Runtime artifacts written to $IDTOKEN_LOW_DIR"

# Ensure generated artefacts are committed (helpful during development/CI)
if ! git diff --quiet -- generated/everparse generated/lowstar; then
	echo "[warn] Generated artefacts differ from the working tree." \
		"Remember to commit updated files under generated/everparse" \
		"and generated/lowstar." >&2
fi

# Generate internal/FStar.h stub for Stack module if needed
# Stack module (Jose.LowStar.Json.Stack) is extracted separately with -skip-compilation
# which doesn't generate the internal/ directory. We provide a minimal stub.
STACK_MODULE="${ROOT}/artifacts/karamel/Jose_LowStar_Json_Stack.c"
if [[ -f $STACK_MODULE ]]; then
	echo "[lowstar] Generating internal/FStar.h stub for Stack module"
	INTERNAL_DIR="${ROOT}/artifacts/karamel/internal"
	mkdir -p "$INTERNAL_DIR"
	cat >"$INTERNAL_DIR/FStar.h" <<-'HEADER_EOF'
		/* Auto-generated by run_jose_lowstar.sh for Stack module
		* KaRaMeL -skip-compilation doesn't generate internal/ directory.
		* This stub provides the minimal includes needed by Jose_LowStar_Json_Stack.c
		*/

		#ifndef __INTERNAL_FSTAR_H
		#define __INTERNAL_FSTAR_H

		#include "FStar_UInt_8_16_32_64.h"
		#include "krmllib.h"

		#endif /* __INTERNAL_FSTAR_H */
	HEADER_EOF
	echo "[lowstar] Generated: $INTERNAL_DIR/FStar.h"
fi
