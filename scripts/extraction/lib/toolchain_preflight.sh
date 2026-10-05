#!/usr/bin/env bash
# Admit explicit extraction pins before creating outputs or invoking suppliers.

extraction_pin_error() {
	printf '[error] %s; use the pinned Nix verification shell\n' "$1" >&2
	return 1
}

extraction_require_path() {
	local name=$1 kind=$2 value=${!1:-}
	if [[ $value != /* ]]; then
		extraction_pin_error "$name must name an explicit absolute $kind"
		return 1
	fi
	if [[ $kind == executable ]]; then
		[[ -f $value && -x $value ]] || {
			extraction_pin_error "$name is not an executable file"
			return 1
		}
	else
		[[ -d $value ]] || {
			extraction_pin_error "$name is not a directory"
			return 1
		}
	fi
}

extraction_require_relation() {
	local selected=$1 expected=$2 label=$3 actual_path expected_path
	actual_path=$(readlink -e -- "$selected") || {
		extraction_pin_error "$label cannot resolve its selected route"
		return 1
	}
	expected_path=$(readlink -e -- "$expected") || {
		extraction_pin_error "$label cannot resolve its pinned supplier route"
		return 1
	}
	[[ $actual_path == "$expected_path" ]] || {
		extraction_pin_error "$label differs from its pinned supplier route"
		return 1
	}
}

extraction_preflight() {
	local name directory
	for name in FSTAR KAMEL EVERPARSE; do
		extraction_require_path "$name" executable || return 1
	done
	for name in FSTAR_HOME KARAMEL_HOME EVERPARSE_PREFIX EVERPARSE_SOURCE_ROOT \
		HACL_PREFIX EVERCRYPT_PREFIX HACL_FSTAR_PATH EVERCRYPT_SRC_DIR; do
		extraction_require_path "$name" directory || return 1
	done
	extraction_require_relation "$FSTAR" "$FSTAR_HOME/bin/fstar.exe" FSTAR || return 1
	extraction_require_relation "$KAMEL" "$KARAMEL_HOME/bin/krml" KAMEL || return 1
	extraction_require_relation "$EVERPARSE" "$EVERPARSE_PREFIX/bin/everparse" EVERPARSE || return 1
	extraction_require_relation "$EVERPARSE_SOURCE_ROOT" "$EVERPARSE_PREFIX" \
		EVERPARSE_SOURCE_ROOT || return 1
	extraction_require_relation "$HACL_FSTAR_PATH" "$HACL_PREFIX/share/hacl-star/fstar" \
		HACL_FSTAR_PATH || return 1
	extraction_require_relation "$EVERCRYPT_SRC_DIR" "$EVERCRYPT_PREFIX/share/evercrypt" \
		EVERCRYPT_SRC_DIR || return 1
	for directory in "$FSTAR_HOME/lib/fstar/ulib" "$KARAMEL_HOME/lib/krml" \
		"$EVERPARSE_SOURCE_ROOT/share/everparse/prelude" \
		"$EVERPARSE_SOURCE_ROOT/src/3d/prelude" "$EVERPARSE_SOURCE_ROOT/src/lowparse" \
		"$EVERPARSE_SOURCE_ROOT/lib/lowparse" "$EVERPARSE_SOURCE_ROOT/krmllib/obj" \
		"$EVERCRYPT_SRC_DIR/providers/fst" "$EVERCRYPT_SRC_DIR/specs" \
		"$EVERCRYPT_SRC_DIR/code"; do
		[[ -d $directory ]] || {
			extraction_pin_error "Pinned supplier layout is missing $directory"
			return 1
		}
	done
}

extraction_wasi_preflight() {
	extraction_require_path WASI_CLANG executable || return 1
	extraction_require_path WASI_SYSROOT directory || return 1
	[[ -d $WASI_SYSROOT/include && -d $WASI_SYSROOT/lib ]] || {
		extraction_pin_error 'WASI_SYSROOT must contain include and lib'
		return 1
	}
}
