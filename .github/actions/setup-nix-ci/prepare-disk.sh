#!/usr/bin/env bash
set -euo pipefail

# The action supplies the workspace, runner temp and Nix store paths explicitly.
if [[ $# -ne 4 ]]; then
	echo "Usage: prepare-disk.sh MINIMUM_FREE_GIB WORKSPACE RUNNER_TEMP NIX_STORE" >&2
	exit 2
fi
minimum=$1
shift
if [[ ! $minimum =~ ^[0-9]+$ ]]; then
	echo "minimum-free-gib must be a nonnegative integer" >&2
	exit 2
fi
# Normalize leading zeroes before Bash arithmetic and reject overflow.
minimum=${minimum#"${minimum%%[!0]*}"}
minimum=${minimum:-0}
# Compare equal-length decimal strings before arithmetic to avoid overflow.
# shellcheck disable=SC2071
if ((${#minimum} > 10)) || { ((${#minimum} == 10)) && [[ $minimum > 8589934591 ]]; }; then
	echo "minimum-free-gib exceeds the supported byte range" >&2
	exit 2
fi
required_bytes=$((minimum * 1073741824))
cleanup=true
reason="unconditional cleanup (minimum-free-gib=0)"

available_bytes() {
	local path=$1 output available
	# /nix may not exist before the installer. Measure its nearest existing parent.
	while [[ ! -e $path ]]; do
		[[ $path == / || -z $path ]] && return 1
		path=$(dirname -- "$path")
	done
	output=$(LC_ALL=C df -B1 --output=avail -- "$path") || return 1
	[[ $output == *$'\n'* ]] || return 1
	[[ ${output%$'\n'*} =~ ^[[:space:]]*Avail[[:space:]]*$ ]] || return 1
	read -r available <<<"${output##*$'\n'}"
	[[ $available =~ ^[0-9]+$ ]] || return 1
	available=${available#"${available%%[!0]*}"}
	available=${available:-0}
	# Compare equal-length decimal strings before arithmetic to avoid overflow.
	# shellcheck disable=SC2071
	if ((${#available} > 19)) || { ((${#available} == 19)) && [[ $available > 9223372036854775807 ]]; }; then
		return 1
	fi
	echo "Available bytes on $path: $available" >&2
	printf '%s\n' "$available"
}

echo "Disk capacity before cleanup decision:"
df -h || true
if ((minimum > 0)); then
	cleanup=false
	reason="every relevant filesystem has at least ${minimum} GiB available"
	for path in "$@"; do
		if ! available=$(available_bytes "$path"); then
			cleanup=true
			reason="capacity measurement unavailable for $path"
			break
		elif ((available < required_bytes)); then
			cleanup=true
			reason="less than ${minimum} GiB available for $path"
			break
		fi
	done
fi

started=$SECONDS
if [[ $cleanup == true ]]; then
	echo "Running disk cleanup: $reason"
	if command -v sudo >/dev/null 2>&1; then
		SUDO="sudo"
	else
		SUDO=""
	fi
	$SUDO rm -rf /usr/share/dotnet /opt/ghc /usr/local/lib/android /usr/local/share/boost /opt/hostedtoolcache/CodeQL || true
	$SUDO docker system prune -af || true
	$SUDO apt-get clean || true
else
	echo "Skipping disk cleanup: $reason"
fi
echo "Disk cleanup elapsed seconds: $((SECONDS - started))"
echo "Disk capacity after cleanup decision:"
df -h || true
