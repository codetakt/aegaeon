#!/usr/bin/env bash
# Build the publishable archive in a fresh local store. Its Nix paths retain
# their normal /nix/store names inside the image.
set -euo pipefail

store_root=$(mktemp -d "${RUNNER_TEMP:?}/publish-oci-store.XXXXXXXX")
upstream=https://cache.nixos.org
key=cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
options=(
	--store "local?root=$store_root"
	--option accept-flake-config false
	--option builders ''
	--option substituters "$upstream" --option extra-substituters ''
	--option trusted-substituters ''
	--option trusted-public-keys "$key" --option extra-trusted-public-keys ''
	--option require-sigs true
)

existing=$(nix "${options[@]}" path-info --all)
if [[ -n $existing ]]; then
	echo 'Expected an empty OCI publication store' >&2
	exit 1
fi
archive=$(nix "${options[@]}" build --no-update-lock-file --no-link --print-out-paths \
	--print-build-logs .#docker-image)
if [[ ! $archive =~ ^/nix/store/[0-9a-z]{32}-aegaeon\.tar\.gz$ || ! -f $store_root$archive ]]; then
	echo 'Expected one locally realized OCI archive' >&2
	exit 1
fi
ln -sT "$store_root$archive" result
