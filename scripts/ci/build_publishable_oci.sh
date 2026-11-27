#!/usr/bin/env bash
# Build the publication archive with only signed upstream substitutes.
set -euo pipefail

nix_command=(nix)
installable=.#docker-image
if [[ $# == 1 && $1 == --hosted ]]; then
	# The Hosted kernel can restrict namespaces for unprivileged local stores.
	# Use the installed Nix manager and a root-owned store on the disposable VM.
	# Fetch the immutable public revision without evaluating a runner-owned checkout as root.
	revision=${GITHUB_SHA:?}
	[[ $revision =~ ^[0-9a-f]{40}$ && $revision == "$(git rev-parse HEAD)" ]]
	store_root=$(sudo -n -- /usr/bin/mktemp -d /var/tmp/aegaeon-oci-store.XXXXXXXX)
	[[ $store_root =~ ^/var/tmp/aegaeon-oci-store\.[[:alnum:]]{8}$ ]]
	sudo -n -- /usr/bin/chmod 0711 "$store_root"
	nix_command=(sudo -n -H -- /nix/var/nix/profiles/default/bin/nix)
	installable="github:codetakt/aegaeon/$revision#docker-image"
elif [[ $# == 0 ]]; then
	store_root=$(mktemp -d "${RUNNER_TEMP:?}/publish-oci-store.XXXXXXXX")
else
	echo 'Usage: build_publishable_oci.sh [--hosted]' >&2
	exit 2
fi

upstream=https://cache.nixos.org
key=cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
options=(
	--store "local?root=$store_root"
	--option sandbox true --option sandbox-fallback false
	--option accept-flake-config false
	--option builders ''
	--option substituters "$upstream" --option extra-substituters ''
	--option trusted-substituters ''
	--option trusted-public-keys "$key" --option extra-trusted-public-keys ''
	--option require-sigs true
)

existing=$("${nix_command[@]}" "${options[@]}" path-info --all)
if [[ -n $existing ]]; then
	echo 'Expected an empty OCI publication store' >&2
	exit 1
fi
archive=$("${nix_command[@]}" "${options[@]}" build --no-update-lock-file --no-link --print-out-paths \
	--print-build-logs "$installable")
if [[ ! $archive =~ ^/nix/store/[0-9a-z]{32}-aegaeon\.tar\.gz$ || ! -f $store_root$archive ]]; then
	echo 'Expected one locally realized OCI archive' >&2
	exit 1
fi
ln -sT "$store_root$archive" result
