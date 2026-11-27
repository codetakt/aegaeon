#!/usr/bin/env bash
set -euo pipefail

expect_setting() {
	local name=$1 expected=$2 actual
	actual=$(nix config show "$name")
	if [[ $actual != "$expected" ]]; then
		echo "Unexpected Nix configuration for publication: $name" >&2
		exit 1
	fi
}

expect_setting accept-flake-config false
expect_setting builders ''
expect_setting substituters https://cache.nixos.org
expect_setting trusted-substituters ''
expect_setting trusted-public-keys 'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='
expect_setting require-sigs true
