#!/usr/bin/env bash
set -euo pipefail
config_digest() {
	local archive=$1 config
	config=$(tar -xOf "$archive" manifest.json | jq -er '
	  if length == 1 and .[0].RepoTags == ["aegaeon:latest"]
	  then .[0].Config | strings | select(length > 0)
	  else error("unexpected image manifest") end') || return 1
	tar -xOf "$archive" -- "$config" | sha256sum | cut -d' ' -f1
}

expected=$(config_digest result)
loaded=$(docker image inspect aegaeon:latest --format '{{.Id}}')
[[ $loaded =~ ^sha256:[0-9a-f]{64}$ ]]
if [[ $loaded != "sha256:$expected" ]]; then
	# The containerd image store can report a manifest ID. Compare the config
	# bytes that Docker actually exports for the tag before publishing it.
	exported=$(mktemp)
	trap 'rm -f -- "$exported"' EXIT
	docker image save --output "$exported" aegaeon:latest
	actual=$(config_digest "$exported")
	if [[ $actual != "$expected" ]]; then
		printf 'Imported config mismatch: expected %s, found %s\n' "$expected" "$actual" >&2
		exit 1
	fi
fi
sha256sum result
printf 'Docker imported image %s with config sha256:%s\n' "$loaded" "$expected"
