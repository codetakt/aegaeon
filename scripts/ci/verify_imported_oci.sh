#!/usr/bin/env bash
set -euo pipefail
config=$(tar -xOzf result manifest.json | jq -er '
  if length == 1 and .[0].RepoTags == ["aegaeon:latest"]
  then .[0].Config else error("unexpected image manifest") end')
expected=$(tar -xOzf result -- "$config" | sha256sum | cut -d' ' -f1)
loaded=$(docker image inspect aegaeon:latest --format '{{.Id}}')
test "$loaded" = "sha256:$expected"
sha256sum result
printf 'Docker imported image %s\n' "$loaded"
