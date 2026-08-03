#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

mkdir -p artifacts
chmod 777 artifacts
LOG="artifacts/karamel.log"

ensure_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		sudo apt-get update
		sudo apt-get install -y docker.io
	fi
}

ensure_docker

# Pull image only if not present
if ! docker image inspect projecteverest/everest-linux:latest >/dev/null 2>&1; then
	echo "Pulling Project Everest image..."
	docker pull projecteverest/everest-linux:latest
fi

echo "=== KaRaMeL Extraction ===" | tee "$LOG"

docker run --rm -v "$PWD":/workspace -w /workspace projecteverest/everest-linux:latest bash -c "\
  set -euo pipefail; \
  export PATH=/home/test/FStar/bin:/home/test/z3/bin:/home/test/karamel:\$PATH; \
  export FSTAR_HOME=/home/test/FStar; \
  export KRML_HOME=/home/test/karamel; \
  mkdir -p artifacts/karamel; \
  chmod +x scripts/extraction/run_jose_lowstar.sh; \
  scripts/extraction/run_jose_lowstar.sh; \
  tar -czf artifacts/karamel/jose-lowstar.tar.gz -C generated/lowstar jose; \
  rm -rf generated/lowstar/jose; \
" 2>&1 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "✅ KaRaMeL extraction completed" | tee -a "$LOG"
