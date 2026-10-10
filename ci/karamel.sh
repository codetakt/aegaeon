#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

# Keep the legacy archive entrypoint on the same pinned routes as extraction.
exec nix develop .#verification --command bash -s <<'SCRIPT'
set -euo pipefail
source scripts/extraction/lib/toolchain_preflight.sh
extraction_preflight

mkdir -p artifacts/karamel
LOG="artifacts/karamel.log"
{
	echo "=== KaRaMeL Extraction ==="
	bash scripts/extraction/run_jose_lowstar.sh
	tar -czf artifacts/karamel/jose-lowstar.tar.gz -C generated/lowstar jose
	rm -rf generated/lowstar/jose
	echo
	echo "✅ KaRaMeL extraction completed"
} 2>&1 | tee "$LOG"
SCRIPT
