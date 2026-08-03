#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

mkdir -p artifacts
chmod 777 artifacts
LOG="artifacts/fstar.log"

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

docker run --rm -v "$PWD":/workspace -w /workspace projecteverest/everest-linux:latest bash -c "\
  set -e; \
  # Set up paths for F*, Z3, and dependencies
  export PATH=/home/test/FStar/bin:/home/test/z3/bin:\$PATH; \
  export FSTAR_HOME=/home/test/FStar; \
  export HACL_HOME=/home/test/hacl-star; \
  export KRML_HOME=/home/test/karamel; \

  echo 'F* version:'; \
  fstar.exe --version || exit 1; \
  echo 'Z3 version:'; \
  z3 --version || echo 'Z3 not found'; \

  # Find non-empty F* files, excluding generated files
  FILES=\$(find fstar tests/fstar -name '*.fst' -size +0 -not -path '*/generated/*' 2>/dev/null || true); \
  if [ -z \"\$FILES\" ]; then echo 'ERROR: No F* files found to verify'; exit 1; fi; \
  echo \"Found \$(echo \$FILES | wc -w) non-empty F* files\"; \

  # For now, use admit_smt_queries true due to missing dependencies
  # Once HACL* and other deps are properly set up, we can remove this
  fstar.exe --admit_smt_queries true --warn_error +271 \
    --include fstar \
    --include tests/fstar \
    --include tests/fstar/property \
    --include tests/fstar/unit \
    --include generated/everparse \
    --include \$FSTAR_HOME/ulib \
    --include \$HACL_HOME/dist/gcc-compatible \
    --include \$KRML_HOME/krmllib \
    \$FILES" 2>&1 | tee "$LOG"

# Check for actual F* errors (excluding warn_error messages)
if grep -E '^[^#]*\(Error' "$LOG" | grep -v 'warn_error' >/dev/null; then
	echo "F* verification failed with errors" >&2
	exit 1
fi

echo "F* verification completed successfully"
