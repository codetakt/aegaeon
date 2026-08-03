#!/usr/bin/env bash
set -euo pipefail

# Compile and run dudect tests for comparison, MAC, signature, and JWE paths.

mkdir -p target artifacts/ct/dudect

# EverCrypt (HACL*) dist library (provided by Nix as `.#evercrypt-dist`).
EVERCRYPT_CFLAGS="$(pkg-config --cflags evercrypt)"
EVERCRYPT_LIBS="$(pkg-config --libs --static evercrypt)"

# EverCrypt headers depend on KaRaMeL runtime headers (`krml/*`, `krmllib.h`).
KARAMEL_PREFIX="$(dirname "$(dirname "$(command -v krml)")")"
KARAMEL_CFLAGS="-I${KARAMEL_PREFIX}/include"

# Comparison path
cc tests/constant_time/compare_timing_test.c -Iinclude -Ic -O2 -std=c11 -o target/compare_timing_test -lm
./target/compare_timing_test | tail -n 1 >artifacts/ct/dudect/compare.json

# HMAC path
cc tests/constant_time/hmac_timing_test.c c/rsa_signatures.c c/jws.c -Iinclude -Ic $KARAMEL_CFLAGS $EVERCRYPT_CFLAGS -O2 -std=c11 -o target/hmac_timing_test $EVERCRYPT_LIBS -lmbedcrypto -lmbedx509 -lm
./target/hmac_timing_test | tail -n 1 >artifacts/ct/dudect/hmac.json

# Signature path (Ed25519)
cc tests/constant_time/ed25519_timing_test.c c/rsa_signatures.c -Iinclude -Ic $KARAMEL_CFLAGS $EVERCRYPT_CFLAGS -O2 -std=c11 -o target/ed25519_timing_test $EVERCRYPT_LIBS -lmbedcrypto -lmbedx509 -lcrypto -lm
./target/ed25519_timing_test | tail -n 1 >artifacts/ct/dudect/ed25519.json

# Signature path (RSA-PSS)
cc tests/constant_time/rsa_timing_test.c c/rsa_signatures.c -Iinclude -Ic $KARAMEL_CFLAGS $EVERCRYPT_CFLAGS -O2 -std=c11 -o target/rsa_timing_test $EVERCRYPT_LIBS -lmbedcrypto -lmbedx509 -lcrypto -lm
./target/rsa_timing_test | tail -n 1 >artifacts/ct/dudect/rsa.json

# JWE decrypt path
cc tests/constant_time/jwe_timing_test.c c/jwe.c -Iinclude -Ic $KARAMEL_CFLAGS $EVERCRYPT_CFLAGS -O2 -std=c11 -o target/jwe_timing_test $EVERCRYPT_LIBS -lcrypto -lm
./target/jwe_timing_test | tail -n 1 >artifacts/ct/dudect/jwe.json

# Collate individual results into a single report capturing the maximum
# p-value across all dudect runs. This allows CI to assert that each tested
# path operates in constant time with high confidence.
python3 - <<'PYTHON'
import json, pathlib
out = pathlib.Path('artifacts/ct/dudect')
results = {}
for name in ['compare', 'hmac', 'ed25519', 'rsa', 'jwe']:
    with (out / f"{name}.json").open() as f:
        results[name] = json.load(f)
state = 1 if all(r['state'] == 1 for r in results.values()) else 0
max_p = max(r['p'] for r in results.values())
with (out / 'report.json').open('w') as f:
    json.dump(
        {
            'state': state,
            'p': max_p,
            # Conservative lower bound across the currently configured dudect runs:
            # compare=200000, hmac=200000, ed25519=20000, rsa=100000, jwe=100000.
            'num_traces': 20000,
            'tests': results,
        },
        f,
    )
PYTHON
