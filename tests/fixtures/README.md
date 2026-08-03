# Test RSA Fixtures (Optional)

## Overview

- These fixtures are used by `crates/server/tests/private_key_jwt_tests.rs` when `AEGAEON_TEST_RSA_FIXTURES=1`.
- Do NOT use any keys here in production. They are for tests only.

## How Tests Discover Keys

- Private key: `AEGAEON_RSA_PRIV_PEM` (inline PEM or `@/path/to/file`) OR `tests/fixtures/rsa2048-private.pk8.pem`
- Public key:  `AEGAEON_RSA_PUB_PEM`  (inline PEM or `@/path/to/file`) OR `tests/fixtures/rsa2048-public.pem`

## Recommended Key Format

- Private key: PKCS#8 PEM, 2048 bits or larger
  - Header: `-----BEGIN PRIVATE KEY-----`
- Public key: SPKI (SubjectPublicKeyInfo) PEM
  - Header: `-----BEGIN PUBLIC KEY-----`

## Generate a 2048-bit RSA Key and Matching Public Key

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048-private.pk8.pem
openssl rsa -in rsa2048-private.pk8.pem -pubout -out rsa2048-public.pem
```

## Run Tests with Fixtures

```bash
export AEGAEON_TEST_RSA_FIXTURES=1
# Either let tests pick up files from tests/fixtures, or point explicitly:
export AEGAEON_RSA_PRIV_PEM=@tests/fixtures/rsa2048-private.pk8.pem
export AEGAEON_RSA_PUB_PEM=@tests/fixtures/rsa2048-public.pem

cargo test -p aegaeon-server --test private_key_jwt_tests -- --nocapture
```

## Notes

- If the private key is smaller than 2048 bits, the tests will skip with a message containing `TooSmall`.
- For CI, prefer providing keys via environment (GitHub Actions secrets/variables)
  rather than committing private keys.
