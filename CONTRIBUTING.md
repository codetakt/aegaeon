# Contributing to Aegaeon

Thank you for your interest in contributing to Aegaeon.

Aegaeon is a security-first OAuth 2.0 / OIDC authorization server. The project
defaults to standards-first behaviour and uses operator-controlled policy gates
for optional extensions. Changes that affect protocol behaviour should cite the
relevant RFC(s) and include conformance tests or verification artefacts.

## Development environment (recommended: Nix)

We use Nix Flakes to provide reproducible toolchains (Rust, F*, EverParse,
KaRaMeL, Tamarin, Kani, security tooling).

```bash
# Enter the development shell
nix develop

# Baseline checks (build + lint + formatting where applicable)
nix flake check

# Build the server (release)
nix build .#server
./result/bin/aegaeon-server --release
```text

If you do not use Nix, you will need the pinned Rust nightly in
`rust-toolchain.toml` plus additional native dependencies. Non-Nix setups are
not guaranteed to match CI.

## Code style

### Rust

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Guidelines:
- Prefer simple, defensive code paths (fail-closed for unknown/unsupported inputs).
- Avoid `unsafe` unless strictly necessary; isolate it and justify it in the PR.
- Keep comments and documentation in English.

### Python (validation scripts)

CI installs the minimal dependencies via:

```bash
pip install -r requirements.txt
pip install pytest cryptography
```

## Protocol and security checks

### Security suite (recommended)

Runs dependency policy (`cargo deny`), audits, fuzz smoke, SBOM scan, and other
security checks.

```bash
nix run .#security-suite
```

### Formal verification / regression runs

These are heavier and may take time:

```bash
nix build .#verify-fstar
nix build .#verify-tamarin
nix build .#verify-kani
nix build .#verify-dudect
```

Local helpers:

```bash
cargo xtask kani
cargo xtask dudect
```

Verification logs are written under `artifacts/` (ignored by default).

## Compliance matrix

The RFC compliance matrix is source-managed and schema-validated:

```bash
python3 scripts/validation/validate_compliance_matrix.py --check
```

When updating `spec/compliance-matrix.yaml`, ensure referenced paths exist and
that the corresponding tests/proofs are updated.

## Generated artefacts

Do not hand-edit generated files. Regenerate from the source and commit the
resulting diffs as a single, focused change.

```bash
# Low*/KaRaMeL extraction (JOSE)
scripts/extraction/run_jose_lowstar.sh

# EverParse batch generation
scripts/extraction/run_everparse_batch.sh
```

## Running GitHub Actions locally (optional)

We support local workflow runs via `act`:

```bash
cp .env.act.example .env.act
act -l
```

Pass secrets via `act -s NAME=value` or `act --secret-file .secrets` (do not put
secrets in `.env.act`).

## Pull request checklist

- Run `nix flake check`.
- Add/adjust tests for behaviour changes.
- Update the compliance matrix when changing protocol behaviour.
- Avoid introducing non-standard protocol extensions unless they are gated and documented.

## Repository structure

```text
artifacts/   # Local logs and reports (ignored by default)
c/           # C sources used by verification / harnesses
crates/      # Rust implementation
docs/        # Documentation
fstar/       # F* sources
fuzz/        # Rust fuzz targets and corpora
generated/   # Source-managed generated artefacts (EverParse, Low*)
nix/         # Nix packaging and flake wiring
proofs/      # Protocol/security proofs (e.g., Tamarin)
scripts/     # CI/verification helpers
spec/        # Compliance matrix and schemas
supply-chain/# cargo-vet / dependency governance data
tests/       # Conformance, fixtures, constant-time harnesses
xtask/       # Small task runner (cargo xtask)
```

## Security reporting

Do not open public issues for security vulnerabilities. Use GitHub Security
Advisories for private reporting and coordinated disclosure.

## Documentation

- Update AGENTS.md for architectural changes
- Keep RFC references current
- Document all public APIs with examples
- Include security considerations in docs

## Getting Help

- Check existing issues and discussions
- Review AGENTS.md for architectural context
- See `docs/README.md` for the canonical list of `nix` entry points
- Ask in discussions for clarification

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (see LICENSE file).
