# Cargo Vet Bootstrap

This directory is reserved for `cargo vet` configuration:
`config.toml`, `audits.toml`, `imports.lock`, and related files.

## Maintenance

- Update the generated files with `cargo vet diff` / `cargo vet check`.
- Track unaudited crates and review status in `docs/policies/dependency-policy.md`.
