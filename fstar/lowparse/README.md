# EverParse Schemas (3D / LowParse)

This directory contains EverParse 3D schemas (`*.3d`) used to generate verified parsers.
Generated artefacts are source-managed under `generated/everparse/` for CI reproducibility.

## Schemas

- `DCR.3d` — DCR request/response framing (RFC 7591/7592) and policy fields.
- `DcrRegistration.3d` — minimal DCR registration payload framing (policy-focused).
- `Dpop.3d` — DPoP proof framing (RFC 9449).
- `JoseHeader.3d` — JOSE header entry framing (RFC 7515/7519).
- `IdTokenSchema.3d` — OIDC ID Token/UserInfo framing (length-prefixed buffers).
- `LogoutTokenSchema.3d` — OIDC logout token framing.

## Regeneration

```bash
nix develop .#verification --command bash -c 'scripts/extraction/run_everparse_batch.sh'
```

## Notes

- EverParse validates canonical binary encodings at FFI boundaries; it does not parse/validate raw JSON.
- Builds fail closed if required artefacts are missing (`crates/ffi/build.rs`).
- Optional DCR self-check can be enabled via `policy.dcrEverparseRuntimeEnabled=true` in the active management database policy (`crates/server/src/dcr/everparse.rs`).
- `DcrRegistration.3d` is generated and compiled, but is not invoked from Rust yet.
- See `spec/compliance-matrix.yaml` and `.github/workflows/verification.yml` for coverage and drift checks.
