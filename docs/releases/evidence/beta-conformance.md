# Beta Conformance Summary

Last updated: 2026-07-07

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-03-30):** This is a point-in-time conformance summary. For current machine-generated evidence, use `artifacts/conformance/` and the releases index in `docs/releases/README.md`.

Date: 2026-02-18 (Phase 11 update)

## Current status

- Verification-boundary note: OIDF conformance results are strong runtime interoperability evidence, but they do not by themselves widen the formal verification claim. The later `RS256 Required Slice` and `RS256 Interop Slice` boundary promotions are the current claim-widening evidence; use the current release bundle instead of this historical summary for claim wording.

| Plan | Status | Notes |
|------|--------|-------|
| `oidcc-config-certification-test-plan` | PASS | Baseline OP discovery validation |
| `oidcc-basic-certification-test-plan` | PARTIAL | Recorded local TLS run: 22 PASSED / 3 REVIEW / 8 WARNING / 2 SKIPPED / 0 FAILED |
| `oidcc-formpost-basic-certification-test-plan` | READY | Form Post Response Mode fully implemented; plan available for execution |

- The OpenID conformance-suite checkout exposes **FAPI/OIDC-centric plans** (see `/api/plan/available`).
- The previously referenced plan names (`oauth2-test-plan`, `oauth2-pkce-test-plan`, etc.) are **not present** in the upstream suite and must not be treated as evidence.
- Baseline OIDC evidence is now produced via the OP plan `oidcc-config-certification-test-plan` using the Docker+nginx TLS stack in `scripts/oidf_conformance/`.
- CI workflow (`.github/workflows/oidf-conformance.yml`) updated with correct OIDF plan names and enabled.
- Local TLS automation now captures and uploads real screenshot evidence for modules that require operator review.

## Phase 11 changes

### DPoP Nonce (RFC 9449 Section 5)
- **Implemented**: Server-side nonce generation, time-bounded rotation with grace period
- **Endpoint behavior**: `DPoP-Nonce` header returned in DPoP error responses + `use_dpop_nonce` error code
- **Policy control**: `AEGAEON_REQUIRE_DPOP_NONCE` env var (default: `true`), `AEGAEON_DPOP_NONCE_TTL_SECS` (default: 300)
- **F-star verification**: `fstar/dpop/Dpop.Nonce.fst` — 4 lemmas (freshness, binding, rotation safety, enforcement), 0 admit
- **Compliance matrix**: 4 new entries (9449-011 through 9449-014)
- **Tests**: 10 new unit tests in `crates/server/src/middleware/dpop.rs`

### JAR metadata advertisement
- **Fixed**: `request_object_signing_alg_values_supported` now initialized in OIDC discovery struct
- Algorithms: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384
- Previously was `None` in the discovery struct (only populated at runtime in `web/mod.rs`)

### CI workflow
- Plan names corrected to actual OIDF upstream names
- `AEGAEON_OIDF_CONFORMANCE_ENABLED` set to `1`
- Plan discovery step validates availability before running
- Correct API interaction pattern matching `run_oidcc_basic_plan.sh`

## Evidence (OIDF OP plan)

### `oidcc-config-certification-test-plan` (baseline, PASS)

- Current artifact pointer (overwritten on each run):
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/results.json`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/export.zip`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/plan.json`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/suite_commit.txt`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/latest_run_id.txt`
- Run-specific (timestamped):
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/results_<run_id>.json`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/export_<run_id>.zip`
  - `artifacts/conformance/oidcc-config-certification-test-plan/plan-export/files_<run_id>/test-log-*.json`

### `oidcc-basic-certification-test-plan` (execution evidence, PARTIAL)

- Current artifact pointer (overwritten on each run):
  - `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/results.json`
  - `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/export.zip`
  - `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/plan.json`
  - `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/suite_commit.txt`
  - `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/latest_run_id.txt`
- Notes:
  - Recorded local TLS run produced `22 PASSED / 3 REVIEW / 8 WARNING / 2 SKIPPED / 0 FAILED`.
  - Real screenshot evidence is generated under `artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_<run_id>/` and uploaded automatically when `OIDF_AUTO_UPLOAD_EVIDENCE=1`.
  - Remaining `REVIEW` modules are:
    - `oidcc-prompt-login`
    - `oidcc-max-age-1`
    - `oidcc-ensure-registered-redirect-uri`
  - These remain `REVIEW` because the upstream conformance-suite marks image-based evidence uploads as review-required; they no longer fail and no longer remain `WAITING`.
  - `oidcc-response-type-missing` now passes in the automated local TLS flow.
  - `oidcc-ensure-request-object-with-redirect-uri` remains `SKIPPED`, which matches Aegaeon's `request_uri`-only posture.

#### REVIEW handling policy

- Treat `REVIEW` as **non-blocking local evidence** when all of the following are true:
  - the module result is `FINISHED/REVIEW` with no `FAILED` result in the same plan run;
  - `run_<timestamp>.log` contains `evidence uploaded:` for the module;
  - the matching screenshot is present under `screenshots_<run_id>/`.
- Under the recorded local TLS run, the three remaining `REVIEW` modules satisfy that policy:
  - `oidcc-prompt-login` (`KaCDGB63sykT1v2`)
  - `oidcc-max-age-1` (`NJJe2svewJ7YSxE`)
  - `oidcc-ensure-registered-redirect-uri` (`vAOO5JgXwYcuxpq`)
- These modules remain review-gated because the upstream suite requires a human decision over uploaded image evidence. They are therefore:
  - acceptable for Aegaeon's beta self-certification evidence set; and
  - still incomplete for any formal OIDF certification claim until the upstream review step is completed.

### `oidcc-formpost-basic-certification-test-plan` (ready for execution)

- Form Post Response Mode is fully implemented (`crates/server/src/form_post.rs`)
- Discovery advertises `response_modes_supported: ["query", "form_post"]`
- Expected to pass with no code changes
- Evidence will be archived at: `artifacts/conformance/oidcc-formpost-basic-certification-test-plan/plan-export/`

### Bootstrap (available plans / suite commit)

- `artifacts/conformance/bootstrap/plan_available_<run_id>.json` / `.txt`
- `artifacts/conformance/bootstrap/suite_commit_<run_id>.txt`

## Scope decisions

- **JAR `request` parameter (not via PAR)**: N/A — Aegaeon only supports `request_uri` (PAR-style). This is intentional per OAuth 2.1 / RFC 9700 guidance.
- **FAPI / JARM**: Deferred (Phase 12+)
- **OIDC Session Management / Front-Channel Logout**: Intentionally excluded (BCP-deprecated per RFC 9700)
- **Formal OIDF certification**: Not in scope (self-certification with published evidence is sufficient for beta)

## Repro (local-only, HTTPS required by upstream suite)

1) Prepare env:

```bash
cp scripts/oidf_conformance/.env.example scripts/oidf_conformance/.env
```

1) Provide certificates:

- Recommended (DNS-01): `docker compose ... --profile acme run --rm acme`
- Local certs: place `${CERT_PRIMARY_DOMAIN}.crt` / `.key` under `scripts/oidf_conformance/certificates/`

1) Discover available plans:

```bash
./scripts/oidf_conformance/discover_plans.sh
```

1) Run a specific plan:

```bash
OIDF_PLAN_NAME=oidcc-basic-certification-test-plan ./scripts/oidf_conformance/run_oidcc_basic_plan.sh
```

If you publish nginx on non-443 host ports, include the port in both `AEGAEON_PUBLIC_BASE_URL` and
`SUITE_PUBLIC_BASE_URL` (see `.env.example`).
