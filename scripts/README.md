# Scripts Directory Overview

## Layout

### `ci/`

- `run_act.sh` — Local GitHub Actions runs via `act`

### `fuzz/`

- `manage_fuzz_corpus.py` — Corpus history + archive maintenance

### `kani/`

- `run_kani.sh` — Main Kani harness runner (writes logs to `artifacts/kani/`)

### `lint/`

- `lint_actions.sh` — actionlint wrapper
- `lint_markdown.sh` — markdownlint-cli2 wrapper
- `lint_nix.sh` — nixfmt/statix/deadnix wrapper

### `flake/`

- `lint_rust_strict_packages.sh` — strict Clippy lane for the current Rust workspace packages
  (`aegaeon-client`, `aegaeon-core`, `aegaeon-crypto`, `aegaeon-jose`, `aegaeon-jose-tlv`,
  `aegaeon-loadtest`, `aegaeon-observability`, `aegaeon-server`, `ffi`, `xtask`); keeps
  `clippy::cargo` enabled while suppressing `clippy::multiple_crate_versions`
- `lint_server_clippy_inventory.sh` — `aegaeon-server` production lib/bin Clippy inventory gate
  for lints that were intentionally retired from the server source tree:
  `map_unwrap_or`, `ref_option`, `needless_pass_by_value`, `too_many_lines`, and
  `too_many_arguments`

### `sanitizers/`

- `run_sanitizers.sh` — ASan smoke harness
- `run_sanitizers_build_std.sh` — ASan build-std harness

### `verify/`

- `verify_fstar_ci.sh` — CI-style F* verification wrapper
- `verify_fstar_abstract.sh` — Abstract F* verification wrapper

### `validation/`

- `test_rfc_compliance.sh` — RFC MUST requirement regression test
- `build_publication_org_rollout_report.py` — Build and validate a
  publication-organization rollout report with audit-grade task details
- `collect_enterprise_readiness_phase1_evidence.py` — Collect validated Phase 1 evidence into a
  standard release archive and generate the release manifest plus enterprise bundle
- `run_oidc_kms_parity.sh` — fail-closed AWS KMS / LocalStack parity lane for OIDC `RS256`
  signing evidence
- `run_oidc_aws_kms_parity_from_tofu.sh` — read the AWS KMS parity OpenTofu outputs, run the
  real-AWS OIDC KMS parity test, generate `classification.json`, and validate the classification
  manifest
- `verify_rfc_tests.sh` — Lightweight RFC smoke run
- `validate_compliance_matrix.py` / `ensure_matrix_paths.py` — Fail-closed compliance matrix
  schema and evidence-path validators; use `--write-stubs` only for deliberate bootstrap work
- `check_docs_structure.py` — documentation structure audit for local links, README coverage,
  required document metadata, canonical-entry type labels, status vocabulary, curated `docs/`
  payload files, stale docs paths, and committed/generated Markdown indexes
- `validate_claim_gates.py` — Future-claim gate validator for enterprise-readiness,
  certification, bounded admin-UI assurance, activation semantics, and evidence-link checks
- `validate_admin_ui_assurance.py` — Phase 3 admin UI assurance validator for the bounded
  management-session / management-client / OpenAPI security boundary
- `validate_certification_evidence_bundle.py` — Phase 2 certification evidence bundle validator;
  separates internal completion from external/public certification activation
- `validate_enterprise_readiness_evidence_bundle.py` — Enterprise-readiness evidence bundle validator
- `validate_enterprise_readiness_phase1.py` — Final Phase 1 closure wrapper that requires complete
  canonical enterprise evidence IDs, an inactive claim gate, matching bundle claim gate, and approved
  enterprise evidence bundle
- `validate_phase4_activation_preflight.py` — Phase 4 internal preflight validator that verifies
  inactive claim gates, internal bundles/validators, and an explicit external/public blocker list
- `build_enterprise_slo_baseline_from_hosted_evidence.py` — Build a partial enterprise SLO baseline
  manifest from hosted readiness evidence before full load-scenario evidence is available
- `validate_enterprise_slo_baseline.py` — Enterprise SLO baseline manifest validator
- `validate_kms_hsm_classification.py` — KMS/HSM OIDC signing classification manifest validator
- `validate_managed_provider_evidence.py` — Managed-provider evidence validator
- `validate_publication_org_rollout.py` — Publication-organization rollout report validator
- `validate_release_security_evidence.py` — Release security evidence manifest validator
- `validate_sdk_release_publication_bundle.py` — SDK release-publication bundle validator; use
  `--require-enterprise-ready` for Phase 1 enterprise-readiness evidence
- `test_enterprise_readiness_validators.py` — Local semantic self-tests for the Phase 1 evidence
  validators and enterprise bundle wiring

### `release/`

- `create_release.sh` — Create an annotated version tag and release artefacts
- `generate_sbom.sh` — SBOM (CycloneDX) + grype scan

## Common Commands

```bash
# RFC MUST requirement checks
./scripts/validation/test_rfc_compliance.sh

# OIDC AWS KMS parity lane (LocalStack on localhost:4566)
nix develop .#ci --command bash scripts/validation/run_oidc_kms_parity.sh

# OIDC AWS KMS hosted / production-style parity lane
# Requires infra/tofu/oidc-aws-kms-parity to be applied first.
AEG_KMS_CLASSIFICATION_REVIEWER=<reviewer-id> \
nix develop .#ci --command bash scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh

# Full verification/audit suite (deny/audit/vet/fuzz/asan/SBOM/geiger/udeps)
nix run .#security-suite

# ASan smoke (minimal)
nix run .#sanitizer-smoke

# Kani harnesses
# (smoke) minimal suite
nix develop -c ./scripts/kani/run_kani.sh

# (regression) thicker suite for regressions
AEG_KANI_SUITE=regression nix develop -c ./scripts/kani/run_kani.sh

# Release artefacts / SBOM generation
./scripts/release/create_release.sh v1.0.0
./scripts/release/generate_sbom.sh

# Future claim-gate policy validation
nix develop .#default --command bash -c 'python3 scripts/validation/validate_claim_gates.py --all'

# Documentation structure audit
python3 scripts/validation/check_docs_structure.py

# Generated documentation index
python3 scripts/validation/check_docs_structure.py --print-index

# Refresh committed documentation index
python3 scripts/validation/check_docs_structure.py --write-index

# Phase 2 certification internal evidence validation
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_certification_evidence_bundle.py \
    docs/releases/evidence/certification-phase2-internal-bundle.json'

# Phase 2 certification validator semantic self-test
nix develop .#default --command bash -c 'python3 scripts/validation/test_certification_evidence_validators.py'

# Phase 3 admin UI assurance internal evidence validation
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_admin_ui_assurance.py \
    docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json'

# Phase 3 admin UI assurance validator semantic self-test
nix develop .#default --command bash -c 'python3 scripts/validation/test_admin_ui_assurance_validators.py'

# Phase 4 claim activation preflight validation
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_phase4_activation_preflight.py \
    docs/releases/evidence/phase4-claim-activation-preflight.json'

# Phase 4 claim activation preflight semantic self-test
nix develop .#default --command bash -c 'python3 scripts/validation/test_phase4_activation_preflight.py'

# Enterprise-readiness validator semantic self-test
nix develop .#default --command bash -c 'python3 scripts/validation/test_enterprise_readiness_validators.py'

# SDK released-client publication evidence validation
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_sdk_release_publication_bundle.py --require-enterprise-ready <bundle.json>'

# Enterprise-readiness final activation-review bundle validation
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_readiness_evidence_bundle.py --require-approved <bundle.json>'

# Phase 1 enterprise-readiness closure check
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_readiness_phase1.py <bundle.json>'

# Phase 1 evidence archive collection
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
    --release-id <release-id> \
    --publication-org-rollout <publication-org-rollout-report.json> \
    --sdk-release-publication-bundle <release-publication-bundle.json> \
    --managed-provider-evidence <managed-provider-evidence.json> \
    --kms-classification <kms-classification.json> \
    --enterprise-slo-baseline <enterprise-slo-baseline.json> \
    --build-log <nix-flake-check.log> \
    --verification-log <verified-reqs.log> \
    --security-log <security-suite.log> \
    --sbom <aegaeon-sbom.json> \
    --support-response <support-response.md>'

# Phase 1 source evidence preflight without writing an archive
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
    --release-id <release-id> \
    --publication-org-rollout <publication-org-rollout-report.json> \
    --sdk-release-publication-bundle <release-publication-bundle.json> \
    --managed-provider-evidence <managed-provider-evidence.json> \
    --kms-classification <kms-classification.json> \
    --enterprise-slo-baseline <enterprise-slo-baseline.json> \
    --build-log <nix-flake-check.log> \
    --verification-log <verified-reqs.log> \
    --security-log <security-suite.log> \
    --sbom <aegaeon-sbom.json> \
    --support-response <support-response.md> \
    --preflight-only'

# Publication organization rollout report generation
nix develop .#default --command bash -c \
  'python3 scripts/validation/build_publication_org_rollout_report.py \
    --owner <owner> \
    --repo aegaeon-sdk \
    --branch main \
    --task publication_org_branch_protection=done=<audit-detail> \
    --task publication_org_secret_rollout=done=<audit-detail> \
    --out <publication-org-rollout-report.json>'
```

Python dependencies are provided by the Nix devShell (`nix develop`).
