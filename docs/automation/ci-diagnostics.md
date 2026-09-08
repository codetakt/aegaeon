# CI Diagnostics and Evidence

Last updated: 2026-09-08

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, security reviewers, CI maintainers

## Supported tools

Repository-wide Nix formatting uses `treefmt --ci` from the pinned
`pkgs.nixfmt-tree` wrapper. Pre-commit can still pass individual Nix files to
`nixfmt`; directory traversal belongs to the wrapper.

All direct external Action references in repository workflows and local Actions
are pinned to commit digests. Version comments identify the reviewed releases.
Cosign and Codecov retain their existing major versions. The Rust toolchain Action
is pinned separately from its explicit `stable` or `nightly` input; those compiler
channels remain rolling. An Action digest fixes its code, not every tool or nested
dependency it downloads.

The JavaScript Actions used for checkout, artifacts, attestation, Nix installation,
Docker metadata/login, release publication, issue creation, SARIF upload, GitHub
scripts, and Java setup use Node 24 releases.
Hosted runners must support Node 24 (runner 2.327.1 or newer); authenticated
Git operations inside container actions with the current checkout require 2.329.0
or newer. Artifact downloads retain digest-mismatch failures and normal archive
extraction. No opt-out from checkout's fork-PR protections is configured.

Root JavaScript and TypeScript tooling uses ES modules. CommonJS configuration
files use the explicit `.cjs` extension, including ESLint and commitlint. This
avoids Node reparsing unclassified TypeScript without changing the SDK's source
contracts or introducing a second compilation step.

## Provenance and coverage evidence

The deprecated `actions/attest-sbom` wrapper is replaced by `actions/attest`.
Build provenance also uses the generic Action to share the attestation interface;
the upstream `actions/attest-build-provenance` README does not currently mark that
wrapper as deprecated.

The provenance job takes the attestation bundle from `actions/attest`'s
`bundle-path` output. Before archiving it, `gh attestation verify` checks each built
subject against that bundle, the repository identity, and the SLSA v1 predicate.
An absent bundle, failed verification, or missing upload input fails the job.
An attestation records the stated build; it does not establish the product's
release assurance contract or a SLSA certification level.

The SBOM job uses the same supported attestation Action with an explicit
`sbom-path`. Its SBOM predicate and subject remain separate from build provenance.
These publication paths retain their non-PR conditions. A successful PR workflow
does not test hosted attestation publication; confirm bundle verification and
artifact retrieval in the subsequent main run.

Coverage upload consumes the explicitly generated, nonempty `lcov.info`. Codecov
file discovery and unrelated coverage-provider plugins are disabled because
`cargo llvm-cov` already produced the report. The uploader's signature checks
remain enabled. Missing local ownertrust for a correctly verified uploader key
does not justify assigning global trust to that key.

LocalStack uses `GATEWAY_LISTEN` for the existing port 4566. The KMS parity lane
continues to check the service and signing behavior.

## dudect acceptance policy

The default absolute-t warning boundary is 3.5 and the failure boundary is 4.5.
Both bands block CI: a result above 3.5 needs investigation even if it has not
crossed 4.5. The p-value direction is reversed: values below 0.05 block, with
values below 0.01 classified as failures. When both metrics are reported, the
existing p-value precedence is retained. The minimum trace count is 16,000.

Overrides must preserve nonempty warning bands, finite thresholds, valid p-value
ranges, and a positive trace minimum. Invalid policies fail instead of being
silently normalized. Reported non-finite statistics are rejected. The
`verified-reqs` gate runs regression checks for these rules before checking the
recorded timing evidence.

## Remaining diagnostic boundaries

This tooling update does not establish that every CI warning has been resolved.
The following work requires separate changes and evidence:

| Area | Required follow-up |
| --- | --- |
| Nix container vulnerability coverage | Bind inventories of the shipped Rust dependencies and native libraries to the image, use scanners that recognize those inventories, and reject empty coverage. The current Trivy image result with no recognized packages cannot support a vulnerability-clean claim. |
| Native PS256 and extraction | Distinguish intentional proof-only backends from required release backends, and establish which Low* declarations reach compiled artifacts. |
| Verification and dependencies | Repair first-party proof diagnostics and obsolete lint expectations; update compatible upstream Rust-overlay, F*, KaRaMeL, HACL*, and dependency sets with their corresponding verification. |
| Fixture services and external tools | Validate observability-service migrations and test authentication/persistence settings; retain explained vendor/platform notices and key-trust diagnostics. |
| Cache behavior | The retired magic-nix-cache route was replaced separately. Confirm authenticated FlakeHub restores and uploads in current main runs; successful fallback alone is insufficient. |

Suppressing a warning or weakening a gate does not complete these tasks. The
GitHub-managed review workflow and upstream tool internals also have diagnostics
outside this repository's direct Action configuration.

## Local checks

```bash
nix develop .#ci --command bash scripts/lint/lint_nix.sh
nix develop .#ci --command actionlint
nix develop .#integrity --command python3 scripts/validation/test_dudect.py
nix build .#verified-reqs --no-link -L
nix develop .#ci --command npm run lint:ts
nix develop .#ci --command npm run typecheck:ts
```
