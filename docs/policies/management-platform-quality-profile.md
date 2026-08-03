# Management Platform Quality Profile

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Current Baseline

- shared baseline alignment across `aegaeon`, `../aegaeon-sdk`, and `../aegaeon-admin-console` is
  complete for the current local workspace snapshot
- this document is the ongoing shared quality profile and drift policy for the
  management-platform repositories; historical remediation context remains below

This plan tracks the cross-repository alignment of language-agnostic guardrails, TypeScript
strictness, and fail-closed drift detection across the backend-adjacent SDK and admin-console
repositories. It complements
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`.

The backend repository remains the reference baseline for the shared quality posture unless a
narrower exception is explicitly documented with an owner and expiry.

## 1. Scope and source of truth

Repositories in scope:

- this repository (`aegaeon`)
- sibling `../aegaeon-sdk`
- sibling `../aegaeon-admin-console`

Shared profile archetype:

- `polyglot-oss`, adapted to the actual Aegaeon repository boundaries

Reference baseline in this repository:

- `flake.nix` pre-commit / hook baseline
- `.github/workflows/ci.yml` and `.github/workflows/lint.yml`
- `commitlint.config.cjs`
- `.editorconfig`
- `spec/strict-types.current.json`

## 2. Adopted shared quality profile

### 2.1 Language-agnostic mandatory baseline

All three repositories are expected to keep the following aligned:

- identical `commitlint.config.cjs`
- local hook installation via `git-hooks.nix` / generated `.pre-commit-config.yaml`
- `commit-msg` and `pre-push` enforcement for commitlint
- `CI - Lint` as the stable repo-wide lint workflow name
- hosted `CI - Lint` coverage for:
  - `pre-commit run --all-files`
  - commit-range lint
  - PR-title lint
- broad file-hygiene hooks:
  - `editorconfig-checker`
  - EOF / whitespace / line-ending normalization
  - large-file / merge-conflict / submodule guards
  - JSON / TOML / YAML validation
  - `markdownlint`
  - `typos`
  - `actionlint`
  - shell / Nix checks where the repository owns those file types

### 2.2 TypeScript posture

The TypeScript surfaces intentionally follow the stricter `polyglot-oss` path for framework-heavy
or policy-heavy repositories:

- `aegaeon` keeps a source-managed root strict-types contract in
  `spec/strict-types.current.json` for repository policy scripts and verification-side TypeScript
- `../aegaeon-sdk` keeps a source-managed package/test/tool strict-types contract in
  `sdk/spec/strict-types.current.json`
- `../aegaeon-admin-console` keeps a strong `tsconfig.json` baseline including:
  - `strict`
  - `strictNullChecks`
  - `noImplicitAny`
  - `useUnknownInCatchVariables`
  - `exactOptionalPropertyTypes`
  - `noUncheckedIndexedAccess`
  - `noPropertyAccessFromIndexSignature`
  - `noImplicitOverride`
  - `noImplicitReturns`
  - `noFallthroughCasesInSwitch`
  - `noUnusedLocals`
  - `noUnusedParameters`
  - `forceConsistentCasingInFileNames`
  - `skipLibCheck: false`

Current linting choice:

- the TypeScript repositories intentionally stay on typed ESLint rather than switching to a pure
  Biome baseline because the surfaces are React / Storybook / policy-test / workflow-audit heavy
- this matches the skill guidance for `polyglot-oss`: use stronger typed ESLint-style guardrails
  for framework-heavy or policy-heavy TS surfaces instead of forcing a plain Biome-only profile

### 2.3 Repository-specific additive policy

Allowed additive policy, beyond the shared baseline:

- `aegaeon` adds Rust, proof, and Python helper guardrails that are not relevant to the sibling TS
  repositories
- `../aegaeon-sdk` adds release-custody, workflow-inventory, and client-claim policy audits
- `../aegaeon-admin-console` adds DCO sign-off checking and repository-boundary enforcement

Additive policy is acceptable only when it does not weaken the shared baseline.

### 2.4 Intentional EditorConfig exceptions

The repositories now share the same default EditorConfig posture and intentionally exempt only the
surfaces where hard line-length enforcement creates churn without improving source quality:

- all repositories:
  - Markdown: no indentation or line-length enforcement
  - `LICENSE` copies: no indentation or line-length enforcement
- `aegaeon`:
  - `flake.nix`: no line-length enforcement
- `../aegaeon-admin-console`:
  - `src/stories/assets/**`
  - `src/stories/Logo.tsx`
  - `src/stories/ToggleSwitch.tsx`
  - `openapi/**/*.json`
- `../aegaeon-sdk`:
  - `sdk/packages/**/dist/**`
  - `sdk/spec/**/*.json`
  - `sdk/tests/browser/**/*.html`

These are line-length scope exceptions only. They are not exemptions from EOF, line-ending,
charset, or trailing-whitespace policy unless explicitly stated in `.editorconfig`.

## 3. Current status snapshot (2026-05-14)

### 3.1 Backend baseline (`aegaeon`)

Confirmed:

- commitlint is enforced for `commit-msg` and `pre-push`
- hosted CI enforces `pre-commit --all-files`, commit-range lint, and PR-title lint
- the hook baseline includes broad file-hygiene coverage (`editorconfig`, whitespace/EOF, large
  files, merge conflicts, JSON/TOML/YAML, Markdown, typos, Nix, shell, GitHub Actions)
- the local TypeScript contract requires:
  - `strict: true`
  - `noImplicitAny: true`
  - `useUnknownInCatchVariables: true`
  - `exactOptionalPropertyTypes: true`
  - `noUncheckedIndexedAccess: true`
  - `noImplicitOverride: true`
  - `skipLibCheck: false`
- false overrides of strict flags are explicitly forbidden

### 3.2 SDK baseline (`../aegaeon-sdk`, local workspace snapshot on 2026-05-14)

Confirmed strengths:

- `commitlint.config.cjs` is byte-for-byte aligned with the backend baseline
- `flake.nix` now includes:
  - `commitlint`
  - `commitlint-pre-push`
  - file-hygiene hooks
  - JSON/TOML/YAML validation
  - `markdownlint`
  - `typos`
  - shell / Nix / GitHub Actions checks
  - Python helper checks
  - TypeScript lint / typecheck hooks
- `.github/workflows/lint.yml` exists and enforces:
  - `pre-commit run --all-files`
  - workflow-inventory audit
  - commit-range lint
  - PR-title lint
  - TypeScript lint / typecheck
  - strict-types audit
- `sdk/tsconfig.base.json`, `sdk/tsconfig.tests.node.json`,
  `sdk/tsconfig.tests.browser.json`, and `sdk/packages/runtime-node/tsconfig.json` now satisfy the
  backend-side strict-types contract
- `pnpm run audit:strict-types` passes locally

Resolved on 2026-05-14:

- `pre-commit run --all-files` now passes locally
- the remaining `editorconfig-checker` debt was resolved by:
  - reflowing real source / workflow files where line length mattered
  - carving out generated / copied / browser-fixture surfaces where hard line-length enforcement
    was not useful
- `LICENSE` copies are no longer mutated by the shared hook baseline

### 3.3 Admin-console baseline (`../aegaeon-admin-console`, local workspace snapshot on 2026-05-14)

Confirmed strengths:

- `commitlint.config.cjs` is byte-for-byte aligned with the backend baseline
- the effective hook baseline in `nix/flake/common.nix` now matches the backend profile for:
  - `commitlint`
  - file hygiene
  - JSON/TOML/YAML validation
  - `markdownlint`
  - `typos`
  - shell / Nix / GitHub Actions checks
  - TypeScript lint / typecheck hooks
- `.github/workflows/lint.yml` exists and enforces:
  - DCO sign-off checking
  - `pre-commit run --all-files`
  - commit-range lint
  - PR-title lint
  - repository-boundary checks
  - TypeScript lint / typecheck
- `tsconfig.json` is strong and keeps `skipLibCheck: false`
- `pnpm lint` and `pnpm typecheck` pass locally

Resolved on 2026-05-14:

- the `nix/flake/common.nix` shellHook interpolation bug was fixed and committed
- `pre-commit run --all-files` now passes locally
- the remaining `editorconfig-checker` debt was resolved by:
  - reflowing real source / workflow files where line length mattered
  - carving out Storybook and generated OpenAPI surfaces where hard line-length enforcement was
    not useful

### 3.4 Documentation drift

Confirmed:

- backend coordination notes had temporarily drifted while the sibling repositories moved ahead
- this repository needed to describe the local sibling-repository inventories accurately:
  - SDK: `verify-core.yml`, `ci.yml`, `lint.yml`, `playwright.yml`,
    `managed-provider-evidence.yml`, `client-claim-promotion.yml`,
    `released-client-readiness.yml`, `publish.yml`
  - admin-console: `ci.yml`, `lint.yml`, `stack-e2e.yml`

Resolved on 2026-05-14:

- the backend coordination docs in this repository were updated to match the actual sibling
  repository inventories
- the quality-alignment document now captures the current steady-state profile rather than a stale
  list of already-cleared blockers

## 4. Ongoing drift policy

Priority order:

1. keep the shared guardrail definitions synchronized across all three repositories
2. preserve the stable `CI - Lint` workflow and `Lint` job naming used for required checks
3. keep TypeScript strictness fail closed in hosted CI and source-managed contracts
4. document any exception before it lands and give it an explicit owner/scope

Required review rules:

- if `commitlint.config.cjs` changes in one repository, the same change must be evaluated for the
  other two in the same review window
- if `.editorconfig` changes, rerun `pre-commit run --all-files` in the affected repository and
  re-check whether the change should also be mirrored in the other repositories
- if a TS strict-types contract changes, rerun the contract audit in hosted CI before merge
- if a repository adds a new workflow that becomes branch-protection relevant, its display name and
  required-check posture must be documented in-repo

Recommended verification commands:

- backend:
  - `PRE_COMMIT_HOME=/tmp/pre-commit-aegaeon nix develop .#ci --command pre-commit run --all-files`
  - `nix develop .#ci --command npm run typecheck:ts`
  - `nix develop .#ci --command npm run audit:strict-types`
- SDK:
  - `PRE_COMMIT_HOME=/tmp/pre-commit-sdk nix develop . --command pre-commit run --all-files`
  - `nix develop . --command bash -lc "cd sdk && pnpm run lint"`
  - `nix develop . --command bash -lc "cd sdk && pnpm run audit:strict-types"`
- admin-console:
  - `PRE_COMMIT_HOME=/tmp/pre-commit-admin nix develop . --command pre-commit run --all-files`
  - `nix develop . --command pnpm lint`
  - `nix develop . --command pnpm typecheck`

## 5. Completion state

This plan's original remediation exit criteria are now met in the local workspace snapshot dated
2026-05-14:

- [x] all three repositories enforce the same commit-message policy shape:
  - identical `commitlint.config.cjs`
  - commit-range lint
  - PR-title lint
- [x] SDK and admin-console expose a documented, fail-closed hook baseline aligned with the backend
      profile or a documented approved subset
- [x] the SDK strict-types audit is green
- [x] SDK and admin-console both pass `pre-commit run --all-files`
- [x] backend coordination notes and sibling workflow inventories no longer disagree

Future work from here belongs to ongoing drift management, publication/org rollout, and broader
management-platform execution. It is no longer blocked on the baseline quality alignment itself.
