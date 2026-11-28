# Reviewing Dependency Updates

Last updated: 2026-11-20

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

## Proposal schedule

[Dependabot configuration](../../.github/dependabot.yml) requests the following
updates. It takes effect only after integration into the default branch.

| Ecosystem | Manifest locations | Version proposals |
| --- | --- | --- |
| GitHub Actions | `/`, `/.github/actions/*` | Weekly; seven-day cooldown; minor/patch group `actions` |
| Cargo | `/`, `/fuzz`, `/crates/kani-harness`, `/crates/pure`, `/dev-tools/sanitizer-smoke` | Disabled; alert-driven security group `cargo` |
| npm | `/` | Weekly; seven-day cooldown; minor/patch group `npm` |
| Docker | `/`, `/scripts/oidf_conformance/suite` | Monthly; minor/patch group `docker` |
| pip | `/examples/minimal-rp` | Monthly; individual proposals |
| OpenTofu | `/infra/tofu/*` | Monthly; minor/patch group `tofu` |
| Nix | `/`, `/.flakehub`, `/examples/preview-review` | Monthly; individual input proposals |

Each version-enabled configuration sets an open version-PR limit of two; this is
not a global repository cap. Major updates stay separate from minor/patch groups.
These limits and cooldowns do not limit security PRs. Cargo's required weekly
schedule and zero version-PR limit do not disable security updates; repository
alerts and security updates must be enabled. No vulnerability updates are
ignored, and no automerge is configured.
Docker Compose fixtures are outside this configuration.

Nix proposals update `flake.lock`. Dependabot does not advance immutable
references inside `flake.nix`; a lockfile update does not update every compiler,
verification tool or other toolchain pin. Review those separately. See GitHub's
[ecosystem support](https://docs.github.com/en/code-security/dependabot/ecosystems-supported-by-dependabot/supported-ecosystems-and-repositories)
and [configuration options](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference).

## Rust requirements and lockfiles

The root `Cargo.toml` lists twelve workspace members. They resolve together
under the root `Cargo.lock`. Each of its four excluded packages owns a separate
lockfile. Dependabot tracks all five Cargo directories. The online supply-chain
stage audits each lockfile using RustSec. The workspace, fuzz and sanitizer tool
also run Cargo Deny. The pure crate and Kani harness currently resolve only
local packages.

| Resolution root | Consumers | Direct or transitive `rustls` |
| --- | --- | --- |
| Workspace | attribute-mapping, server, postgres, client, ffi, jose, jose-tlv, observability, loadtest, aegaeon-core, crypto, xtask | Direct requirements below |
| `fuzz` | Fuzz targets with path dependencies into the product | Transitive, separately locked |
| `dev-tools/sanitizer-smoke` | Standalone sanitizer helper | None |
| `crates/pure` | Standalone pure crate | None |
| `crates/kani-harness` | Standalone Kani harness and its pure path dependency | None |

Inherit compatible requirements from `[workspace.dependencies]` when members
share the same version policy. Keep the default-features setting on the workspace
entry, and declare provider and protocol features on the consuming member.
Keep an independent exact requirement when the crate must resolve to the reviewed
patch. The current direct `rustls` group has four unconditional, non-optional
declarations. All four disable default features and enable `std` and `tls12`.

| Member | Cargo dependency kind | Requirement | Provider feature |
| --- | --- | --- | --- |
| `crates/client` | Normal | Inherits compatible workspace requirement | `ring` |
| `crates/crypto` | Normal | Inherits compatible workspace requirement | `aws_lc_rs` |
| `crates/server` | Normal | Exact reviewed patch for the serving binary | `ring` |
| `crates/loadtest` | Development | Exact reviewed patch for test fixtures | `ring` |

For a `rustls` security update, change the workspace baseline and both exact
pins together. Update the package in both the workspace and fuzz lockfiles
with `cargo update --manifest-path <manifest> -p rustls --precise <version>`.
Check the five lockfile diffs and run
`python3 -m unittest discover -s tests/ci -p test_shared_rustls.py`.
A new direct user, provider requirement, or independent version line requires
review of its entry in the group. Keep other packages' own requirements when
their major versions, dependency kinds, feature defaults or target conditions
need a different policy.

For a manifest-only refactor, compare `cargo metadata --locked --format-version 1`
for each resolution root. Compare `cargo tree --locked -e normal,build -f '{p} {f}'`
and `-e normal,build,dev` for each affected member and target. Also check the
combined workspace and fuzz trees, including all features used in CI.
Run the affected locked builds and tests, including fuzz targets, and the
dependency policy checks. Independent lockfiles use their own resolution even
when they build workspace crates by path.

## Review and integration

Bot generation is a proposal. Review the actual dependency diff, advisories,
compatibility and required evidence before integration. Preserve GitHub Actions
SHA pins. Cargo changes require the existing
[dependency policy](../policies/dependency-policy.md) and cargo-vet review;
do not add blanket exemptions to pass an update.

Messages use fixed `ci(deps)` for Actions and `chore(deps)` otherwise. Do not add
`include: scope`: npm development dependencies can then produce the unapproved
`deps-dev` scope. Commit headers and ordinary PR titles must fit the existing
72-character limit.
For PRs authored by `dependabot[bot]`, title length above 72 characters produces a
warning without blocking CI. All other title rules still apply. This exception
uses GitHub's PR author metadata, so a human-triggered rerun has the same result;
a missing or different author keeps the blocking limit. Branch names, labels and
the workflow actor do not grant the exception.

CI, Lint and Documentation use the same title-specific configuration. Commit
messages still use the unchanged base configuration, including the blocking
72-character header limit. Shorten generated commit headers when necessary.
The current commitlint rules permit long HTTP(S) URL lines, including comparison
links; ordinary body and footer lines still have their 100-character limit.

Inspect every actual bot commit signature before integration. GitHub's bot
signature does not authorize a new signing identity. Satisfy the configured
authorized-identity policy, preparing reviewed replacement commits signed with
the authorized identity when required, and verify every introduced signature
locally and on GitHub. Keep source, dependency, toolchain and artifact identities
bound to the evidence actually checked. Mandatory CI, reviews and applicable
merge-queue gates still apply; an update is not integrated merely because a bot
opened it or a local check passed.

## Activation checks

After default-branch activation, inspect the first hosted updater result for
each ecosystem: manifest discovery, grouping, labels, message format, signatures
and workflow results. Confirm security-update settings and the `dependencies`
label exist. Actions proposals also use `ci`; Cargo proposals use `security`.

Dependabot-triggered workflows normally have a read-only token and no ordinary
Actions secrets. Hosted bot permissions and cache behavior must be observed;
local configuration validation does not establish them. The KMS parity lane uses
LocalStack. Verify that dependency PRs build/load containers without publishing
images or attestations. Do not bypass failed bot CI or use `pull_request_target`
to execute untrusted update code. Diagnose failures within the existing trust
boundary; see GitHub's
[Dependabot Actions restrictions](https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions).
