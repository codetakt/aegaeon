# Reviewing Dependency Updates

Last updated: 2026-10-02

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

## Review and integration

Bot generation is a proposal. Review the actual dependency diff, advisories,
compatibility and required evidence before integration. Preserve GitHub Actions
SHA pins. Cargo changes require the existing
[dependency policy](../policies/dependency-policy.md) and cargo-vet review;
do not add blanket exemptions to pass an update.

Messages use fixed `ci(deps)` for Actions and `chore(deps)` otherwise. Do not add
`include: scope`: npm development dependencies can then produce the unapproved
`deps-dev` scope. Every title and commit header, including single-package updates,
must fit the existing 72-character limit. Shorten generated text when necessary.
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
