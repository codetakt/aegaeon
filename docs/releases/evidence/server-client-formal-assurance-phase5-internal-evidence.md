# Server / Client Formal Assurance Phase 5 Internal Evidence

Last updated: 2026-09-07

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

This document records the internal Phase 5 closure baseline for combined
server/client formal-assurance wording. It is not a public
`formally verified server and client` claim.

## Status of this historical record

The text below records the earlier bounded Phase 5 assessment. Its original
[bundle](https://github.com/codetakt/aegaeon/blob/a8dcb13ec6c636f294782db7bc747082247d67c8/docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json)
and [claim gate](https://github.com/codetakt/aegaeon/blob/a8dcb13ec6c636f294782db7bc747082247d67c8/spec/server-client-formal-assurance-claim.current.json)
are fixed at that commit. The approval labels in those records apply only to
those historical inputs; they do not approve the assurance contracts adopted later.

As of 2026-09-07, the working-tree bundle at the legacy filename is a **new,
unapproved preflight inventory** with a distinct bundle ID. Its generator records
pending reviews and includes unsatisfied obligations from the current claim gate.
The current gate remains inactive at `phase5-planned`. Regeneration refreshes
input identities and inventory only; it does not rerun proofs or security tests,
issue approval, or implement the new release-assurance evaluator. Use the
[assurance statement](../../verification/claims/assurance-statement.md) and its
linked contract status documents for current public claims.

## Historical status

- Internal Phase 5 status: complete for the bounded claim gate, TCB boundary,
  validator, generated evidence bundle, and internal engineering review scopes.
- Public server/client formal-assurance status: blocked until released-client
  activation, hosted evidence, publication custody, release security evidence,
  and external review are complete.
- Claim gate: `spec/server-client-formal-assurance-claim.current.json` remains
  `claim_active=false`.

## Boundary

The internal Phase 5 bundle supports only this future target wording:

- assumption-qualified formally verified OIDC/OAuth server
- released client/RP SDK containing a verified client core
- explicit runtime-adapter and external-dependency TCB boundaries

The internal bundle does not prove or claim:

- OS, browser, device, HSM, KMS, or host entropy sources
- third-party dependency correctness
- browser / Node / WebCrypto runtime correctness
- external IdP, DNS, TLS termination, or network behaviour
- browser storage, callback hosting, or application session persistence
- compat-only algorithm surfaces
- React, browser rendering, CSS/layout, or visual UI behaviour

## Canonical Bundle

The machine-readable bundle is:

- `docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json`

It records:

- the inactive Phase 5 claim gate
- all included claim boundaries and required TCB disclosures
- the non-public blocker closure report
- dependent released-client / promotion / Phase 4 gate snapshots
- complete internal evidence paths and hashes where non-recursive
- approved internal review scopes
- pending public-activation blockers

The non-public blocker closure report is:

- `docs/releases/evidence/phase5-pre-public-blockers.json`

It records that the local/client readiness snapshots, evidence schemas,
validators, and internal reviews are closed without changing public wording.
Publication-org branch-protection / release-secret rollout is also closed by the
ready sibling SDK rollout report. Its remaining blockers are activation-only
external/public tasks: fresh hosted evidence, release custody, external review,
release security archiving, released-client activation, and final public wording.

## Validation

Regenerate and check the bundle from the pinned dev shell:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_server_client_formal_assurance_phase5_evidence.py \
    && python3 scripts/validation/collect_server_client_formal_assurance_phase5_evidence.py --check'
```

Validate the claim gate and bundle:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_server_client_formal_assurance.py \
    docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json'
```

Validate the non-public blocker closure report:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_server_client_pre_public_blockers.py \
    docs/releases/evidence/phase5-pre-public-blockers.json'
```

The internal bundle may pass while public server/client wording remains blocked.
External completion requires `public_claim_ready=true`,
`release_stage=external-complete`, active released-client claim state, fresh
hosted evidence, release custody approval, and approved external security review.
