# Key Inventory — Verified Core & SDK Artefacts

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Security

Audience: security reviewers, maintainers

> **Status note (2026-03-08):** This is an operational inventory and process note. It is not a live key registry; current active material and permissions remain in the relevant secret-management system and release workflow.

This document tracks the lifecycle of cryptographic material involved in building and distributing Verified Core artefacts and SDK packages. It complements the release runbook (`docs/operations/sdk-release.md`) and CI guidance (`docs/program-management/initiatives/sdk/sdk-ci-plan.md`).

## 1. Key Classes

| Name | Purpose | Location | Rotation | Notes |
|------|---------|----------|----------|-------|
| `verified-core-release-ed25519` | Signs the canonical Verified Core WASM artefacts bundled with OSS / SaaS releases | AWS KMS asymmetric key (`alias/aegaeon/verified-core-release`, ARN `arn:aws:kms:us-east-1:123456789012:key/0b53f0a7-8d68-4f2b-8b4f-5c2fe0ad0c3e`) | Annual (Q4) — owned by Release Engineering | Public key distributed as `VERIFIED_CORE_PUBKEY`; rotation ticket: `SEC-KEY-2024-019` |
| `verified-core-dev-ed25519-*` | Signs development-only or preview Verified Core builds | 1Password Vault `Aegaeon Dev Keys` | On demand (per branch / per environment) | Generated locally via `ssh-keygen`, uploaded by `op` CLI (see Section 2) |
| `sdk-provenance-cosign` (optional) | Produces cosign attestations / provenance for published npm/crate artefacts | HSM/KMS or 1Password (depending on policy) | Annual | Used by `publish.yml` once provenance attestation is enabled |

## 2. Generating Development Keys (Ed25519)

Use `ssh-keygen` + 1Password CLI (`op`) to create and escrow a key pair. The private key must never remain on disk after upload.

```bash
tmpdir=$(mktemp -d)
ssh-keygen -t ed25519 \
  -C "aegaeon-dev-verified-core-$(date +%Y%m%d)" \
  -f "$tmpdir/aegaeon-dev-verified-core"

OP_VAULT="Aegaeon Dev Keys"
OP_TITLE="Dev Verified Core Signing $(date +%Y-%m-%d)"

op item create \
  --vault "$OP_VAULT" \
  --category="secure-note" \
  --title "$OP_TITLE" \
  --tags sdk,verified-core,dev \
  "private_key=password:$(cat "$tmpdir/aegaeon-dev-verified-core")" \
  "public_key=concealed:$(cat "$tmpdir/aegaeon-dev-verified-core.pub")"

op document create "$tmpdir/aegaeon-dev-verified-core" \
  --vault "$OP_VAULT" \
  --title "$OP_TITLE (private-key)"
op document create "$tmpdir/aegaeon-dev-verified-core.pub" \
  --vault "$OP_VAULT" \
  --title "$OP_TITLE (public-key)"

shred -u "$tmpdir/aegaeon-dev-verified-core" "$tmpdir/aegaeon-dev-verified-core.pub"
rmdir "$tmpdir"
```

Record the new key in the table above (description, creation date, intended environment). When the key is deprecated, mark it as `revoked` with the revocation date.

## 3. Accessing Keys in CI

For GitHub Actions or other CI jobs:

```yaml
- name: Fetch Verified Core signature
  run: |
    op read "op://Aegaeon Dev Keys/Dev Verified Core Signing 2026-01-15/public_key" > /tmp/verified-core-dev.pub
    op document get "Dev Verified Core Signing 2026-01-15 (signature)" --vault "Aegaeon Dev Keys" > /tmp/verified_core.wasm.sig
```

Ensure the workflow uses a Secrets Automation token with read-only access to the vault entry.

## 4. Rotation / Incident Handling

- Production key rotation is tracked in the governance calendar (see `docs/security/tcb-inventory.md`). Notify release engineering two weeks prior.
- If any key is suspected compromised, revoke immediately:
  - Update this inventory (status = `revoked`, include incident ticket).
  - Purge cached artefacts signed with the compromised key.
  - Re-issue artefacts with a fresh key.
