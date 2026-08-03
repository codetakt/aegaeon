# Verification Ops Guide

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

Operational guide for maintaining the **VerifiedReqs** invariant in the
Aegaeon compliance matrix.

---

## 1. Overview

**VerifiedReqs** is the set of compliance-matrix entries that carry
assumption-qualified formal proofs:

```text
VerifiedReqs = { r in compliance-matrix
               | r.status = verified
               AND exists p in r.proof : p.type in {fstar, tamarin, kani, everparse, lowstar, hacl} }
```

**Formal boundary note:** In realistic von Neumann systems with I/O, the project
cannot formally prove computational hardness (EUF‑CMA/collision resistance)
except as theorem premises, OS/device entropy sources (modeled as external
contracts), or external host/storage behaviour (modeled as explicit interface
contracts or TCB boundaries). These remain outside the formal claim.

Every entry with `status: verified` **must** have at least one formal proof
reference. Entries without proof references must use `status: implemented`,
`partial`, or another non-verified status.

Every formal proof block on a verified entry must be grounded. A row no longer
passes because one sibling block resolves while another F*, Tamarin, Kani,
EverParse, Low*, or HACL block floats.

**Why this matters:** The project's formal verification claim
([claim-definition.md &sect;0.2](../claims/assurance-case/claim-definition.md#02-claim-scope)) applies
*only* to VerifiedReqs. An entry incorrectly marked `verified` without a proof
reference inflates the claim and misrepresents the verification posture.

**Crypto profile boundary:** The strong‑constraint claim applies only to
instances configured with the **verified allowlist** (see
`docs/verification/claims/crypto-allowlist.md`). Requirements that depend on
non‑verified crypto paths must not be promoted to `verified` unless the
verified allowlist is in effect for the relevant IdP/RP/chain instance.
Boundary-closure exceptions (including the promoted OIDC `RS256 Required Slice`
and `RS256 Interop Slice`) must be recorded in the allowlist, the boundary
roadmap, and the compliance matrix before any claim wording changes.

---

## 2. Promoting a requirement to `verified`

All of the following conditions **must** be met before setting
`status: verified` on a compliance-matrix entry:

1. **Formal proof entry** &mdash; At least one `proof[]` entry with `type` in
   the canonical set: `fstar`, `tamarin`, `kani`, `everparse`, `lowstar`,
   `hacl`. (Note: `dudect` is empirical, not formal; see &sect;4.)
2. **File exists** &mdash; The `file` field must point to an existing verified
   module (F\* `.fst`/`.fsti`, Tamarin `.spthy`, Kani harness, EverParse
   `.3d`, etc.).
3. **Lemma match** &mdash; If the proof entry uses a `lemma:` field, `file:`
   **must also be present** so the identifier can be grepped. The CI script
   rejects `lemma:` without a `file:` reference (see &sect;3).
4. **Semantic labels** &mdash; If the proof entry uses `invariant:` or
   `refinement:` fields, the referenced file must exist, be verified (0 admit),
   and the label must match a real identifier in that file. For refinement-type
   evidence, cite the relevant type, val, or lemma identifier directly.
5. **Model fidelity** &mdash; F* proof files used by verified rows must be
   classified in `docs/verification/claims/model-fidelity.yaml`. Modules marked
   `toy-stub` cannot ground verified entries.
6. **CI green** &mdash; The corresponding verification CI gate must pass
   (`nix build .#verify-fstar`, `.#verify-tamarin`, `.#verify-kani`, etc.).

---

## 3. Proof reference semantics

The compliance matrix uses three kinds of F\* proof identifiers:

| Field | Convention | Match requirement |
|-------|-----------|-------------------|
| `lemma:` | Exact F\* lemma/val name (`let lemma_xxx` or `val lemma_xxx`) | Must match a greppable identifier in the referenced file |
| `invariant:` | Identifier for a type-system property | Must match a greppable identifier in the referenced file |
| `refinement:` | Identifier for a refinement type constraint | Must match a greppable identifier in the referenced file |

**File path fields:** Proof entries **must** use `file:` to specify the
verification artifact. All legacy proof-block `module:` fields have been
migrated to `file:`. The entry-level `module:` field points to the Rust
implementation and is **not** used as a proof-file reference.

**Tamarin:** `lemma:` names must match actual `lemma <name>` declarations in
the referenced `.spthy` file.

All formal blocks are checked. Remove stale sibling blocks, normalize labels to
real identifiers, or replace them with the actual lemma/type that carries the
claim before setting or keeping `status: verified`.

---

## 4. Canonical proof type set

| Type | Framework | Quality | Typical evidence |
|------|-----------|---------|-----------------|
| `fstar` | F\* type system | Formal | `.fst`/`.fsti` module with 0 admit |
| `lowstar` | F\* + KaRaMeL extraction (Low\*) | Formal | Low\* module or extracted C |
| `hacl` | HACL\* verified crypto | Formal | Integration module |
| `tamarin` | Tamarin Prover (symbolic Dolev-Yao) | Formal | `.spthy` model with verified lemmas |
| `kani` | Kani bounded model checker | Formal | Rust harness file |
| `everparse` | EverParse parser verification | Formal | `.3d` schema or generated validator |
| `dudect` | dudect constant-time testing | Empirical | Timing-test harness |

These seven types map to four verification frameworks plus one empirical
testing tool (`dudect`). Any `proof[].type` value outside this set is
**not** a formal proof reference and does not
qualify the entry for `status: verified`.

---

## 5. Checklist: adding or modifying a `verified` entry

### Promotion checklist

- [ ] `proof[].type` is in the canonical set (&sect;4)
- [ ] `proof[].file` exists on disk and is verified (check CI)
- [ ] `proof[].lemma` matches a real identifier in the file (if present)
- [ ] `invariant:`/`refinement:` labels match real identifiers in the file
- [ ] F* proof files are covered by `model-fidelity.yaml`
- [ ] No verified row cites a `toy-stub` F* module
- [ ] CI passes: `python3 scripts/validation/verify_verified_reqs.py --strict`
- [ ] Verification gate passes: `nix build .#verify-fstar` (or relevant gate)
- [ ] If adding a new `assume val`, update the
      [Assumption Register](../claims/assumptions/current-register.md) with category, risk, and
      reducibility assessment
- [ ] If the requirement depends on JWS/JWT/JWE crypto, confirm the
      **verified allowlist** applies to the instance and the implementation
      is HACL*/EverCrypt‑backed.

### Downgrade / removal checklist

- [ ] Update [claim-definition.md](../claims/assurance-case/claim-definition.md) if the claim scope changes
- [ ] Document the reason in the PR description
- [ ] If the entry moves to `implemented`, confirm it still has adequate
      test coverage

---

## 6. CI validation

### `verify_verified_reqs.py`

The script `scripts/validation/verify_verified_reqs.py` validates the
VerifiedReqs invariant on every PR when run with `--strict`:

| Check | Description |
|-------|-------------|
| Formal type | Every `status: verified` entry has `proof[].type` in the canonical set |
| File existence | Every `proof[].file` resolves to a real path |
| Lemma + file | Every `proof[].lemma` has a `proof[].file` and the identifier is greppable |
| All-block grounding | Every formal proof block on a verified entry is grounded |
| Model fidelity | Every checked-in F* module is classified and `toy-stub` modules are rejected as verified grounding |
| Runtime link | Every `status: verified` entry has a `runtime_link` pointing to an existing Rust file |

**Failures block merge.** Fix by either:
1. Adding the missing proof reference, or
2. Downgrading `status` to `implemented` if no formal proof exists.

### Verification gates

| Gate | Command | What it checks |
|------|---------|---------------|
| F\* | `nix build .#verify-fstar` | All F\* modules type-check, 0 admit |
| Tamarin | `nix build .#verify-tamarin` | All `.spthy` lemmas verified |
| Kani | `nix build .#verify-kani` | All harnesses pass within bounds |
| EverParse | (included in F\* gate) | `.3d` schemas verified |

---

## 7. Common operations

### Adding a new formally-verified requirement

1. Write the proof (F\* module, Tamarin model, Kani harness, etc.)
2. Verify locally: `nix build .#verify-fstar` (or relevant gate)
3. Add the entry to `spec/compliance-matrix.yaml` with `status: verified`
   and a `proof[]` entry referencing the file and lemma
4. Confirm the F* file is classified in
   `docs/verification/claims/model-fidelity.yaml`
5. Run `python3 scripts/validation/verify_verified_reqs.py --strict`
6. Commit and open PR

### Finding unverified entries that could be promoted

Search for entries with `status: implemented` that have matching F\*/Tamarin
proofs already in the codebase:

```bash
# Find F* modules not yet referenced in the matrix
grep -rn 'let lemma_' fstar/ --include='*.fst' | \
  cut -d: -f1 | sort -u
```

### Auditing assume vals after a proof campaign

After reducing assume vals, update:
1. [current-register.md](../claims/assumptions/current-register.md) &mdash; register and counts
2. [verification-scope.md](../claims/assurance-case/verification-scope.md) &sect;1.1 &mdash; F* scope
3. Short claims in README.md, SECURITY.md, CHANGELOG.md

---

## 8. Runtime linkage

Every `status: verified` entry must have a `runtime_link` field pointing to
the Rust implementation file where the verified behaviour is enforced.

### Adding `runtime_link` to a new entry

1. If `module` is already a `crates/` path, use it as `runtime_link`
2. If `module` is an F\* spec (`fstar/`), look up the corresponding Rust file
   in `FSTAR_TO_RUST_MAP` inside `scripts/validation/populate_runtime_link.py`
3. If `module` is a docs path, use the first `crates/` path from `tests[]`
4. Run `python3 scripts/validation/verify_verified_reqs.py --strict` &mdash;
   Rule 4 checks `runtime_link` presence and file existence

### Drift detection

After modifying a Rust file that is a `runtime_link` target:

```bash
# Check which entries are affected
python3 scripts/validation/check_runtime_drift.py --check

# Re-generate manifest after confirming the proof still applies
python3 scripts/validation/check_runtime_drift.py --generate
```

See [runtime-linkage.md](runtime-linkage.md) for the full feature-flag
matrix and liveness classification.

---

## 9. Cross-references

| Document | What it covers |
|----------|---------------|
| [claim-definition.md &sect;0.2](../claims/assurance-case/claim-definition.md#02-claim-scope) | VerifiedReqs formal definition and claim statement |
| [current-register.md](../claims/assumptions/current-register.md) | Assumption Register (12 assume vals across 8 files: 6 crypto, 2 HACL* linkage, 1 EverParse linkage, 2 OIDC hash runtime linkage, 1 WASM host) |
| `scripts/validation/verify_verified_reqs.py` | CI validation script for VerifiedReqs invariant |
| `spec/compliance-matrix.yaml` | Source of truth for all requirement entries |
| `spec/compliance-matrix.schema.json` | YAML schema for matrix entries |
| [claim-index.md](../claims/claim-index.md) | Auto-generated quality and strength breakdown of all verified entries |
| [model-fidelity-register.md](../claims/model-fidelity-register.md) | Human-readable F* model fidelity classifications |
| [model-fidelity.yaml](../claims/model-fidelity.yaml) | Machine-readable F* model fidelity inventory used by the strict validator |
| [runtime-linkage.md](runtime-linkage.md) | Proof-to-implementation traceability, feature flags, liveness |
| `scripts/validation/populate_runtime_link.py` | Auto-populate runtime\_link with FSTAR\_TO\_RUST\_MAP |
| `scripts/validation/check_runtime_liveness.py` | Liveness classification of runtime-linked files |
| `scripts/validation/check_runtime_drift.py` | Drift detection for runtime-linked files |
| `scripts/validation/check_keygen_rng.py` | Key generation RNG boundary guard (SystemRandom usage) |
