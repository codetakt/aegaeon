# Verification Ops Guide

Last updated: 2026-09-07

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

**Why this matters:** VerifiedReqs is the legacy evidence inventory described in
[claim-definition.md &sect;0.2](../claims/assurance-case/claim-definition.md#02-claim-scope).
The [server contract](../claims/assurance-case/assurance-contract.md) defines
obligations independently of row status. Incorrectly marked rows misrepresent
available evidence; correctly grounded rows still do not activate the foundation
claim or remove unproved requirements from its scope.

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

---

## 10. Assurance review packets and document revisions

This procedure maintains review inputs for the
[assurance statement](../claims/assurance-statement.md) and
[evaluation rules](../claims/assurance-evaluation.md). Packet integrity checks
establish reproducible review inputs; they do not activate release assurance.

### Preparing a self-contained review packet

Preserve repository-relative paths inside the packet. For contract revision
`2026-09-07-r3`, the `contract-integrity` category contains these seven files:

```text
spec/server-assurance-contract.schema.json
spec/sdk-assurance-contract.schema.json
scripts/validation/validate_server_assurance_contract.py
scripts/validation/validate_sdk_assurance_contract.py
scripts/validation/test_server_assurance_contract.py
scripts/validation/test_sdk_assurance_contract.py
scripts/validation/assurance_document_integrity.py
```

Both validators import the shared helper. Include any new local dependencies
when the validators or tests change; copying only their entry points is insufficient.
Also include both contract registers, their referenced documents, the compliance
matrix, the client boundary and legacy policy files, and every SDK
`reference_source_paths` and `project_sources` file. Preserve pinned project
source bytes, including generated OpenAPI, without regenerating them for the packet.
Archive the external standards under `standards/` using each pinned URI's basename
and the exact bytes identified by its SHA-256.

Record the review ID, base commit, working-tree scope, file categories and
SHA-256 digests in the packet manifest. Record the Python environment and dependency
versions (`jsonschema` and `PyYAML`), commands, exit statuses and outputs with the
preparation results. From the copied packet's root, run:

```bash
python3 scripts/validation/validate_server_assurance_contract.py --source-dir standards
python3 scripts/validation/validate_sdk_assurance_contract.py --source-dir standards
python3 scripts/validation/test_server_assurance_contract.py
python3 scripts/validation/test_sdk_assurance_contract.py
```

Use the copied scripts and inputs, with no source-checkout imports, symlinks or
sibling-repository dependencies. If the review also checks an SDK workspace,
include that workspace and pass its packet-local path to `--sdk-workspace`.
Verify the final manifest's digests inside the packet before handing it over.
Keep earlier packets and reports unchanged; issue a new identified packet for
changed inputs and distinguish preparation checks from reviewer findings.

### Updating document revision pins

Each register's `document_revisions` maps five document fields to independently
versioned revisions: `normative_document`, `standards_document`, `status_document`,
`evaluation_document` and `statement_document`.

1. Update the changed document's single `Document revision:` declaration before
   `Status:` and update its corresponding entry in every register that references it.
2. When changing either shared document (the assurance statement or evaluation rules),
   update the applicable pin in **both** server and SDK registers in the same change.
   Changing a server-only document does not itself require an SDK document revision.
3. Keep `contract_revision` equal to the normative contract document's revision.
   Independently revised companion documents do not require renumbering an
   unchanged contract or its other companions.
4. Run both validators and regression suites. Refresh any affected project-source
   pins only after reviewing the source changes, then create a new packet manifest
   when distributing the revised inputs.

The shared helper checks distinct paths and revision declarations. It does not
detect changed bytes under an unchanged revision or establish semantic consistency;
the manifest and substantive review remain necessary. Preparing a review packet
does not change contract revisions or activate release assurance; the obligation
registers retain their `specified-not-attested` state.

## 11. Pinned standards acquisition and recovery

### Acquisition and CI

The two contract registers are the only source inventory. Their current union
contains 55 external originals: all 55 server sources and the SDK's subset of 52.
The SDK additionally pins three project sources, whose bytes are checked in the
checkout regardless of `--source-dir`. External standards are not checked into Git.

```bash
nix build .#assurance-standards --out-link result-assurance-standards -L
nix develop .#ci --command python3 scripts/validation/validate_server_assurance_contract.py \
  --source-dir result-assurance-standards
nix develop .#ci --command python3 scripts/validation/validate_sdk_assurance_contract.py \
  --source-dir result-assurance-standards
nix build .#verified-reqs -L
```

`nix/assurance-sources.nix` reads both registers and fetches each original from its
pinned URI with `pkgs.fetchurl` and its exact SHA-256. Shared entries must agree on
ID, edition, URI and digest; conflicting IDs, URIs or flat archive filenames fail
evaluation. Pure inventory regression checks run during derivation evaluation.
The resulting archive uses each URI's basename and contains `manifest.json` with
both register digests and the deduplicated source inventory. Files retain their
original bytes, including HTML and all notices; no HTML normalization, errata
application or conversion occurs.

The package and flake check share a single `verified-reqs` derivation. It sets
`AEGAEON_ASSURANCE_SOURCE_DIR` to the acquired store path; the wrapper requires
that variable and passes `--source-dir` to both validators. Missing files or hash
mismatches fail the gate. The network is used by fixed-output fetches before
sandboxed validation, never by the Python validators. Standalone validators report
explicitly when external bytes were not checked.

The existing `setup-nix-ci` action enables the FlakeHub cache for the core CI and
VerifiedReqs jobs. Fixed-output source store paths can be reused across jobs and
unrelated repository revisions. Cache reuse is an optimization: a clean runner
fetches missing originals and verifies the same pinned digests. Cache outages do
not authorize bypassing hash checks. Cache availability and successful retrieval
are not conformance or release-assurance evidence.

### Preservation and review packets

Keep the successful archive reachable through an output link or another Nix GC
root until its sources have been archived for the release/review. To prepare the
self-contained packet described in section 10, copy dereferenced files into its
`standards/` directory, including the generated manifest. Do not leave packet
symlinks pointing into the preparer's Nix store. Hash the copied bytes in the packet
manifest, retain both source registers, and run both packet-local validators with
`--source-dir standards`. The archive manifest describes inputs, not an attestation.

The standards retain their own copyright and license terms; Aegaeon's Apache-2.0
license does not relicense them. RFCs and IETF drafts identify authors, the IETF
Trust and the applicable Trust Legal Provisions/BCP 78 in their notices. Preserve
those notices and comply with the terms applicable to each adopted document when
copying it. OIDF specifications carry OpenID Foundation notices; for example,
OIDC Core Appendix C permits reproduction and distribution for specification
and implementation purposes with OIDF attribution and without implying endorsement.
Preserve each document's complete notice and review its own terms before sharing
a cache or packet. Do not replace notices with project copyright or claim OIDF
endorsement. No standards bytes are bundled into the server or SDK packages by
this derivation.

### Failed fetches and changed original bytes

An unavailable origin or a fixed-output hash mismatch blocks source acquisition.
OIDF HTML includes presentation bytes: upstream re-rendering can therefore cause
a mismatch even when the visible normative prose appears unchanged. This is an
intentional stop for review, not a reason to accept the newly observed hash.

1. Record the source ID, adopted edition/URI, expected digest, failure log and
   observed digest, if available. Keep newly retrieved bytes separately from the
   adopted archive; preserve the old register and successful archive.
2. Retry transient retrieval failures or restore the exact adopted bytes from a
   retained, trusted archive/cache. Check their SHA-256 before import. Restoring
   identical bytes does not change the baseline and needs no repin.
3. If upstream bytes changed, compare complete originals and review normative
   clauses, dependencies, errata and notices, as well as presentation changes.
   Record whether obligations or evidence are affected. A visual comparison alone
   cannot establish that every change is presentational.
4. Adopt changed bytes only in a reviewed, versioned baseline revision. Update
   the source entry and retrieval date in every register that shares it, the
   affected standards documents and their revision pins. If requirements or
   applicability change, revise the affected contracts/profiles and assess release
   evidence under the evaluation rules. A presentation-only change still requires
   a documented review and baseline revision; never silently refresh a digest.
5. Rebuild the archive and run both byte-checking validators, regression suites
   and `.#verified-reqs`. Create a new identified packet or release record as
   appropriate; retain earlier records. Do not remove `--source-dir`, substitute
   an unversioned URL or waive the mismatch to make CI pass.

If the old bytes cannot be recovered and changed bytes have not been reviewed,
the gate remains failed. Mechanical checks establish references, revisions and
byte identity. Humans still review public wording, applicability and substantive
standards changes.
