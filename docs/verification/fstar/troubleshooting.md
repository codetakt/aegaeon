# F* / KaRaMeL Troubleshooting (Proof / Extraction Hygiene)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This document summarises real-world failure modes encountered in F* (proofs) and KaRaMeL
extraction as a short anti-regression memo. We do not keep long investigation logs or historical
snapshots here; we keep only reusable decision criteria and remediation steps.

## 1) Hygiene: inventory `admit()` / `assume val`

Run these from the repository root:

```bash
rg 'admit\\(' fstar
rg 'assume val' fstar
```

Policy:
- **Extraction surface (Low*/FFI)**: target zero `admit()` / `assume val` wherever possible.
- **Boundary contracts (runtime/allocator/FFI)**: if an `assume val` must remain, document the
  contract explicitly (who must provide what) and keep the system fail-closed, e.g.
  `docs/verification/jose/json-lowstar-ffi-contracts.md`.
- Track requirement status in `spec/compliance-matrix.yaml` and track warning cleanups in
  `docs/verification/workplans/lemma-hardening-plan.md`.

## 2) When SMT returns `unknown` (rlimit/fuel)

Typical symptoms:
- `Could not prove post-condition`
- `unknown because (incomplete quantifiers) (rlimit=...)`
- logs indicating fuel/ifuel exhaustion

Recommended order:
1. **Make the proof cheaper** (add helper lemmas, reduce quantifiers, break up `List.length`
   chains, simplify `calc` blocks).
2. **Increase Z3/ fuel only locally** (avoid global tuning).

Local tuning example (only where needed):
```fstar
#push-options "--z3rlimit 50 --fuel 4 --ifuel 2"
// ... hard lemma(s) ...
#pop-options
```

Notes:
- Raising the global rlimit permanently is a last resort, because it tends to harm CI
  reproducibility.
- Prefer shrinking the proof inductively and making measures explicit instead of “brute-forcing”
  `unknown` away.

## 3) Low*/Buffer nat/int footguns

Common pitfalls:
- Expressions like `remaining - 1` can end up typed as `int`, causing failures such as
  `Expected nat got int`.
- SMT may fail to recover the preconditions for `Buffer.upd` / `Buffer.index` (bounds/live/measure)
  and get stuck.

Remediation:
- Refactor so the value stays a `nat` (`match`, `Nat.pred`, explicit type annotations).
- Prove the `UInt32` conversion preconditions first (e.g. `UInt32.v idx < UInt32.v count`) and
  close the `Buffer` API preconditions locally.

## 4) When KaRaMeL extraction breaks (dependency chains / Warning 15)

Typical causes:
- The extraction target drags in **spec/proof-only modules** or **non-Low* compatible
  dependencies**.
- The Stack layer depends on `Prims.list` or mathematical integers, producing many Warning 15
  messages.

Recommendations:
- **Minimise the extraction surface** (the “Option B: minimal Stack module” pattern).
  - Example: `Jose.LowStar.Json.Stack` should avoid depending on Jose.* and expose only the minimal
    types and functions needed.
- Do not treat Warning 15 as “noise”.
  - It can directly lead to fail-open/DoS via abort paths, leaks around `KRML_HOST_MALLOC`, and
    gaps in the verification story. Target zero Warning 15 on the extraction surface.

Primary references:
- JOSE Low*/C path status and verification summary: `docs/verification/jose/phase4-verification-summary.md`
- Overall plan and milestones: `docs/program-management/initiatives/jose/lowstar/lowstar-extraction-plan.md`

## 5) Evidence storage (avoid doc bloat)

- Store long logs and large outputs under `artifacts/` and reference them by path from docs.
- If a historical snapshot is needed, treat version control history and CI artefacts as primary
  sources.

## 6) EverCrypt.Helpers name resolution (monitoring)

Symptom: Low*/EverParse extraction may fail because `EverCrypt.Helpers` cannot be resolved
(dependency path resolution drift).

If it happens again:

1. Re-enter the devShell (stabilises include paths):
   ```bash
   nix develop .#default --command true
   ```
2. Clear caches:
   ```bash
   rm -rf fstar/.cache fstar/.hints generated/lowstar/oidc
   ```
3. Run a trace build and keep the logs:
   ```bash
   nix run .#verify-lowstar -- --trace_error
   ```
4. Verify include/KaRaMeL flags with a dry run:
   ```bash
   scripts/extraction/run_jose_lowstar.sh --dry-run
   ```

If it still does not resolve, file a ticket with `fstar.log` + KaRaMeL logs as an EverCrypt include-layout issue.

## 7) Long-lived process segfaults (`fstar.exe` crash after large batch)

Symptom: `nix build .#verify-fstar` (or another large batch) ends with `Segmentation fault (core dumped)` even though the individual modules re-verify cleanly.

What we learned (2026-01-15):

- The crash surfaces after dozens of modules when `fstar.exe` is kept alive with `--detail_errors --query_stats`.
- Re-running the same modules in small batches succeeds; there is no single bad `.fst`.

Operational guidance:

1. **Split verification into batches**. The project `verify-fstar` target now shells out to multiple `fstar.exe` invocations, each covering a subset of the module list. Keep per-batch run time short (<2–3 minutes).
2. **Keep logging minimal by default**. Run the steady-state commands without `--detail_errors`; re-run the failing batch with verbose flags only when needed.
3. **Capture evidence if it crashes again**: the batch command, log snippet, and (if possible) the core dump. Do not revert to the single-process flow in CI.

If the behaviour regresses even with batching, bump the F* pin and share the smaller reproducer upstream before falling back to long-lived runs.
