# Verification Artefact Structure Guidelines

Last updated: 2026-07-07

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This note outlines how we should organise proof libraries, F\* modules, and
documentation so that outstanding work remains easy to track. Use it together
with the verification roadmap at `../../program-management/roadmaps/active/proofs-roadmap.md`.

## F\* module layout

Example split for `fstar/jose/Jose.HeaderParser.fst`:

1. `Jose.StringLemmas` – generic list/string helpers (`string_in_list_*`,
   ASCII/UTF-8 length lemmas). Reusable across TLV and JOSE.
2. `Jose.TlvLemmas` – TLV-specific invariants (`keys_of_entries`, uniqueness,
   recursive decoder invariants).
3. `Jose.Utf8Lemmas` – UTF-8 canonical form and round-trip lemmas.
4. `Jose.HeaderParser` – parser code plus high-level lemmas that depend on (2)
   and (3).

Keeping utilities separate prevents circular dependencies as we add more JOSE or
OIDC modules.

### Suggested files

```text
fstar/
 ├─ jose/
 │   ├─ Jose.StringLemmas.fst
 │   ├─ Jose.Utf8Lemmas.fst
 │   ├─ Jose.TlvLemmas.fst
 │   └─ Jose.HeaderParser.fst
 └─ Lib/
     └─ BufferLemmas.fst  (optional, shared LowStar.Buffer helpers)
```

## Documentation layout

- High-level status: `../../program-management/roadmaps/active/proofs-roadmap.md`
- Detailed backlog: per-topic plans (e.g. `../../program-management/initiatives/jose/parser/header-parser-plan.md`,
  `../../program-management/initiatives/jose/json-tlv/json-tlv-proof-plan.md`)
- Long-tail backlog: `../../program-management/roadmaps/future/future-projects.md` (items
  not yet scheduled, deeper refactors, large proof initiatives)

When adding a new plan, link it from the relevant README and note which parts of
the code tree it covers.

## Working agreements

1. Prefer the `Lemma (requires ...)(ensures ...)` form even for simple Boolean
   equalities.
2. Avoid raw `assert false` scaffolding: convert each occurrence into a named
   lemma. If you cannot discharge it immediately, record it in the relevant plan
   or in `../../program-management/roadmaps/future/future-projects.md`.
3. Keep `assume` declarations localised. For example, keep assumed UTF-8 decoder
   specs in `Jose.Utf8Lemmas` so that replacing them with concrete
   implementations later touches a single file.
4. Update docs as part of proof work. When you close a TODO, mark it in both the
   detailed plan and the high-level roadmap.
5. Avoid repo-local scratch directories (for example, do not create a top-level
   `tmp/`). Use `${TMPDIR:-/tmp}` + `mktemp -d` for ephemeral work, and
   `${XDG_CACHE_HOME:-~/.cache}` for long-lived checkouts/caches.
