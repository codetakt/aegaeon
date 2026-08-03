# Documentation Style Guide

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Documentation

Audience: contributors, maintainers

This guide defines the preferred structure for long-lived Markdown documentation
under `docs/`.

## Core principles

- Keep one **canonical** document per question whenever possible.
- Use directory `README.md` files as the first entrypoint for readers.
- Use checked-in Markdown for stable guidance, scope, and summaries.
- Use `artifacts/` for current machine-generated evidence and raw transcripts.
- Keep temporary investigations out of tracked docs unless their result is promoted
  into a permanent section such as `verification/`, `operations/`, or `program-management/`.
- Promote durable content into the canonical document, then delete stale deep dives.
  Keep archives only when a current document can explain their audit or traceability value.
- Use `python3 scripts/validation/check_docs_structure.py --report-long-docs`
  during larger docs refactors to find files that may need overview/detail splits.

## Recommended templates

### 0. Long-lived document header

Use this order for all Markdown documents under `docs/`, including directory
`README.md` files:

```md
# <Title>

Last updated: YYYY-MM-DD

Status: <current implementation baseline | active plan | future plan | historical record | snapshot | draft | archived>

Owner: <team or role>

Audience: <primary readers>
```

Do not omit these fields. The structure audit uses them to classify the document, generate
`docs/index.md`, and route stale-document reviews. Avoid custom metadata blocks such as `Document:`
unless the document is an API/schema spec that needs explicit version fields.

### 1. Section index / directory `README.md`

Recommended shape:

1. `# <Section> Overview`
2. Short paragraph describing what belongs in the section
3. `## Scope`
4. `## Canonical Documents`
5. `## Reading Rule of Thumb`

Use additional sections only when they improve navigation.

Keep `Canonical Documents` lists short enough to scan. As a rule of thumb, keep
top-level entries at **8 or fewer**; when a directory needs more links, group
related documents into categorized bullets or delegate details to child
`README.md` files. Use
`python3 scripts/validation/check_docs_structure.py --report-dense-readmes`
during larger documentation reviews to find dense entrypoint lists.

### 2. Point-in-time report / snapshot

Place this directly below the title when the document is time-bound:

```md
> **Status note (YYYY-MM-DD):** This is a point-in-time summary. For the current
> authoritative posture or latest evidence, use <canonical doc> and/or <artifacts path>.
```

Examples: release evidence summaries such as `docs/releases/evidence/beta-conformance.md`,
security reviews, baseline summaries, and one-off audits such as
`docs/releases/runbooks/phase1-evidence-acquisition.md`.
The docs structure audit requires a top `Status note` for every `snapshot`
and `draft` document so readers do not confuse point-in-time or unapproved
content with the current implementation baseline.

### 2a. Current implementation specification

Recommended shape:

1. `# <Feature> Specification`
2. `Last updated: YYYY-MM-DD`
3. `Status: current implementation baseline`
4. `## Purpose`
5. `## Boundary Model` or `## Scope`
6. `## Implemented Capabilities`
7. `## Operational Requirements` when relevant
8. `## References`

Use specs for durable runtime/API behaviour that is already implemented. Do not keep completed
execution checklists in specs unless they are still useful as regression requirements.

### 2b. Roadmap / future plan

Recommended shape:

1. `# <Area> Roadmap` or `# <Area> Plan`
2. `Last updated: YYYY-MM-DD`
3. `Status: active plan` or `Status: future plan`
4. `## Baseline`
5. `## Active Sequence` or `## Target Plans`
6. `## Acceptance Criteria` or `## Definition Of Done`
7. `## References`

Roadmaps should cover future, not-yet-complete, or ongoing evidence-maintenance work. Completed
implementation history belongs in `docs/program-management/historical/`.

### 2c. Handoff / current-context note

Keep handoff and current-context notes under `docs/development/` only while they
describe live integration work. Once the referenced delivery phase is complete,
move the note to `docs/program-management/historical/` or promote durable
requirements into the relevant spec, operation, or verification document.

### 2d. Historical delivery record

Recommended shape:

1. `# <Area> Delivery Record`
2. `Last updated: YYYY-MM-DD`
3. `Status: historical record`
4. Short paragraph pointing to the current spec or current roadmap
5. Delivery details retained only where they help future regression checks

### 3. Superseded document handling

Default to deletion after the durable content has been promoted. Keep a short
compatibility stub only when an external reference or release artefact needs a
temporary stable path. Put the lifecycle fields in the top section before
`## Scope`:

```md
# <Title> (moved)

This compatibility entrypoint preserves the historical `<path>` path. The
maintained document now lives in `<canonical replacement>`.

Retained for: <external reference, release artefact, or generated evidence reason>

Review after: YYYY-MM-DD
```

Do not keep compatibility pointers for internal-only paths that can be recovered
from Git history. Archived Markdown should retain explicit audit or traceability
value and should not duplicate the current source of truth. The docs structure
audit rejects compatibility stubs without `Retained for:` and `Review after:`
metadata. Use
`python3 scripts/validation/check_docs_structure.py --report-compatibility-stubs`
to review retained stubs and their scheduled review dates.

## Heading conventions

- Prefer `Overview`, `Purpose`, `Scope`, `Current Baseline`, `Implemented Capabilities`,
  `Operational Requirements`, `Canonical Documents`, `Current References`, `References`,
  `Reading Rule of Thumb`, `Historical / Archived Snapshots`.
- Keep headings short and descriptive.
- Avoid multiple documents at the same level using different labels for the same concept (for example, `Index`, `Documents`, and `Current Documents` for equivalent directory-entry sections).

## Path and Filename Conventions

- Use lowercase kebab-case for Markdown filenames, for example
  `docs/releases/evidence/beta-conformance.md` or
  `docs/releases/runbooks/phase1-evidence-acquisition.md`.
- Use lowercase kebab-case directory names. Version directories may use dots,
  for example `v0.1.0/`.
- Reserve `README.md` for directory entrypoints and `docs/index.md` for the
  generated documentation inventory.
- Keep Markdown paths inside code spans resolvable from the current file or from
  the repository root, for example `docs/specs/README.md` or `../README.md`.
- Do not add tracked investigation scratchpads under `docs/`. Promote durable
  conclusions directly into the relevant permanent section.

## Status vocabulary

Use these status values consistently:

- `current implementation baseline`: implemented durable product/API/runtime behaviour
- `active plan`: work currently being sequenced or executed
- `future plan`: intentionally deferred or not-yet-implemented work
- `historical record`: completed delivery context retained for regression or traceability
- `snapshot`: point-in-time evidence or review material
- `draft`: publication copy, collateral, or other derived material that is not yet final
- `archived`: superseded material kept only for explicit audit or traceability value

Avoid mixing status with marketing wording. If a document affects public claims, link to
`docs/product-positioning.md` and the relevant verification claim document.

The status line is enforced as top-level metadata for all Markdown documents
under `docs/`. Inline status fields inside tables, task lists, or section
content can use domain-specific wording when that wording is clearer.

## Owner and Audience Metadata

Use `Owner:` for the team or role expected to keep the document current, not for
authorship attribution. Use `Audience:` for the primary readers who should rely
on the document. Keep both values short and stable, for example:

- `Owner: Verification`
- `Audience: verification reviewers, maintainers`
- `Owner: Product / Publication`
- `Audience: publication contributors, maintainers`

## Evidence conventions

- If a document says `latest`, either:
  - make it a stub that points to `artifacts/`, or
  - explicitly mark it as a snapshot with a `Status note`.
- Do not treat checked-in Markdown alone as proof of current state when fresh command output or artefacts are available.
- Keep raw logs, execution transcripts, and nested machine evidence under `artifacts/`; `docs/`
  should contain reader-facing Markdown, curated source-managed JSON manifests, and small sample
  configuration files only when a document explicitly references them.

## Canonical boundary reminder

When a document touches verification posture, keep the ownership boundaries explicit:

- formal claim / assumptions / verified-vs-compat boundary → `docs/verification/`
- product and API specifications → `docs/specs/`
- active planning / sequencing → `docs/program-management/`
- release evidence and operator runbooks → `docs/releases/`, `docs/operations/`

## Document Type Labels

Directory indexes should prefix `Canonical Documents` entries with a short type
label when the surrounding directory mixes document classes. Use bracketed
lowercase labels from the validated vocabulary:

- `[analysis]`, `[architecture]`, `[automation]`, `[brief]`, `[checklist]`
- `[claim]`, `[configuration]`, `[context]`, `[design]`, `[development]`
- `[draft]`, `[evidence]`, `[guide]`, `[handoff]`, `[historical]`
- `[index]`, `[initiative]`, `[model]`, `[performance]`, `[plan]`
- `[policy]`, `[publication]`, `[reference]`, `[release]`, `[roadmap]`
- `[runbook]`, `[sample]`, `[security]`, `[snapshot]`, `[spec]`
- `[summary]`, `[workplan]`

Use `python3 scripts/validation/check_docs_structure.py --print-index` when you need a generated
Markdown inventory of document paths, inferred document types, titles, and top-level status values.
Commit `docs/index.md` only through
`python3 scripts/validation/check_docs_structure.py --write-index`; the normal structure audit
checks that the committed index is up to date.
