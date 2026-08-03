# JOSE Initiative Overview

Last updated: 2026-07-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

Aegaeon's JOSE workstream covers header parsing, JSON/TLV normalisation, and
Low*/C extraction. Use this document to locate the active plans and understand
their dependencies.

## Scope

- JOSE header parsing and raw JSON boundary work
- JSON/TLV normalisation and proof planning
- Low*/C extraction sequencing and FFI integration

## Canonical Documents

- `[initiative]` [JOSE implementation plan](jose-implementation-plan.md)
- `[workplan]` [Low* extraction plan](lowstar/lowstar-extraction-plan.md)
- `[workplan]` [JSON TLV proof plan](json-tlv/json-tlv-proof-plan.md)
- `[spec]` [Header parser specification](parser/header-parser-spec.md)
- `[plan]` [Header parser plan](parser/header-parser-plan.md)
- `[summary]` [Status and milestones](status.md)

## Related Subdirectories

- [Parser plans](parser/README.md)
- [JSON/TLV plans](json-tlv/README.md)
- [Low* extraction plans](lowstar/README.md)
- [Historical JOSE initiative records](../../historical/initiatives/jose/README.md)

## Reading Rule of Thumb

1. Start here for the active JOSE document map.
2. Use [Status and milestones](status.md) for current workstream state and sequencing.
3. Use the subdirectory READMEs for focused parser, TLV, and Low* work.
4. Promote completed runtime behavior into `../../../specs/` or `../../../verification/`.
