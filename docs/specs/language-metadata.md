# Language metadata admission and registry updates

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Engineering

Audience: implementers, operators, reviewers

Aegaeon validates supplied language tags in Federation metadata and upstream OP
Discovery. Invalid original values cannot be hidden by signed metadata replacement,
policy removal, role filtering or cache reuse. This is metadata admission; it does
not establish that a provider actually supports the languages it advertises.

## Tag form and dated consumer profile

Two predicates are implemented separately in
`crates/server/src/metadata/language_tags/`: full RFC 5646 form and structural
restrictions, and validity under a pinned registry profile. Receiving boundaries
require both. The stricter registry requirement is Aegaeon's consumer policy;
RFC 5646 does not require every consumer to consult a registry.

Form checking includes all 26 whole grandfathered tags, private-only tags, normal
primary lengths 2–8, extlangs, scripts, alpha/numeric regions, variants,
extensions and private tails. Second/third extlangs and case-insensitive duplicate
variants/singletons are rejected. Repeated private subtags and opaque extension
payload items are allowed. There is no additional total tag-length or subtag-count
limit; existing request and JWT bounds still apply. Input is not trimmed,
case-rewritten, Unicode-normalized or converted to a preferred spelling.

The ordinary-subtag snapshot is IANA File-Date **2026-09-17**. Extension allocation
uses the separate IANA registry File-Date **2014-04-02**. The profile checks the
correct registered categories, private ranges and extlang's enclosing-primary
Prefix. Deprecated registrations remain accepted. Variant Prefix and
Suppress-Script recommendations do not become admission constraints. Private-use
items need no individual registrations. Extension singletons must be allocated,
but extension payload semantics are not interpreted or validated; no Unicode
locale/transform extension claim is made.

A tag such as `eng`, a future reserved primary, or a later allocation may be
well-formed yet rejected under this snapshot. A new assignment requires a registry
update before acceptance. Rejection does not establish that the tag is globally
invalid. Existing evidence remains bound to the version actually checked.

## Fields and operations

OP Federation metadata and ordinary OP Discovery check each supplied
`ui_locales_supported` and `claims_locales_supported` element. AS Federation
metadata checks `ui_locales_supported`. Omitted and empty arrays are allowed;
order, spelling and repeated array entries are preserved. Wrong-role fields keep
their existing extension meaning.

Federation recognizes the following exact base names, both untagged and followed
by `#` and an admitted language tag:

| Roles | String fields | Nonempty arrays of strings | Informational URLs |
| --- | --- | --- | --- |
| All, including extension entity types | `organization_name`, `display_name`, `description` | `keywords`, `contacts` | `logo_uri`, `policy_uri`, `information_uri`, `organization_uri` |
| OP / AS additions | — | — | `service_documentation`, `op_policy_uri`, `op_tos_uri` |
| RP / OAuth client additions | `client_name` | — | `client_uri`, `tos_uri` |
| OAuth resource additions | `resource_name` | — | `resource_documentation`, `resource_policy_uri`, `resource_tos_uri` |

Informational URLs must be absolute parseable URLs without literal whitespace,
controls or backslashes. This is not HTTPS endpoint policy or outbound request
authorization. Human-readable Unicode strings are retained as received. Untagged
values carry no inferred language. Supplied recognized resource fields use
RFC 9728 meanings without requiring that optional profile or its complete schema.

Unknown names, wrong-role bases, nested extension members and nonlocalizable
names such as `jwks_uri#en` stay opaque extensions. Ordinary Discovery and ordinary
DCR do not acquire Federation suffix schemas. Localized policy names are checked
as names; operator objects are not mistaken for final metadata values. Actual
original and retained derived values are checked at their respective boundaries.

Federation §16 literal JSON comparison is preserved. `display_name#en` and
`display_name#EN` remain distinct serialized names even when their values differ.
A policy targets its exact decoded name; it does not target aliases or language
ranges. Escaped spellings that decode to the same name remain duplicates.
`value` and `default` merges, array operators and optional local policy pins retain
their existing equality. For example, `subset_of:["en"]` applied to `["EN"]`
produces `[]`. This does not assert that the strings identify different languages.

Language interpretation is separate: case does not change tag identity. Aegaeon's
metadata preservation and policy operations do not choose a localized presentation.
Future actual matching or selection needs its own contract consistent with the
imported language recommendations; it cannot be inferred from generic equality.

## Producers and residual responsibilities

The secure AS metadata constructor serializes `ui_locales_supported:["en-US"]`;
that emitted tag is registered and uses canonical casing. The ordinary OP Discovery
constructor omits both locale arrays. A serialization regression test checks these
outputs. Public DTO callers remain responsible for registered/canonical tag choices
and the truth of support they advertise; public mutation is not a certification.
Forwarding admitted received values without inventing tags does not choose a new
canonical spelling.

This consumer profile does not establish external producer behavior, truthful
language support, locale negotiation, UserInfo Claim selection, Trust Mark
localization, extension payload semantics, or complete optional role schemas.
No formal or full-product assurance claim follows from these checks.

## Reproducible registry updates

Official originals and public provenance are under
`crates/server/data/language-tags/`. `provenance.json` binds official URLs, file
dates and SHA-256 digests. Runtime uses generated immutable Rust tables without
network access, Python or a mutable registry.

To update:

1. Preserve new official source bytes and verify their origin, file dates and
   digests. Update the bundled originals and provenance together.
2. Run `python3 scripts/validation/generate_language_tags.py`. Do not hand-edit
   `registry.rs`. The generator rejects malformed records, invalid continuation
   syntax, missing/duplicate fields, invalid categories and unsupported ranges.
3. Review additions, deprecations, category membership, extlang prefixes, ranges
   and extension allocations. Keep old evidence version-bound and assess changes
   to receiving compatibility. New extension allocations do not implement their
   payload semantics.
4. Run `python3 scripts/validation/generate_language_tags.py --check`,
   `python3 scripts/validation/test_language_tag_generator.py`, and the language,
   Federation and upstream metadata regression tests. The existing
   `validation-scripts` CI job enforces data/provenance/table correspondence and
   generator regression checks.

Relevant Rust tests include `metadata::language_tags::tests`,
`federation::tests::endorsed_keys::language_metadata`, `federation::tests::endorsed_keys::capability_metadata`,
and `web::management::tests::upstream_metadata::language_metadata`. They cover
finite examples and real local fixture boundaries, not a proof of the standards
or all deployed artifacts.
