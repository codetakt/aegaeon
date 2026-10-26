# Aegaeon attribute mapping

An IO-free Rust engine for transforming authenticated attributes into typed,
recipient-specific output. The engine accepts an immutable local owner, a
recipient, source metadata, a versioned policy and an adapter-owned output
contract. It returns the complete output with source evidence, or a value-free
error. It does not authenticate sources, select or link accounts, sign tokens,
or publish claims to a protocol endpoint.

## Authorization contract

The caller must authenticate the inputs and policy, resolve the immutable owner,
select the actual recipient and supply a trusted observation time. Deserializing
these Rust types establishes none of those facts. A recipient identifies the
environment, client and output surface; an empty grant set authorizes nobody.

Each referenced source attribute must belong to the selected owner, appear in
the policy's input allowlist, permit the exact recipient and be current at the
supplied time. Each output separately needs a release rule and a matching output
schema. References in unused coalesce alternatives and empty array-map bodies
still contribute restrictions and source evidence. Derivation cannot remove an
input's disclosure restrictions. No partial result is returned on failure.

The adapter owns the output contract. Identity and security claims such as
`sub`, `iss`, `aud`, `nonce` and `cnf` are reserved, together with any additional
names reserved by the adapter. Storing an attribute with one of those names does
not grant permission to emit it as a protocol claim.

## Transformations

Policies support exact object/array paths, literals, object and array assembly,
coalesce, ASCII lowercase, concatenation and array item mapping. They cannot
execute arbitrary code or perform IO. Object keys are not normalized.

Missing and present JSON null are distinct. A missing object member is omitted;
a missing array item is an error so positions cannot silently shift. Coalesce
selects the first present value, including null, while evaluating and validating
all alternatives. An invalid alternative is not hidden by an earlier value.
Schemas distinguish strings, booleans, numbers, integers, null, arrays and
objects, including required members; unknown object members are rejected.

Policy schema version 1 is supported. Unknown serialized fields, unsupported
versions, duplicate source keys, incompatible types and malformed identifiers
are rejected. Source metadata is retained with every produced claim; it remains
evidence supplied by the caller, not a signature or independent attestation.

## Resource limits and integration

The engine limits encoded input attributes to 256 KiB in total, each encoded
policy and output contract to 256 KiB, and complete encoded output to 64 KiB.
JSON and expression depth, collection sizes, policy nodes and evaluation steps
have separate bounds in `model.rs`. These are evaluation limits: adapters must
also bound requests and deserialize safely before calling the engine.

The crate has no server configuration or endpoint registration. A server adapter
must establish ownership, provenance, policy authority and recipient admission
before calling it, then enforce protocol-specific output and lifecycle rules.
Local unit tests exercise these engine contracts; they are not a formal proof of
all inputs or a proof of any future protocol integration.

Run `nix develop -c cargo test -p aegaeon-attribute-mapping` from the workspace.
