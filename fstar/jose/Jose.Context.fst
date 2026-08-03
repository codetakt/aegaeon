module Jose.Context

open FStar.UInt32
open FStar.Math.Lemmas

/// JOSE request context holding runtime policies.
/// This type encapsulates per-request configuration such as header length limits,
/// allowing flexible policy enforcement while maintaining verification guarantees.
noeq
type jose_context = {
  /// Maximum allowed length for Base64URL-encoded JOSE protected headers.
  /// Stored as a machine integer for Low* extraction, refined to be non-zero.
  header_max_length: (len:UInt32.t{len <> UInt32.zero})
}

noextract
val header_max_length_nat : jose_context -> nat
noextract
let header_max_length_nat (ctx:jose_context) : nat = UInt32.v ctx.header_max_length

/// Default context matching the historical fixed policy (4096 characters).
let default_context : jose_context = {
  header_max_length = UInt32.uint_to_t 4096
}

/// Construct a context with a custom header length limit.
/// The limit must be positive (non-zero) for legacy lemmas.
val make_context : max_len:UInt32.t{max_len <> UInt32.zero} -> jose_context
let make_context max_len = {
  header_max_length = max_len
}

/// Lemma: The header_max_length field always fits in UInt32 (trivial).
val lemma_context_header_max_length_u32_safe :
  ctx:jose_context ->
  Lemma (ensures header_max_length_nat ctx < pow2 32)
let lemma_context_header_max_length_u32_safe ctx = ()

/// Lemma: The header_max_length field is always positive.
val lemma_context_header_max_length_positive :
  ctx:jose_context ->
  Lemma (ensures header_max_length_nat ctx > 0)
let lemma_context_header_max_length_positive ctx =
  assert (ctx.header_max_length <> UInt32.zero);
  ()

/// Convert context header_max_length to UInt32 (identity helper).
noextract
val context_header_max_length_u32 : ctx:jose_context -> UInt32.t
noextract
let context_header_max_length_u32 ctx = ctx.header_max_length

/// Lemma: Round-trip property for UInt32 conversion (identity).
noextract
val lemma_context_u32_roundtrip :
  ctx:jose_context ->
  Lemma (ensures UInt32.v (context_header_max_length_u32 ctx) = header_max_length_nat ctx)
noextract
let lemma_context_u32_roundtrip ctx = ()
