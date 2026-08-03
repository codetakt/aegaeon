module Jose.Policy

(** Maximum allowed length (in characters) for Base64URL-encoded JOSE protected headers. *)
let header_max_length : nat = 4096

(** Maximum allowed length for the optional kid field. *)
let kid_max_length : nat = 255

// Context-based API (new)
open Jose.Context

/// Context-based accessor for header maximum length.
/// Use this in new code that accepts a jose_context parameter.
val get_header_max_length : jose_context -> nat
let get_header_max_length ctx = header_max_length_nat ctx

/// Lemma: Context-based accessor returns a valid UInt32-bounded value.
val lemma_get_header_max_length_bounded :
  ctx:jose_context ->
  Lemma (ensures get_header_max_length ctx > 0 /\ get_header_max_length ctx < pow2 32)
let lemma_get_header_max_length_bounded ctx =
  lemma_context_header_max_length_u32_safe ctx;
  lemma_context_header_max_length_positive ctx
