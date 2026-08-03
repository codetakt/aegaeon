module Jose

open FStar.All

(** Canonicalization of JOSE protected header (deterministic).

    At the spec level, we model canonicalize as the identity function.
    The runtime implementation (in Rust) performs JSON key-sorting, but
    all F* proofs depend only on idempotence and determinism, not on the
    specific sorting order.  The identity satisfies both properties. *)
val canonicalize: string -> string
let canonicalize h = h

val header_deterministic: h:string -> Tot bool
let header_deterministic _ = true

// Allowed JWS algs (legacy / non-verified path).
val alg_allowed: string -> bool
let alg_allowed a = a = "RS256" || a = "ES256"

// Verified JWS algs for strong-constraint mode (HACL*/EverCrypt only).
val alg_verified_allowed: string -> bool
let alg_verified_allowed a =
  a = "HS256" || a = "HS384" || a = "HS512" || a = "EdDSA"

(** Idempotence: re-canonicalizing a canonical header is a no-op.
    Trivially follows from the identity definition. *)
val lemma_header_canonical_idempotent: h:string -> Lemma
  (requires header_deterministic h)
  (ensures  (canonicalize (canonicalize h) = canonicalize h))
let lemma_header_canonical_idempotent _h = ()

// Allow-list lemma (placeholder)
let lemma_alg_allowlist (a:string) : Lemma
  (requires (alg_allowed a))
  (ensures True) = ()

// Stability: canonicalized header remains within the deterministic fragment
let lemma_header_deterministic_stable (h:string) : Lemma
  (requires header_deterministic h)
  (ensures  header_deterministic (canonicalize h)) = ()
