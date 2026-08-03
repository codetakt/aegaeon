module Pkce

open FStar.All
open Verified.Crypto.Bridge

(** Abstract S256 model: base64url(SHA256(verifier)).

    Delegates to HACL* SHA-256 via Verified.Crypto.Bridge.sha256_of_string.
    The actual computation is string → bytes → SHA-256 → base64url string.

    Marked `irreducible` so that downstream proofs cannot observe the
    SHA-256 internals.  This preserves the abstraction that s256 is
    an opaque one-way function: proofs may only use reflexivity
    (`s256 v == s256 v`) and the structural properties of verify_pkce. *)
val s256: string -> string
irreducible let s256 s = sha256_of_string s

// Domain predicate for verifier (RFC 7636): length and charset constraints
// NOTE: This is a placeholder; in practice, use EverParse for strict checks.
// Length-based check (RFC 7636 §4.1: verifier length between 43 and 128)
let strlen (s:string) : nat = FStar.String.strlen s
val verifier_ok: string -> bool
let verifier_ok v = (43 <= strlen v) && (strlen v <= 128)

// Verify PKCE with explicit method; Accept only S256.
// Also enforces RFC 7636 §4.1 verifier length constraints.
val verify_pkce: method:string -> verifier:string -> challenge:string -> Tot bool
let verify_pkce method verifier challenge =
  method = "S256" && verifier_ok verifier && challenge = s256 verifier

// Convenience wrapper: S256 only
val verify_pkce_s256: verifier:string -> challenge:string -> Tot bool
let verify_pkce_s256 v c = verify_pkce "S256" v c

// Lemma: If verification succeeds, method is S256 and challenge binds to verifier
let lemma_pkce_s256_binding (method:string) (verifier:string) (challenge:string) : Lemma
  (requires (verify_pkce method verifier challenge))
  (ensures (method = "S256" /\ challenge = s256 verifier)) = ()

// Lemma: plain method is rejected under this verifier
let lemma_pkce_plain_rejected (verifier:string) (challenge:string) : Lemma
  (ensures (not (verify_pkce "plain" verifier challenge))) = ()

// Proved: verify_pkce includes verifier_ok in its conjunction, so the
// ensures follows directly from the requires by extracting the conjunct.
let lemma_verify_implies_verifier_ok (method:string) (verifier:string) (challenge:string) : Lemma
  (requires (verify_pkce method verifier challenge))
  (ensures  (verifier_ok verifier))
  = ()
