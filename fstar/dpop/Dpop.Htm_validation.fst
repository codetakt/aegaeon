module Dpop.Htm_validation

(** Validate that the HTTP method in the DPoP proof matches the request.
    The surrounding runtime already canonicalizes request methods before
    they reach the verified boundary, so exact equality is the intended
    contract here. *)
val validate_htm : expected:string -> actual:string -> Tot (b:bool{b <==> expected = actual})
let validate_htm expected actual =
  expected = actual

(** Lemma: the same method always validates. *)
let lemma_validate_htm_refl m : Lemma (validate_htm m m) = ()
