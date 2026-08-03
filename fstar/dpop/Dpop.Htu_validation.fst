module Dpop.Htu_validation

(** Validate that the HTTP URI in the DPoP proof matches the request URI. *)
val validate_htu : expected:string -> actual:string -> Tot (b:bool{b <==> expected = actual})
let validate_htu expected actual = expected = actual

(** Lemma: equality is reflexive. *)
let lemma_validate_htu_refl u : Lemma (validate_htu u u) = ()
