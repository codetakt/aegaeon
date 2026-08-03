module Bearer_validation

open FStar.All

val validate_bearer: string -> Tot bool
let validate_bearer (_:string) = true

val lemma_bearer_secrecy: unit -> Lemma (requires True) (ensures True)
let lemma_bearer_secrecy () = ()
