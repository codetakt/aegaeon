module HashComputation.Model

open FStar.Bytes
open HashComputation

(** Tot-level model of the OIDC hash computation.
 *
 * The Low* implementation uses `Stack`/`GHOST`, which makes it awkward to call
 * from pure contexts. Tot-context clients (e.g., `IdToken`) use this model to
 * obtain deterministic hash results.
 *
 * Previously used assume vals; now delegates to the concrete
 * `HashComputation.compute_oidc_hash` function.
 *)

(* Hash result type for the Tot model. *)
type hash_result = {
  success : bool;
  digest : bytes;
}

(* Constructor helpers *)
let hash_ok (digest:bytes) : hash_result = { success = true; digest }
let hash_err : hash_result = { success = false; digest = empty_bytes }

(** Concrete implementation: delegates to HashComputation.compute_oidc_hash. *)
val compute_oidc_hash_bytes_tot :
  alg:string ->
  input:bytes ->
  Tot hash_result
let compute_oidc_hash_bytes_tot alg input =
  match compute_oidc_hash alg input with
  | Some digest -> hash_ok digest
  | None        -> hash_err

(** Determinism: a pure Tot function applied to the same arguments yields
    the same result.  Trivially provable by reflexivity. *)
val lemma_oidc_hash_deterministic :
  alg:string ->
  input:bytes ->
  Lemma (
    compute_oidc_hash_bytes_tot alg input
    == compute_oidc_hash_bytes_tot alg input
  )
let lemma_oidc_hash_deterministic _alg _input = ()
