module IdToken

(* Compatibility shim: the canonical specification now lives in IdToken.Spec.
 * This module re-exports all definitions to avoid breaking existing imports. *)
include IdToken.Spec
