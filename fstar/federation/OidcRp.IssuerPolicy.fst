module OidcRp.IssuerPolicy

(* Simplified functional contract; not an extraction/refinement of Rust, serde,
   the URL parser, metadata supplier or Redis. See upstream-issuer-policy.md. *)
type policy = { version: option nat; issuer: string; required: bool }
let freeze (issuer:string) (profile:bool) (support:option bool) : policy =
  { version = Some 1; issuer = issuer; required = profile || support = Some true }
let admit (p:policy) (received:option string) : bool =
  p.version = Some 1 &&
  (match received with
   | None -> not p.required
   | Some value -> value = p.issuer)

let frozen_identity (issuer:string) (profile:bool) (support:option bool) :
  Lemma ((freeze issuer profile support).issuer = issuer) = ()
let legacy_rejected (issuer:string) (required:bool) (received:option string) :
  Lemma (not (admit { version = None; issuer = issuer; required = required } received)) = ()
let unknown_version_rejected (p:policy) (received:option string) :
  Lemma (requires (p.version <> Some 1)) (ensures (not (admit p received))) = ()
let exact_present_issuer (p:policy) (value:string) :
  Lemma (requires (admit p (Some value))) (ensures (value = p.issuer)) = ()
let profile_requires_presence (issuer:string) (support:option bool) :
  Lemma (not (admit (freeze issuer true support) None)) = ()
let discovery_requires_presence (issuer:string) (profile:bool) :
  Lemma (not (admit (freeze issuer profile (Some true)) None)) = ()
let optional_omission_reachable (issuer:string) (support:option bool) :
  Lemma (requires (support <> Some true)) (ensures (admit (freeze issuer false support) None)) = ()
let matching_response_reachable (issuer:string) (profile:bool) (support:option bool) :
  Lemma (admit (freeze issuer profile support) (Some issuer)) = ()
let mismatch_rejected (issuer:string) (other:string) (profile:bool) (support:option bool) :
  Lemma (requires (issuer <> other))
        (ensures (not (admit (freeze issuer profile support) (Some other)))) = ()
let trailing_slash_distinct () :
  Lemma (not (admit (freeze "https://issuer.example" false None)
                   (Some "https://issuer.example/"))) = ()
