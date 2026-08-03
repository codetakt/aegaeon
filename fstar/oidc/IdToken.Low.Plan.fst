module IdToken.Low.Plan

open FStar.Bytes
open FStar.String
open FStar.List.Tot
open IdToken.Spec

// Planning-only views (lengths/tags/count). Not extracted.
noeq type c_bytes_plan = { len: nat }

noeq type c_option_plan = {
  tag: bool; // false=None, true=Some
  len: nat
}

noeq type c_audience_plan = {
  len: nat;     // total bytes including NULs
  count: nat    // number of entries
}

noeq type id_token_plan = {
  iss: c_bytes_plan;
  sub: c_bytes_plan;
  aud: c_audience_plan;
  nonce: c_option_plan;
  at_hash: c_option_plan;
  c_hash: c_option_plan
}

noeq type userinfo_plan = {
  name: c_option_plan;
  email: c_option_plan;
  email_verified: bool;
  updated_at: bool
}

let rec sum_string_lengths (xs:list string) : Tot nat
  (decreases xs)
  =
  match xs with
  | [] -> 0
  | x :: rest -> String.length x + sum_string_lengths rest

let audience_plan (aud:audience) : c_audience_plan =
  match aud with
  | Single s -> { len = String.length s + 1; count = 1 }
  | Multiple lst -> { len = length lst + sum_string_lengths lst; count = length lst }

let plan_id_token (spec:id_token_claims) : id_token_plan =
  let iss : c_bytes_plan = { len = String.length spec.iss } in
  let sub : c_bytes_plan = { len = String.length spec.sub } in
  let aud = audience_plan spec.aud in
  let nonce =
    match spec.nonce with
    | None -> { tag = false; len = 0 }
    | Some s -> { tag = true; len = String.length s }
  in
  let at_hash =
    match spec.at_hash with
    | None -> { tag = false; len = 0 }
    | Some b -> { tag = true; len = Bytes.length b }
  in
  let c_hash =
    match spec.c_hash with
    | None -> { tag = false; len = 0 }
    | Some b -> { tag = true; len = Bytes.length b }
  in
  {
    iss = iss;
    sub = sub;
    aud = aud;
    nonce = nonce;
    at_hash = at_hash;
    c_hash = c_hash
  }

let plan_userinfo (spec:userinfo_claims) : userinfo_plan =
  let name =
    match spec.name with
    | None -> { tag = false; len = 0 }
    | Some s -> { tag = true; len = String.length s }
  in
  let email =
    match spec.email with
    | None -> { tag = false; len = 0 }
    | Some s -> { tag = true; len = String.length s }
  in
  {
    name = name;
    email = email;
    email_verified = Option.isSome spec.email_verified;
    updated_at = Option.isSome spec.updated_at
  }
