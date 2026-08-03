module Jose.SdJwt

(** SD-JWT (Selective Disclosure JWT) formal specification.

    Models the hash-commitment scheme of RFC 9901: an issuer replaces
    selected claims with SHA-256 digests of base64url-encoded disclosure
    arrays [salt, claim_name, claim_value].  The holder later reveals
    individual claims by presenting the corresponding disclosures.

    This module proves five key properties:
      P1  completeness        — presenting all disclosures recovers all claims
      P2  non-forgeability    — no forged disclosure accepted (collision resistance)
      P3  soundness (subset)  — partial disclosure yields partial claims
      P4  no-duplicate        — duplicate digests are detected
      P5  reconstruction      — reconstructed claims ⊆ original claims

    Crypto primitives use HACL* via Verified.Crypto.Bridge:
      • disclosure_digest     — HACL* SHA-256 (irreducible, collision resistance by assumption)
    The encoding function json_array_encode is fully concrete with proved
    roundtrip (decode_encode_inverse) and injectivity (json_array_encode_injective). *)

open FStar.List.Tot
open FStar.Json
open FStar.Bytes
open FStar.Base64
open HashComputation
open Verified.Crypto.Bridge

(* =========================================================================
  Concrete encoding — spec-level deterministic serialization
  ========================================================================= *)

open FStar.Char
module Str = FStar.String

(* Tag characters — all ASCII, well below the surrogate range *)
private let ch_L : char = char_of_int 76   (* unary length digit *)
private let ch_D : char = char_of_int 68   (* delimiter *)
private let ch_N : char = char_of_int 78   (* Null *)
private let ch_T : char = char_of_int 84   (* Bool true *)
private let ch_F : char = char_of_int 70   (* Bool false *)
private let ch_P : char = char_of_int 80   (* Positive int *)
private let ch_M : char = char_of_int 77   (* Negative int *)
private let ch_Q : char = char_of_int 81   (* String *)
private let ch_A : char = char_of_int 65   (* Array start *)
private let ch_O : char = char_of_int 79   (* Object start *)
private let ch_E : char = char_of_int 69   (* End marker *)

(* Unary length: n copies of ch_L followed by ch_D *)
let rec unary_of_nat (n:nat) : Tot (list char) (decreases n) =
  if n = 0 then [ch_D]
  else ch_L :: unary_of_nat (n - 1)

(* Parse unary: count ch_L chars until ch_D *)
let rec parse_unary_acc (cs:list char) (acc:nat)
  : Tot (option (nat * list char)) (decreases cs) =
  match cs with
  | [] -> None
  | c :: rest ->
    if c = ch_D then Some (acc, rest)
    else if c = ch_L then parse_unary_acc rest (acc + 1)
    else None

(* Length-prefixed char list encoding *)
let encode_chars (cs:list char) : Tot (list char) =
  unary_of_nat (FStar.List.Tot.length cs) @ cs

let parse_chars (cs:list char) : Tot (option (list char * list char)) =
  match parse_unary_acc cs 0 with
  | None -> None
  | Some (n, rest) ->
    if n <= FStar.List.Tot.length rest then Some (FStar.List.Tot.splitAt n rest)
    else None

(* String encoding via char lists *)
let encode_str (s:string) : Tot (list char) =
  encode_chars (Str.list_of_string s)

let parse_str (cs:list char) : Tot (option (string * list char)) =
  match parse_chars cs with
  | None -> None
  | Some (content, rest) -> Some (Str.string_of_list content, rest)

(* JSON encoding — tag-based, self-delimiting, recursive.
  The mutual recursion over FStar.Json requires increased fuel for the sub-term ordering. *)
#push-options "--fuel 4 --ifuel 2 --z3rlimit 20"
let rec json_to_chars (v:json) : Tot (list char) (decreases v) =
  match v with
  | Null -> [ch_N]
  | Bool true -> [ch_T]
  | Bool false -> [ch_F]
  | Number n ->
    if n >= 0 then ch_P :: unary_of_nat n
    else ch_M :: unary_of_nat (0 - n)
  | String s -> ch_Q :: encode_str s
  | Array elems -> ch_A :: json_list_to_chars elems @ [ch_E]
  | Object pairs -> ch_O :: json_pairs_to_chars pairs @ [ch_E]
and json_list_to_chars (l:list json) : Tot (list char) (decreases l) =
  match l with
  | [] -> []
  | v :: rest -> json_to_chars v @ json_list_to_chars rest
and json_pairs_to_chars (l:list (string * json)) : Tot (list char) (decreases l) =
  match l with
  | [] -> []
  | (k, v) :: rest -> encode_str k @ json_to_chars v @ json_pairs_to_chars rest
#pop-options

(* JSON decoding — mutual recursion with length-based termination *)
#push-options "--fuel 4 --ifuel 2 --z3rlimit 20"
let rec chars_to_json (cs:list char)
  : Tot (option (json * list char)) (decreases %[FStar.List.Tot.length cs; 0]) =
  match cs with
  | [] -> None
  | c :: rest ->
    if c = ch_N then Some (Null, rest)
    else if c = ch_T then Some (Bool true, rest)
    else if c = ch_F then Some (Bool false, rest)
    else if c = ch_P then
      (match parse_unary_acc rest 0 with
        | Some (n, rest') -> Some (Number n, rest')
        | None -> None)
    else if c = ch_M then
      (match parse_unary_acc rest 0 with
        | Some (n, rest') -> Some (Number (0 - n), rest')
        | None -> None)
    else if c = ch_Q then
      (match parse_str rest with
        | Some (s, rest') -> Some (String s, rest')
        | None -> None)
    else if c = ch_A then
      (match chars_to_json_list rest with
        | Some (elems, rest') ->
          (match rest' with
            | ch :: rest'' -> if ch = ch_E then Some (Array elems, rest'') else None
            | [] -> None)
        | None -> None)
    else if c = ch_O then
      (match chars_to_json_pairs rest with
        | Some (pairs, rest') ->
          (match rest' with
            | ch :: rest'' -> if ch = ch_E then Some (Object pairs, rest'') else None
            | [] -> None)
        | None -> None)
    else None
and chars_to_json_list (cs:list char)
  : Tot (option (list json * list char)) (decreases %[FStar.List.Tot.length cs; 1]) =
  match cs with
  | [] -> Some ([], cs)
  | c :: _ ->
    if c = ch_E then Some ([], cs)
    else
      (match chars_to_json cs with
        | Some (v, rest') ->
          if FStar.List.Tot.length rest' < FStar.List.Tot.length cs then
            (match chars_to_json_list rest' with
              | Some (vs, rest'') -> Some (v :: vs, rest'')
              | None -> None)
          else None
        | None -> None)
and chars_to_json_pairs (cs:list char)
  : Tot (option (list (string * json) * list char)) (decreases %[FStar.List.Tot.length cs; 1]) =
  match cs with
  | [] -> Some ([], cs)
  | c :: _ ->
    if c = ch_E then Some ([], cs)
    else
      (match parse_str cs with
        | Some (key, rest') ->
          if FStar.List.Tot.length rest' < FStar.List.Tot.length cs then
            (match chars_to_json rest' with
              | Some (value, rest'') ->
                if FStar.List.Tot.length rest'' < FStar.List.Tot.length cs then
                  (match chars_to_json_pairs rest'' with
                    | Some (pairs, rest''') -> Some ((key, value) :: pairs, rest''')
                    | None -> None)
                else None
              | None -> None)
          else None
        | None -> None)
#pop-options

(** Concrete json_array_encode: length-prefixed salt + name + json encoding. *)
let json_array_encode (salt:string) (name:string) (value:json) : Tot string =
  Str.string_of_list (encode_str salt @ encode_str name @ json_to_chars value)

(* ---- Roundtrip helper lemmas ---- *)

let rec lemma_parse_unary_acc_roundtrip (n:nat) (rest:list char) (acc:nat)
  : Lemma (ensures parse_unary_acc (unary_of_nat n @ rest) acc == Some (acc + n, rest))
    (decreases n)
  = if n = 0 then ()
    else lemma_parse_unary_acc_roundtrip (n - 1) rest (acc + 1)

let rec lemma_splitAt_length_prefix (l1:list char) (l2:list char)
  : Lemma (ensures FStar.List.Tot.splitAt (FStar.List.Tot.length l1) (l1 @ l2) == (l1, l2))
    (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: tl -> lemma_splitAt_length_prefix tl l2

let lemma_parse_chars_roundtrip (cs:list char) (rest:list char)
  : Lemma (ensures parse_chars (encode_chars cs @ rest) == Some (cs, rest))
  = FStar.List.Tot.Properties.append_assoc (unary_of_nat (FStar.List.Tot.length cs)) cs rest;
    lemma_parse_unary_acc_roundtrip (FStar.List.Tot.length cs) (cs @ rest) 0;
    FStar.List.Tot.Properties.append_length cs rest;
    lemma_splitAt_length_prefix cs rest

let lemma_parse_str_roundtrip (s:string) (rest:list char)
  : Lemma (ensures parse_str (encode_str s @ rest) == Some (s, rest))
  = lemma_parse_chars_roundtrip (Str.list_of_string s) rest;
    Str.string_of_list_of_string s

(* JSON roundtrip: chars_to_json (json_to_chars v @ rest) == Some (v, rest)
  Requires rest to start with ch_E or be empty for the list/pairs cases.
  The mutual recursion over FStar.Json + lexicographic termination creates a large
  SMT query; the increased rlimit and fuel are required for Z3 to close the proof. *)
#push-options "--z3rlimit 400 --fuel 8 --ifuel 4"
let rec lemma_json_roundtrip (v:json) (rest:list char)
  : Lemma (ensures chars_to_json (json_to_chars v @ rest) == Some (v, rest))
    (decreases v)
  = match v with
    | Null | Bool _ -> ()
    | Number n ->
      if n >= 0 then lemma_parse_unary_acc_roundtrip n rest 0
      else lemma_parse_unary_acc_roundtrip (0 - n) rest 0
    | String s -> lemma_parse_str_roundtrip s rest
    | Array elems ->
      FStar.List.Tot.Properties.append_assoc
        (json_list_to_chars elems) [ch_E] rest;
      lemma_json_list_roundtrip elems (ch_E :: rest)
    | Object pairs ->
      FStar.List.Tot.Properties.append_assoc
        (json_pairs_to_chars pairs) [ch_E] rest;
      lemma_json_pairs_roundtrip pairs (ch_E :: rest)

and lemma_json_list_roundtrip (l:list json) (term:list char)
  : Lemma
    (requires (match term with [] -> True | c :: _ -> c = ch_E))
    (ensures chars_to_json_list (json_list_to_chars l @ term) == Some (l, term))
    (decreases l)
  = match l with
    | [] -> ()
    | v :: tl ->
      FStar.List.Tot.Properties.append_assoc
        (json_to_chars v) (json_list_to_chars tl) term;
      lemma_json_roundtrip v (json_list_to_chars tl @ term);
      FStar.List.Tot.Properties.append_length (json_to_chars v) (json_list_to_chars tl @ term);
      lemma_json_list_roundtrip tl term

and lemma_json_pairs_roundtrip (l:list (string * json)) (term:list char)
  : Lemma
    (requires (match term with [] -> True | c :: _ -> c = ch_E))
    (ensures chars_to_json_pairs (json_pairs_to_chars l @ term) == Some (l, term))
    (decreases l)
  = match l with
    | [] -> ()
    | (k, v) :: tl ->
      FStar.List.Tot.Properties.append_assoc
        (encode_str k) (json_to_chars v @ json_pairs_to_chars tl) term;
      FStar.List.Tot.Properties.append_assoc
        (json_to_chars v) (json_pairs_to_chars tl) term;
      lemma_parse_str_roundtrip k (json_to_chars v @ json_pairs_to_chars tl @ term);
      FStar.List.Tot.Properties.append_length
        (encode_str k) (json_to_chars v @ json_pairs_to_chars tl @ term);
      lemma_json_roundtrip v (json_pairs_to_chars tl @ term);
      FStar.List.Tot.Properties.append_length (json_to_chars v) (json_pairs_to_chars tl @ term);
      lemma_json_pairs_roundtrip tl term
#pop-options

(* =========================================================================
  Digest dependencies — HACL* SHA-256 via Verified.Crypto.Bridge
  ========================================================================= *)

(** Compute the digest of an already-encoded disclosure string.
    Corresponds to `base64url(SHA-256(ascii(encoded)))` in Rust.
    Delegates to HACL* SHA-256 via Verified.Crypto.Bridge.sha256_of_string.
    Real cryptographic computation — NOT identity.
    Marked `irreducible` — Z3 sees only the type signature. *)
irreducible
let disclosure_digest (encoded:string) : Tot string = sha256_of_string encoded

(** Determinism: the same encoded input always yields the same digest.
    Reflexivity — the SMTPat triggers Z3 on disclosure_digest occurrences. *)
let disclosure_digest_deterministic (e:string)
  : Lemma (ensures disclosure_digest e == disclosure_digest e)
  [SMTPat (disclosure_digest e)]
  = ()

(** Collision resistance lifted to the disclosure digest function.
    Two distinct encoded disclosures never share a digest.
    This is a computational hardness assumption on SHA-256 — NOT provable
    from first principles. Previously "proved" via reveal_opaque on
    an identity model (tautological). *)
assume val disclosure_digest_collision_resistant:
  e1:string -> e2:string ->
  Lemma (requires e1 =!= e2)
        (ensures disclosure_digest e1 =!= disclosure_digest e2)
  [SMTPat (disclosure_digest e1); SMTPat (disclosure_digest e2)]

(* =========================================================================
  Core types
  ========================================================================= *)

(** A single SD-JWT disclosure: the triple (salt, claim_name, claim_value). *)
type disclosure = {
  salt       : string;
  claim_name : string;
  claim_value: json;
}

(** Encode a disclosure to its base64url string form. *)
val encode_disclosure : disclosure -> Tot string
let encode_disclosure d =
  json_array_encode d.salt d.claim_name d.claim_value

(** Compute the digest of a disclosure. *)
val digest_of : disclosure -> Tot string
let digest_of d = disclosure_digest (encode_disclosure d)

(** A claim is a key-value pair drawn from a JSON object. *)
type claim = string * json

(** SD-JWT claims wrapper.  The underlying jwt_claims record is NOT modified;
    this type adds the selective-disclosure overlay. *)
type sd_jwt_claims = {
  (** Claims that remain in plaintext in the JWT payload. *)
  plaintext_claims : list claim;
  (** Digests in the `_sd` array (base64url-encoded SHA-256 hashes). *)
  sd_digests       : list string;
  (** The hash algorithm identifier (`_sd_alg`), must be "sha-256". *)
  sd_alg           : string;
}

(* =========================================================================
  Issuance
  ========================================================================= *)

(** Result of issuing an SD-JWT. *)
type issuance_result = {
  payload      : sd_jwt_claims;
  disclosures  : list disclosure;
}

(** Build the list of disclosures and their digests for the given
    selectively-disclosed claims. *)
val build_disclosures :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Tot (list disclosure * list string)
  (decreases claims)
let rec build_disclosures claims sd_names salts =
  match claims, salts with
  | [], _ -> ([], [])
  | (k, v) :: tl, s :: rest_salts ->
    if mem k sd_names then
      let d  = { salt = s; claim_name = k; claim_value = v } in
      let dg = digest_of d in
      let (ds, dgs) = build_disclosures tl sd_names rest_salts in
      (d :: ds, dg :: dgs)
    else
      build_disclosures tl sd_names rest_salts
  | _ :: _, [] -> ([], [])  (* Should not happen given precondition *)

(** Filter claims, keeping only those NOT in the sd set (plaintext). *)
val plaintext_of : claims:list claim -> sd_names:list string -> Tot (list claim)
  (decreases claims)
let rec plaintext_of claims sd_names =
  match claims with
  | [] -> []
  | (k, v) :: tl ->
    if mem k sd_names then plaintext_of tl sd_names
    else (k, v) :: plaintext_of tl sd_names

(** Issue an SD-JWT: split claims into plaintext and selectively-disclosed,
    produce digests and disclosures. *)
val issue :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Tot issuance_result
let issue claims sd_names salts =
  let pt = plaintext_of claims sd_names in
  let (ds, dgs) = build_disclosures claims sd_names salts in
  { payload = { plaintext_claims = pt;
                sd_digests       = dgs;
                sd_alg           = "sha-256" };
    disclosures = ds }

(* =========================================================================
  Verification / reconstruction
  ========================================================================= *)

(** Look up a digest in the sd_digests list. *)
val digest_in : d:string -> ds:list string -> Tot bool
let digest_in d ds = mem d ds

(** Check whether a list of strings contains duplicates. *)
val has_duplicates : l:list string -> Tot bool (decreases l)
let rec has_duplicates l =
  match l with
  | [] -> false
  | hd :: tl -> mem hd tl || has_duplicates tl

(** Compute the list of digests from a list of encoded disclosures. *)
val compute_digests : encs:list string -> Tot (list string) (decreases encs)
let rec compute_digests encs =
  match encs with
  | [] -> []
  | hd :: tl -> disclosure_digest hd :: compute_digests tl

(** Decode an encoded disclosure back to a disclosure record.
    Concrete inverse of encode_disclosure with canonicality check. *)
let decode_disclosure (enc:string) : Tot (option disclosure) =
  let chars = Str.list_of_string enc in
  match parse_str chars with
  | Some (salt, rest1) ->
    (match parse_str rest1 with
      | Some (name, rest2) ->
        (match chars_to_json rest2 with
          | Some (value, []) ->
            let d = { salt = salt; claim_name = name; claim_value = value } in
            if encode_disclosure d = enc then Some d
            else None
          | _ -> None)
      | None -> None)
  | None -> None

(** Reconstruct claims: accumulator loop over encoded disclosures. *)
let rec reconstruct_acc
  (sd:sd_jwt_claims)
  (encoded_disclosures:list string)
  (acc:list claim)
  : Tot (option (list claim))
  (decreases encoded_disclosures)
  =
  match encoded_disclosures with
  | [] -> Some (sd.plaintext_claims @ acc)
  | enc :: rest ->
    let dg = disclosure_digest enc in
    if not (digest_in dg sd.sd_digests) then None
    else
      match decode_disclosure enc with
      | None -> None
      | Some d -> reconstruct_acc sd rest ((d.claim_name, d.claim_value) :: acc)

(** Reconstruct claims from disclosures whose digests appear in the
    sd_digests list.  Returns None on duplicate or unknown digest. *)
val reconstruct :
  sd:sd_jwt_claims -> encoded_disclosures:list string ->
  Tot (option (list claim))
let reconstruct sd encoded_disclosures =
  let presented_digests = compute_digests encoded_disclosures in
  if has_duplicates presented_digests then None
  else reconstruct_acc sd encoded_disclosures []

(** Proved: decode_disclosure is a left-inverse of encode_disclosure.
    Uses roundtrip lemmas for parse_str and chars_to_json plus
    the string_of_list / list_of_string bijection. *)
let decode_encode_inverse (d:disclosure)
  : Lemma (ensures decode_disclosure (encode_disclosure d) == Some d)
    [SMTPat (decode_disclosure (encode_disclosure d))]
  = let cs = encode_str d.salt @ encode_str d.claim_name @ json_to_chars d.claim_value in
    Str.list_of_string_of_list cs;
    FStar.List.Tot.Properties.append_assoc
      (encode_str d.salt) (encode_str d.claim_name) (json_to_chars d.claim_value);
    lemma_parse_str_roundtrip d.salt (encode_str d.claim_name @ json_to_chars d.claim_value);
    lemma_parse_str_roundtrip d.claim_name (json_to_chars d.claim_value);
    FStar.List.Tot.Properties.append_l_nil (json_to_chars d.claim_value);
    lemma_json_roundtrip d.claim_value []

(** Proved: json_array_encode is injective — derived from decode_encode_inverse.
    If two triples encode to the same string, decoding yields the same disclosure,
    so the triples must be equal. *)
let json_array_encode_injective
  (s1:string) (n1:string) (v1:json)
  (s2:string) (n2:string) (v2:json)
  : Lemma (requires json_array_encode s1 n1 v1 == json_array_encode s2 n2 v2)
          (ensures s1 == s2 /\ n1 == n2 /\ v1 == v2)
  = let d1 = { salt = s1; claim_name = n1; claim_value = v1 } in
    let d2 = { salt = s2; claim_name = n2; claim_value = v2 } in
    decode_encode_inverse d1;
    decode_encode_inverse d2

(* =========================================================================
  Helper lemmas
  ========================================================================= *)

(** mem respects list membership for the head element. *)
val mem_head : (#a:eqtype) -> x:a -> tl:list a ->
  Lemma (ensures mem x (x :: tl) = true)
let mem_head #a x tl = ()

(** If x is in xs then it is in (y :: xs). *)
val mem_cons : (#a:eqtype) -> x:a -> y:a -> xs:list a ->
  Lemma (requires mem x xs = true)
        (ensures mem x (y :: xs) = true)
let mem_cons #a x y xs = ()

(** Claims from build_disclosures come from the original list. *)
val build_disclosures_names :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Lemma (ensures (
    let (ds, _) = build_disclosures claims sd_names salts in
    forall (d:disclosure). mem d ds ==>
      (exists (v:json). mem (d.claim_name, v) claims /\ mem d.claim_name sd_names)))
  (decreases claims)
let rec build_disclosures_names claims sd_names salts =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest ->
    build_disclosures_names tl sd_names rest
  | _ :: _, [] -> ()

(** Plaintext claims are a subset of the original claims. *)
val plaintext_subset :
  claims:list claim -> sd_names:list string ->
  Lemma (ensures (
    let pt = plaintext_of claims sd_names in
    forall (c:claim). mem c pt ==> mem c claims))
  (decreases claims)
let rec plaintext_subset claims sd_names =
  match claims with
  | [] -> ()
  | _ :: tl -> plaintext_subset tl sd_names

(** The number of digests equals the number of disclosures. *)
val build_disclosures_length :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Lemma (ensures (
    let (ds, dgs) = build_disclosures claims sd_names salts in
    FStar.List.Tot.length ds = FStar.List.Tot.length dgs))
  (decreases claims)
let rec build_disclosures_length claims sd_names salts =
  match claims, salts with
  | [], _ -> ()
  | (k, _) :: tl, s :: rest ->
    if mem k sd_names then
      build_disclosures_length tl sd_names rest
    else
      build_disclosures_length tl sd_names rest
  | _ :: _, [] -> ()

(** If a forged disclosure's encoding differs from every issued disclosure's
    encoding, then by collision resistance the forged digest cannot appear
    in the sd_digests list.  Follows the recursion of build_disclosures. *)
val forged_digest_not_in_build :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  forged:disclosure ->
  Lemma (requires (
    let (ds, _) = build_disclosures claims sd_names salts in
    forall (d:disclosure). mem d ds ==>
      encode_disclosure forged =!= encode_disclosure d))
  (ensures (
    let (_, dgs) = build_disclosures claims sd_names salts in
    mem (digest_of forged) dgs = false))
  (decreases claims)
let rec forged_digest_not_in_build claims sd_names salts forged =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if mem k sd_names then begin
      let d = { salt = s; claim_name = k; claim_value = v } in
      (* Precondition gives: encode_disclosure forged =!= encode_disclosure d *)
      (* Collision resistance: distinct encodings → distinct digests *)
      disclosure_digest_collision_resistant
        (encode_disclosure forged) (encode_disclosure d);
      (* Recurse for the remaining disclosures *)
      forged_digest_not_in_build tl sd_names rest_salts forged
    end
    else
      forged_digest_not_in_build tl sd_names rest_salts forged
  | _ :: _, [] -> ()

(* =========================================================================
  Property P1: Completeness
  =========================================================================

  If the holder presents ALL disclosures produced by the issuer, then
  every selectively-disclosed claim is reconstructed. *)

(** Helper: each disclosure from build_disclosures has
    (claim_name, claim_value) in the original claims. *)
#push-options "--z3rlimit 50 --fuel 4 --ifuel 2"
private val lemma_build_disc_claim_mem :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  d:disclosure ->
  Lemma
    (requires mem d (fst (build_disclosures claims sd_names salts)))
    (ensures mem (d.claim_name, d.claim_value) claims = true)
    (decreases claims)
private let rec lemma_build_disc_claim_mem claims sd_names salts d =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if mem k sd_names then begin
      let d_i = { salt = s; claim_name = k; claim_value = v } in
      let (ds_tl, _) = build_disclosures tl sd_names rest_salts in
      if d = d_i then ()
      else begin
        assert (mem d ds_tl);
        lemma_build_disc_claim_mem tl sd_names rest_salts d
      end
    end
    else
      lemma_build_disc_claim_mem tl sd_names rest_salts d
  | _ :: _, [] -> ()
#pop-options

(** Helper: each disclosure from build_disclosures has its digest in the digest list. *)
#push-options "--z3rlimit 50 --fuel 4 --ifuel 2"
private val lemma_build_disc_digest_mem :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  d:disclosure ->
  Lemma
    (requires mem d (fst (build_disclosures claims sd_names salts)))
    (ensures mem (digest_of d) (snd (build_disclosures claims sd_names salts)) = true)
    (decreases claims)
private let rec lemma_build_disc_digest_mem claims sd_names salts d =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if mem k sd_names then begin
      let d_i = { salt = s; claim_name = k; claim_value = v } in
      let (ds_tl, dgs_tl) = build_disclosures tl sd_names rest_salts in
      if d = d_i then ()
      else begin
        assert (mem d ds_tl);
        lemma_build_disc_digest_mem tl sd_names rest_salts d
      end
    end
    else
      lemma_build_disc_digest_mem tl sd_names rest_salts d
  | _ :: _, [] -> ()
#pop-options

(** Helper: reconstruct_acc succeeds and acc is included in the result
    when all encoded disclosures have valid digests and decode properly.
    Returns the result and proves it contains acc plus decoded claims. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
private val lemma_reconstruct_acc_succeeds :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  ds:list disclosure ->
  Lemma
    (requires
      FStar.List.Tot.length encs = FStar.List.Tot.length ds /\
      encs == map encode_disclosure ds /\
      (forall (d:disclosure). mem d ds ==> mem (digest_of d) sd.sd_digests))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some _ -> True
      | None -> False))
    (decreases encs)
private let rec lemma_reconstruct_acc_succeeds sd encs acc ds =
  match encs, ds with
  | [], [] -> ()
  | enc :: rest_encs, d :: rest_ds ->
    assert (enc == encode_disclosure d);
    assert (mem d ds);
    assert (mem (digest_of d) sd.sd_digests);
    assert (digest_of d == disclosure_digest (encode_disclosure d));
    assert (disclosure_digest enc == digest_of d);
    assert (digest_in (disclosure_digest enc) sd.sd_digests = true);
    assert (not (digest_in (disclosure_digest enc) sd.sd_digests) = false);
    decode_encode_inverse d;
    assert (decode_disclosure enc == Some d);
    let new_acc = (d.claim_name, d.claim_value) :: acc in
    assert (forall (d':disclosure). mem d' rest_ds ==> mem d' ds);
    assert (forall (d':disclosure). mem d' rest_ds ==> mem (digest_of d') sd.sd_digests);
    lemma_reconstruct_acc_succeeds sd rest_encs new_acc rest_ds
#pop-options

(** Helper: reconstruct_acc result contains the accumulator claims. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
private val lemma_reconstruct_acc_contains_acc :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  ds:list disclosure ->
  Lemma
    (requires
      FStar.List.Tot.length encs = FStar.List.Tot.length ds /\
      encs == map encode_disclosure ds /\
      (forall (d:disclosure). mem d ds ==> mem (digest_of d) sd.sd_digests))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some result -> (forall (c:claim). mem c acc ==> mem c result)
      | None -> False))
    (decreases encs)
private let rec lemma_reconstruct_acc_contains_acc sd encs acc ds =
  match encs, ds with
  | [], [] ->
    assert (reconstruct_acc sd [] acc == Some (sd.plaintext_claims @ acc));
    let result = sd.plaintext_claims @ acc in
    let aux (c:claim) : Lemma (requires mem c acc) (ensures mem c result) =
      FStar.List.Tot.Properties.append_mem sd.plaintext_claims acc c
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires aux)
  | enc :: rest_encs, d :: rest_ds ->
    assert (enc == encode_disclosure d);
    assert (mem d ds);
    assert (mem (digest_of d) sd.sd_digests);
    assert (disclosure_digest enc == digest_of d);
    assert (digest_in (disclosure_digest enc) sd.sd_digests = true);
    decode_encode_inverse d;
    assert (decode_disclosure enc == Some d);
    let new_acc = (d.claim_name, d.claim_value) :: acc in
    assert (forall (c:claim). mem c acc ==> mem c new_acc);
    lemma_reconstruct_acc_contains_acc sd rest_encs new_acc rest_ds
#pop-options

(** Helper: reconstruct_acc result contains the plaintext claims. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
private val lemma_reconstruct_acc_contains_pt :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  ds:list disclosure ->
  Lemma
    (requires
      FStar.List.Tot.length encs = FStar.List.Tot.length ds /\
      encs == map encode_disclosure ds /\
      (forall (d:disclosure). mem d ds ==> mem (digest_of d) sd.sd_digests))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some result -> (forall (c:claim). mem c sd.plaintext_claims ==> mem c result)
      | None -> False))
    (decreases encs)
private let rec lemma_reconstruct_acc_contains_pt sd encs acc ds =
  match encs, ds with
  | [], [] ->
    assert (reconstruct_acc sd [] acc == Some (sd.plaintext_claims @ acc));
    let result = sd.plaintext_claims @ acc in
    let aux (c:claim) : Lemma (requires mem c sd.plaintext_claims) (ensures mem c result) =
      FStar.List.Tot.Properties.append_mem sd.plaintext_claims acc c
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires aux)
  | enc :: rest_encs, d :: rest_ds ->
    assert (enc == encode_disclosure d);
    assert (mem d ds);
    assert (mem (digest_of d) sd.sd_digests);
    assert (disclosure_digest enc == digest_of d);
    assert (digest_in (disclosure_digest enc) sd.sd_digests = true);
    decode_encode_inverse d;
    assert (decode_disclosure enc == Some d);
    let new_acc = (d.claim_name, d.claim_value) :: acc in
    lemma_reconstruct_acc_contains_pt sd rest_encs new_acc rest_ds
#pop-options

(** Helper: reconstruct_acc result contains decoded disclosure claims. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
private val lemma_reconstruct_acc_contains_disc :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  ds:list disclosure ->
  Lemma
    (requires
      FStar.List.Tot.length encs = FStar.List.Tot.length ds /\
      encs == map encode_disclosure ds /\
      (forall (d:disclosure). mem d ds ==> mem (digest_of d) sd.sd_digests))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some result ->
        (forall (d:disclosure). mem d ds ==> mem (d.claim_name, d.claim_value) result)
      | None -> False))
    (decreases encs)
private let rec lemma_reconstruct_acc_contains_disc sd encs acc ds =
  match encs, ds with
  | [], [] -> ()
  | enc :: rest_encs, d :: rest_ds ->
    assert (enc == encode_disclosure d);
    assert (mem d ds);
    assert (mem (digest_of d) sd.sd_digests);
    assert (disclosure_digest enc == digest_of d);
    assert (digest_in (disclosure_digest enc) sd.sd_digests = true);
    decode_encode_inverse d;
    assert (decode_disclosure enc == Some d);
    let new_acc = (d.claim_name, d.claim_value) :: acc in
    (* d is in new_acc, so it will be in the result via contains_acc *)
    lemma_reconstruct_acc_contains_disc sd rest_encs new_acc rest_ds;
    (* d itself: it's in new_acc, so it's in the result *)
    lemma_reconstruct_acc_contains_acc sd rest_encs new_acc rest_ds
#pop-options

(** Helper: every claim is either plaintext or has a corresponding disclosure. *)
#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"
private val lemma_claim_plaintext_or_disclosed :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  c:claim ->
  Lemma
    (requires mem c claims)
    (ensures (
      let pt = plaintext_of claims sd_names in
      let (ds, _) = build_disclosures claims sd_names salts in
      mem c pt \/
      (exists (d:disclosure). mem d ds /\ d.claim_name == fst c /\ d.claim_value == snd c)))
    (decreases claims)
private let rec lemma_claim_plaintext_or_disclosed claims sd_names salts c =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if (k, v) = c then begin
      if mem k sd_names then begin
        (* c is selectively disclosed *)
        let d = { salt = s; claim_name = k; claim_value = v } in
        let (ds_tl, _) = build_disclosures tl sd_names rest_salts in
        assert (mem d (fst (build_disclosures claims sd_names salts)));
        assert (d.claim_name == fst c);
        assert (d.claim_value == snd c)
      end
      else begin
        (* c is plaintext *)
        assert (mem c (plaintext_of claims sd_names))
      end
    end
    else begin
      assert (mem c tl);
      lemma_claim_plaintext_or_disclosed tl sd_names rest_salts c;
      let pt_tl = plaintext_of tl sd_names in
      let (ds_tl, _) = build_disclosures tl sd_names rest_salts in
      if mem k sd_names then begin
        (* plaintext_of (k,v)::tl = plaintext_of tl since k in sd_names *)
        assert (plaintext_of claims sd_names == plaintext_of tl sd_names);
        (* build_disclosures adds d_i :: ds_tl *)
        assert (
          forall (d:disclosure).
            mem d ds_tl ==> mem d (fst (build_disclosures claims sd_names salts)))
      end
      else begin
        (* plaintext_of (k,v)::tl = (k,v) :: plaintext_of tl *)
        assert (plaintext_of claims sd_names == (k, v) :: plaintext_of tl sd_names);
        if mem c pt_tl then
          assert (mem c (plaintext_of claims sd_names))
        else begin
          (* c must have a disclosure in ds_tl, which is subset of ds *)
          assert (
            exists (d:disclosure).
              mem d ds_tl /\ d.claim_name == fst c /\ d.claim_value == snd c);
          assert (
            forall (d:disclosure).
              mem d ds_tl ==> mem d (fst (build_disclosures claims sd_names salts)))
        end
      end
    end
  | _ :: _, [] -> ()
#pop-options

(** Helper: map length equals input length. *)
private let rec lemma_map_length (#a #b:Type) (f:a -> Tot b) (xs:list a)
  : Lemma (ensures FStar.List.Tot.length (map f xs) = FStar.List.Tot.length xs)
    (decreases xs)
  = match xs with
  | [] -> ()
  | _ :: tl -> lemma_map_length f tl

(** Helper: if d is in ds, then encode_disclosure d is in map encode_disclosure ds. *)
private let rec lemma_mem_map_encode (d:disclosure) (ds:list disclosure)
  : Lemma (requires mem d ds)
          (ensures mem (encode_disclosure d) (map encode_disclosure ds))
    (decreases ds)
  = match ds with
  | [] -> ()
  | hd :: tl ->
    if hd = d then ()
    else lemma_mem_map_encode d tl

(** Helper: every original claim is in the reconstruction result.
    Direct recursive proof over claims, avoiding existential elimination.
    Each claim is either plaintext (in result via contains_pt) or has a matching
    disclosure (in result via contains_disc). *)
#push-options "--z3rlimit 150 --fuel 6 --ifuel 3"
private val lemma_every_claim_reconstructed :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  c:claim -> result:list claim ->
  Lemma
    (requires
      mem c claims /\
      (forall (x:claim). mem x (plaintext_of claims sd_names) ==> mem x result) /\
      (let (ds, _) = build_disclosures claims sd_names salts in
        forall (d:disclosure). mem d ds ==> mem (d.claim_name, d.claim_value) result))
    (ensures mem c result)
    (decreases claims)
private let rec lemma_every_claim_reconstructed claims sd_names salts c result =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if c = (k, v) then begin
      if mem k sd_names then begin
        (* c = (k,v) is selectively disclosed — its disclosure is in build_disclosures output *)
        let d = { salt = s; claim_name = k; claim_value = v } in
        let (ds, _) = build_disclosures claims sd_names salts in
        assert (mem d ds);
        assert (mem (d.claim_name, d.claim_value) result);
        assert (d.claim_name == k);
        assert (d.claim_value == v);
        assert ((d.claim_name, d.claim_value) == (k, v))
      end else begin
        (* c = (k,v) is plaintext *)
        assert (mem c (plaintext_of claims sd_names))
      end
    end else begin
      assert (mem c tl);
      (* plaintext_of tl ⊆ plaintext_of claims — by one step of unfolding *)
      let pt_claims = plaintext_of claims sd_names in
      let pt_tl = plaintext_of tl sd_names in
      let aux_pt (x:claim)
        : Lemma (requires mem x pt_tl) (ensures mem x result) =
        assert (mem x pt_claims)
      in
      FStar.Classical.forall_intro (FStar.Classical.move_requires aux_pt);
      (* build_disclosures tl ⊆ build_disclosures claims — by one step of unfolding *)
      let (ds_claims, _) = build_disclosures claims sd_names salts in
      let (ds_tl, _) = build_disclosures tl sd_names rest_salts in
      let aux_ds (d:disclosure)
        : Lemma (requires mem d ds_tl) (ensures mem (d.claim_name, d.claim_value) result) =
        assert (mem d ds_claims)
      in
      FStar.Classical.forall_intro (FStar.Classical.move_requires aux_ds);
      lemma_every_claim_reconstructed tl sd_names rest_salts c result
    end
  | _ :: _, [] -> ()
#pop-options

(** Completeness: presenting all disclosures recovers all claims.
    Proved by: (1) showing reconstruct_acc succeeds via the digest/decode helpers,
    (2) showing plaintext and disclosure claims are in the result, (3) showing
    every original claim matches one of these via lemma_every_claim_reconstructed. *)
#push-options "--z3rlimit 300 --fuel 6 --ifuel 3"
val lemma_completeness :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Lemma (ensures (
    let r = issue claims sd_names salts in
    let encs = map encode_disclosure r.disclosures in
    has_duplicates (compute_digests encs) = false ==>
    (match reconstruct r.payload encs with
      | Some reconstructed ->
        (forall (c:claim). mem c claims ==> mem c reconstructed)
      | None -> False)))
let lemma_completeness claims sd_names salts =
  let r = issue claims sd_names salts in
  let ds = r.disclosures in
  let sd = r.payload in
  let encs = map encode_disclosure ds in
  (* Establish: encs and ds have the same length *)
  lemma_map_length encode_disclosure ds;
  assert (FStar.List.Tot.length encs = FStar.List.Tot.length ds);
  assert (encs == map encode_disclosure ds);
  (* Establish: every disclosure's digest is in sd.sd_digests *)
  let disc_digest_ok (d:disclosure)
    : Lemma (requires mem d ds)
            (ensures mem (digest_of d) sd.sd_digests) =
    lemma_build_disc_digest_mem claims sd_names salts d
  in
  FStar.Classical.forall_intro (FStar.Classical.move_requires disc_digest_ok);
  (* If duplicates exist, the implication is vacuously true *)
  if has_duplicates (compute_digests encs) then ()
  else begin
    (* reconstruct = reconstruct_acc sd encs [] since no dups *)
    assert (reconstruct sd encs == reconstruct_acc sd encs []);
    (* reconstruct_acc succeeds *)
    lemma_reconstruct_acc_succeeds sd encs [] ds;
    (* The result contains plaintext claims *)
    lemma_reconstruct_acc_contains_pt sd encs [] ds;
    (* The result contains disclosure claims *)
    lemma_reconstruct_acc_contains_disc sd encs [] ds;
    (* Connect issue output to build_disclosures *)
    assert (sd == (issue claims sd_names salts).payload);
    assert (sd.plaintext_claims == plaintext_of claims sd_names);
    assert (ds == fst (build_disclosures claims sd_names salts));
    (* Now show every original claim is in the result *)
    match reconstruct_acc sd encs [] with
    | Some result ->
      assert (forall (x:claim). mem x sd.plaintext_claims ==> mem x result);
      assert (forall (x:claim). mem x (plaintext_of claims sd_names) ==> mem x result);
      assert (forall (d:disclosure). mem d ds ==> mem (d.claim_name, d.claim_value) result);
      let claim_in_result (c:claim)
        : Lemma (requires mem c claims)
                (ensures mem c result) =
        lemma_every_claim_reconstructed claims sd_names salts c result
      in
      FStar.Classical.forall_intro (FStar.Classical.move_requires claim_in_result)
    | None -> ()
  end
#pop-options

(* =========================================================================
  Property P2: Non-forgeability
  =========================================================================

  An attacker cannot forge a disclosure that the verifier accepts
  unless they find a SHA-256 collision. Formally: if a disclosure d
  was NOT produced by the issuer, its digest cannot match any digest
  in the _sd array (under the collision resistance assumption). *)

val lemma_non_forgeability :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  forged:disclosure ->
  Lemma (requires (
    let r = issue claims sd_names salts in
    (* The forged disclosure is not among the issued disclosures *)
    not (mem forged r.disclosures) /\
    (* The forged encoding differs from every issued encoding *)
    (forall (d:disclosure). mem d r.disclosures ==>
      encode_disclosure forged =!= encode_disclosure d)))
  (ensures (
    let r = issue claims sd_names salts in
    (* The forged digest does not appear in sd_digests *)
    not (digest_in (digest_of forged) r.payload.sd_digests)))
let lemma_non_forgeability claims sd_names salts forged =
  (* By collision resistance: distinct encodings → distinct digests.
    Since the forged encoding differs from all issued encodings,
    its digest differs from all digests in sd_digests.
    Proof: forged_digest_not_in_build follows the recursion of
    build_disclosures, applying collision_resistant at each step. *)
  forged_digest_not_in_build claims sd_names salts forged

(* =========================================================================
  Property P3: Soundness (subset disclosure)
  =========================================================================

  Presenting a subset of disclosures reveals exactly those claims
  and no others from the SD set. *)

(** Helper: reconstruct_acc result only contains claims from plaintext, acc,
    or decoded disclosures. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
private val lemma_reconstruct_acc_provenance :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  ds:list disclosure ->
  Lemma
    (requires
      FStar.List.Tot.length encs = FStar.List.Tot.length ds /\
      encs == map encode_disclosure ds /\
      (forall (d:disclosure). mem d ds ==> mem (digest_of d) sd.sd_digests))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some result ->
        (forall (c:claim). mem c result ==>
          (mem c sd.plaintext_claims \/
            mem c acc \/
            (exists (d:disclosure).
              mem d ds /\ fst c == d.claim_name /\ snd c == d.claim_value)))
      | None -> False))
    (decreases encs)
private let rec lemma_reconstruct_acc_provenance sd encs acc ds =
  match encs, ds with
  | [], [] ->
    assert (reconstruct_acc sd [] acc == Some (sd.plaintext_claims @ acc));
    let result = sd.plaintext_claims @ acc in
    let aux (c:claim)
      : Lemma (requires mem c result)
              (ensures mem c sd.plaintext_claims \/ mem c acc \/
                (exists (d:disclosure).
                  mem d ds /\ fst c == d.claim_name /\ snd c == d.claim_value)) =
      FStar.List.Tot.Properties.append_mem sd.plaintext_claims acc c
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires aux)
  | enc :: rest_encs, d :: rest_ds ->
    assert (enc == encode_disclosure d);
    assert (mem d ds);
    assert (mem (digest_of d) sd.sd_digests);
    assert (disclosure_digest enc == digest_of d);
    assert (digest_in (disclosure_digest enc) sd.sd_digests = true);
    decode_encode_inverse d;
    assert (decode_disclosure enc == Some d);
    let new_acc = (d.claim_name, d.claim_value) :: acc in
    lemma_reconstruct_acc_provenance sd rest_encs new_acc rest_ds;
    (* Now lift the result: claims from new_acc are either from acc or from d *)
    match reconstruct_acc sd rest_encs new_acc with
    | Some result ->
      let lift (c:claim)
        : Lemma (requires mem c result)
                (ensures mem c sd.plaintext_claims \/ mem c acc \/
                  (exists (d':disclosure).
                    mem d' ds /\ fst c == d'.claim_name /\ snd c == d'.claim_value)) =
        (* From the recursive call, c is either in pt, new_acc, or from rest_ds *)
        assert (mem c sd.plaintext_claims \/ mem c new_acc \/
          (exists (d':disclosure).
            mem d' rest_ds /\ fst c == d'.claim_name /\ snd c == d'.claim_value));
        if mem c sd.plaintext_claims then ()
        else if mem c new_acc then begin
          (* c is in (d.claim_name, d.claim_value) :: acc *)
          if c = (d.claim_name, d.claim_value) then begin
            assert (fst c == d.claim_name);
            assert (snd c == d.claim_value);
            assert (mem d ds)
          end
          else
            assert (mem c acc)
        end
        else begin
          assert (
            exists (d':disclosure).
              mem d' rest_ds /\ fst c == d'.claim_name /\ snd c == d'.claim_value);
          (* rest_ds ⊆ ds *)
          assert (forall (d':disclosure). mem d' rest_ds ==> mem d' ds)
        end
      in
      FStar.Classical.forall_intro (FStar.Classical.move_requires lift)
    | None -> ()
#pop-options

(** Soundness: partial disclosure yields exactly the selected claims.
    Proved by combining reconstruct_acc_provenance (which shows every reconstructed
    claim traces back to plaintext, the accumulator, or a decoded disclosure) with
    the fact that selected disclosures are a subset of issued disclosures. *)
#push-options "--z3rlimit 200 --fuel 6 --ifuel 3"
val lemma_soundness_subset :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  selected:list disclosure ->
  Lemma (requires (
    let r = issue claims sd_names salts in
    (forall (d:disclosure). mem d selected ==> mem d r.disclosures) /\
    has_duplicates (compute_digests (map encode_disclosure selected)) = false))
  (ensures (
    let r = issue claims sd_names salts in
    let encs = map encode_disclosure selected in
    match reconstruct r.payload encs with
    | Some reconstructed ->
      (forall (c:claim). mem c reconstructed ==>
        (mem c r.payload.plaintext_claims \/
          (exists (d:disclosure).
            mem d selected /\ fst c == d.claim_name /\ snd c == d.claim_value)))
    | None -> False))
let lemma_soundness_subset claims sd_names salts selected =
  let r = issue claims sd_names salts in
  let sd = r.payload in
  let encs = map encode_disclosure selected in
  lemma_map_length encode_disclosure selected;
  assert (FStar.List.Tot.length encs = FStar.List.Tot.length selected);
  assert (encs == map encode_disclosure selected);
  (* Every selected disclosure's digest is in sd.sd_digests *)
  let sel_digest_ok (d:disclosure)
    : Lemma (requires mem d selected)
            (ensures mem (digest_of d) sd.sd_digests) =
    assert (mem d r.disclosures);
    lemma_build_disc_digest_mem claims sd_names salts d
  in
  FStar.Classical.forall_intro (FStar.Classical.move_requires sel_digest_ok);
  (* No duplicates, so reconstruct = reconstruct_acc *)
  assert (has_duplicates (compute_digests encs) = false);
  assert (reconstruct sd encs == reconstruct_acc sd encs []);
  (* Apply provenance lemma *)
  lemma_reconstruct_acc_provenance sd encs [] selected;
  (* Now lift: provenance says claims come from pt, [] (empty acc), or selected *)
  match reconstruct_acc sd encs [] with
  | Some result ->
    let empty_acc : list claim = [] in
    let lift (c:claim)
      : Lemma (requires mem c result)
              (ensures mem c sd.plaintext_claims \/
                (exists (d:disclosure).
                  mem d selected /\ fst c == d.claim_name /\ snd c == d.claim_value)) =
      (* From provenance: c is in pt, in empty acc (impossible), or from selected *)
      assert (mem c sd.plaintext_claims \/ mem c empty_acc \/
        (exists (d:disclosure). mem d selected /\ fst c == d.claim_name /\ snd c == d.claim_value));
      (* mem c [] = false, so the middle disjunct drops *)
      assert (mem c empty_acc = false)
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires lift)
  | None -> ()
#pop-options

(** Helper: if an encoded disclosure appears in a list, its digest
    appears in the computed digests of that list. *)
val lemma_digest_mem_in_compute :
  enc:string -> rest:list string ->
  Lemma (requires mem enc rest = true)
        (ensures mem (disclosure_digest enc) (compute_digests rest) = true)
  (decreases rest)
let rec lemma_digest_mem_in_compute enc rest =
  match rest with
  | [] -> ()  (* contradicts precondition *)
  | hd :: tl ->
    if hd = enc then
      (* disclosure_digest hd = disclosure_digest enc by computation;
        mem (disclosure_digest enc) (disclosure_digest hd :: compute_digests tl) = true *)
      ()
    else
      lemma_digest_mem_in_compute enc tl

(* =========================================================================
  Property P4: No-duplicate detection
  =========================================================================

  If the same disclosure is presented twice, reconstruction rejects. *)

val lemma_no_duplicate :
  sd:sd_jwt_claims -> enc:string -> rest:list string ->
  Lemma (requires mem enc rest = true)
        (ensures (
          let encs = enc :: rest in
          has_duplicates (compute_digests encs) = true \/
          reconstruct sd encs == None))
let lemma_no_duplicate sd enc rest =
  (* By lemma_digest_mem_in_compute: mem enc rest ==>
    mem (disclosure_digest enc) (compute_digests rest) = true.
    Then has_duplicates (compute_digests (enc :: rest))
      = has_duplicates (disclosure_digest enc :: compute_digests rest)
      = mem (disclosure_digest enc) (compute_digests rest) || ...
      = true || ...
      = true
    This satisfies the left disjunct. *)
  disclosure_digest_deterministic enc;
  lemma_digest_mem_in_compute enc rest

(* =========================================================================
  Property P5: Reconstruction subset
  =========================================================================

  The reconstructed claims are always a subset of the original claims
  (plaintext ∪ disclosed). No claim can appear in the output that
  was not in the issuer's original claim set. *)

(** Helper: if a disclosure digest matches one in the build_disclosures output,
    and decode_disclosure succeeds, the decoded claim is in the original claims.
    Proof: collision resistance forces enc == encode_disclosure d_i for some
    issued disclosure d_i, then the roundtrip gives d == d_i. *)
val lemma_digest_decode_claim_in_orig :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  enc:string -> d:disclosure ->
  Lemma
    (requires (
      let (_, dgs) = build_disclosures claims sd_names salts in
      mem (disclosure_digest enc) dgs = true /\
      decode_disclosure enc == Some d))
    (ensures mem (d.claim_name, d.claim_value) claims = true)
    (decreases claims)
let rec lemma_digest_decode_claim_in_orig claims sd_names salts enc d =
  match claims, salts with
  | [], _ -> ()
  | (k, v) :: tl, s :: rest_salts ->
    if mem k sd_names then begin
      let d_i = { salt = s; claim_name = k; claim_value = v } in
      let enc_i = encode_disclosure d_i in
      if enc = enc_i then
        decode_encode_inverse d_i
      else begin
        disclosure_digest_collision_resistant enc enc_i;
        lemma_digest_decode_claim_in_orig tl sd_names rest_salts enc d
      end
    end
    else
      lemma_digest_decode_claim_in_orig tl sd_names rest_salts enc d
  | _ :: _, [] -> ()

(** Helper: membership in append distributes over both sublists. *)
private let lemma_mem_append_subset (#a:eqtype)
  (xs:list a) (ys:list a) (bigger:list a)
  : Lemma
    (requires (forall (x:a). mem x xs ==> mem x bigger) /\
              (forall (y:a). mem y ys ==> mem y bigger))
    (ensures (forall (z:a). mem z (xs @ ys) ==> mem z bigger))
  = let aux (z:a) : Lemma (requires mem z (xs @ ys)) (ensures mem z bigger) =
      FStar.List.Tot.Properties.append_mem xs ys z
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires aux)

(** Helper: reconstruct_acc only produces claims from the original claim set.
    Proved by induction on encs using lemma_digest_decode_claim_in_orig
    (for the inductive case) and plaintext_subset + lemma_mem_append_subset
    (for the base case). *)
#push-options "--z3rlimit 100 --fuel 4 --ifuel 2"
val lemma_reconstruct_acc_claims :
  sd:sd_jwt_claims -> encs:list string -> acc:list claim ->
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  Lemma
    (requires (
      sd == (issue claims sd_names salts).payload /\
      (forall (c:claim). mem c acc ==> mem c claims)))
    (ensures (
      match reconstruct_acc sd encs acc with
      | Some result -> (forall (c:claim). mem c result ==> mem c claims)
      | None -> True))
    (decreases encs)
let rec lemma_reconstruct_acc_claims sd encs acc claims sd_names salts =
  match encs with
  | [] ->
    (* reconstruct_acc returns Some (sd.plaintext_claims @ acc) *)
    assert (reconstruct_acc sd [] acc == Some (sd.plaintext_claims @ acc));
    (* sd.plaintext_claims == plaintext_of claims sd_names *)
    assert (sd == (issue claims sd_names salts).payload);
    assert (sd.plaintext_claims == (plaintext_of claims sd_names));
    (* Every plaintext claim is in claims *)
    plaintext_subset claims sd_names;
    assert (forall (c:claim). mem c sd.plaintext_claims ==> mem c claims);
    (* Every acc claim is in claims (precondition) *)
    assert (forall (c:claim). mem c acc ==> mem c claims);
    (* Therefore every claim in (plaintext @ acc) is in claims *)
    lemma_mem_append_subset sd.plaintext_claims acc claims
  | enc :: rest ->
    let dg = disclosure_digest enc in
    if not (digest_in dg sd.sd_digests) then
      (* reconstruct_acc returns None *)
      ()
    else
      match decode_disclosure enc with
      | None -> ()
      | Some d ->
        (* d's claim is in claims *)
        assert (sd == (issue claims sd_names salts).payload);
        assert (sd.sd_digests == (let (_, dgs) = build_disclosures claims sd_names salts in dgs));
        assert (mem (disclosure_digest enc) sd.sd_digests = true);
        lemma_digest_decode_claim_in_orig claims sd_names salts enc d;
        assert (mem (d.claim_name, d.claim_value) claims = true);
        (* New acc satisfies precondition *)
        let new_acc = (d.claim_name, d.claim_value) :: acc in
        assert (forall (c:claim). mem c new_acc ==> mem c claims);
        (* Recurse *)
        lemma_reconstruct_acc_claims sd rest new_acc claims sd_names salts
#pop-options

val lemma_reconstruction_subset :
  claims:list claim -> sd_names:list string ->
  salts:list string{FStar.List.Tot.length salts >= FStar.List.Tot.length claims} ->
  encs:list string ->
  Lemma (ensures (
    let r = issue claims sd_names salts in
    match reconstruct r.payload encs with
    | Some reconstructed ->
      (forall (c:claim). mem c reconstructed ==>
        mem c claims \/
        mem c r.payload.plaintext_claims)
    | None -> True  (* rejection is always safe *)))
let lemma_reconstruction_subset claims sd_names salts encs =
  let r = issue claims sd_names salts in
  let presented_digests = compute_digests encs in
  if has_duplicates presented_digests then ()
  else lemma_reconstruct_acc_claims r.payload encs [] claims sd_names salts
