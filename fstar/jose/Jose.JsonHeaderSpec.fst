module Jose.JsonHeaderSpec

open FStar.List.Tot
open FStar.String
open LowStar.Buffer
open Jose.StringLemmas
open Jose.Utf8Lemmas
open Jose.HeaderKeyLemmas
open FStar.Json
open EqHelpers
module HM = Jose.HeaderMicro
module HS = Jose.HeaderSpec
module Policy = Jose.HeaderPolicy

module List = FStar.List.Tot

type json_value =
  | JsonString: string -> json_value
  | JsonNull: json_value

type json_member = {
  key: string;
  value: json_value
}

let json_of_value (v:json_value) : json =
  match v with
  | JsonString s -> String s
  | JsonNull -> Null

let member_to_json (m:json_member) : string * json =
  (m.key, json_of_value m.value)

let rec members_to_json (members:list json_member) : list (string * json) =
  match members with
  | [] -> []
  | m::rest -> member_to_json m :: members_to_json rest

let eq_string_fields_to_json_cons
  (k:string)
  (v:string)
  (entries:list (string * string))
  : Lemma (ensures HM.string_fields_to_json ((k, v) :: entries) ==
                    (k, String v) :: HM.string_fields_to_json entries)
  = ()

let eq_members_to_json_cons
  (m:json_member)
  (rest:list json_member)
  : Lemma (ensures members_to_json (m :: rest) ==
                    member_to_json m :: members_to_json rest)
  = ()

let string_fields_to_json_prop_to_eq
  (entries1:list (string * string))
  (entries2:list (string * string))
  : Lemma (requires entries1 = entries2)
          (ensures HM.string_fields_to_json entries1 == HM.string_fields_to_json entries2)
  = ()

let members_to_json_prop_to_eq
  (members1:list json_member)
  (members2:list json_member)
  (pf:members1 = members2)
  : Lemma (ensures members_to_json members1 == members_to_json members2)
  =
    match pf with
    | () -> ()

let eq_parse_jwe_sanitized_congruent
  (fields1:list (string * json))
  (fields2:list (string * json))
  : Lemma (requires fields1 == fields2)
          (ensures HS.parse_jwe_sanitized fields1 == HS.parse_jwe_sanitized fields2)
  = ()

let eq_parse_jws_sanitized_congruent
  (fields1:list (string * json))
  (fields2:list (string * json))
  : Lemma (requires fields1 == fields2)
          (ensures HS.parse_jws_sanitized fields1 == HS.parse_jws_sanitized fields2)
  = ()

let allow_list : list string = Policy.allow_list

let duplicate_key_msg : string = Policy.duplicate_key_msg
let invalid_type_msg : string = Policy.invalid_type_msg
let critical_extension_msg : string = Policy.critical_extension_msg

let key_allowed (k:string) : bool = Policy.key_allowed k

let forbids_extension (k:string) : bool = Policy.forbids_extension k

let json_member_allowed (m:json_member) : Tot bool =
  key_allowed m.key &&
  (match m.value with
   | JsonString _ -> (m.key <> "crit" && m.key <> "zip")
   | JsonNull -> false)

let rec keys_of_members (members:list json_member) : list string =
  match members with
  | [] -> []
  | m::rest -> m.key :: keys_of_members rest

let eq_keys_of_members_nil ()
  : Lemma (ensures keys_of_members [] == [])
  = ()

let eq_keys_of_members_cons
  (m:json_member)
  (rest:list json_member)
  : Lemma (ensures keys_of_members (m :: rest) == m.key :: keys_of_members rest)
  = ()

let rewrite_keys_members_cons
  (m:json_member)
  (rest:list json_member)
  : Lemma (ensures keys_of_members (m :: rest) == m.key :: keys_of_members rest)
  = eq_keys_of_members_cons m rest

let lemma_keys_of_members_eq_to_prop
  (rest:list json_member)
  (keys:list string)
  (pf:keys_of_members rest == keys)
  : Lemma (keys_of_members rest = keys)
  =
    match pf with
    | _ -> ()

let lemma_keys_eq_prop
  (tail_entries:list (string * string))
  (rest:list json_member)
  (pf:keys_of_entries tail_entries == keys_of_members rest)
  : Lemma (keys_of_entries tail_entries = keys_of_members rest)
  =
    match pf with
    | _ -> ()


let lemma_keys_of_members_nil ()
  : Lemma (keys_of_members [] == [])
  = ()

let lemma_keys_of_members_cons_eq
  (m:json_member)
  (rest:list json_member)
  : Lemma (keys_of_members (m :: rest) == m.key :: keys_of_members rest)
  = ()

type json_string_map = list (string * string)

let valid_header_pairs (entries:json_string_map) : Tot bool =
  no_duplicate_keys (keys_of_entries entries) &&
  List.for_all key_allowed (keys_of_entries entries)

type json_error =
  | JsonInvalidType: string -> json_error
  | JsonDuplicateKey: string -> json_error
  | JsonUnsupportedKey: string -> json_error
  | JsonCriticalExtension: string -> json_error

let lemma_valid_pairs_components
  (entries:list (string * string))
  : Lemma
      (requires valid_header_pairs entries)
      (ensures no_duplicate_keys (keys_of_entries entries) /\
               List.for_all key_allowed (keys_of_entries entries))
  = ()

let lemma_keys_of_members_cons
  (m:json_member)
  (rest:list json_member)
  : Lemma (keys_of_members (m :: rest) = m.key :: keys_of_members rest)
  = ()

let lemma_forall_key_allowed_cons
  (k:string)
  (ks:list string)
  : Lemma
      (requires key_allowed k /\ List.for_all key_allowed ks)
      (ensures List.for_all key_allowed (k :: ks))
  = ()

let lemma_not_in_when_eq
  (k:string)
  (xs:list string)
  (ys:list string)
  : Lemma
      (requires xs = ys /\ not (string_in_list k xs))
      (ensures not (string_in_list k ys))
  = ()

let rec json_object_canonical (members:list json_member) : Tot bool =
  match members with
  | [] -> true
  | m::rest ->
      json_member_allowed m &&
      not (string_in_list m.key (keys_of_members rest)) &&
      json_object_canonical rest

let rec normalize_json_members
  (members:list json_member)
  : Pure (jlresult (list (string * string)) json_error)
    (requires True)
    (ensures (fun res ->
      match res with
      | Ok entries ->
          keys_of_entries entries = keys_of_members members /\
          valid_header_pairs entries
      | Error _ -> True))
    (decreases members)
  =
    match members with
    | [] -> Ok []
    | m::rest ->
        if not (key_allowed m.key) then Error (JsonUnsupportedKey m.key)
        else if string_in_list m.key (keys_of_members rest) then Error (JsonDuplicateKey m.key)
        else
          match m.value with
          | JsonNull -> Error (JsonInvalidType m.key)
          | JsonString v ->
              if m.key = "crit" || m.key = "zip" then Error (JsonCriticalExtension m.key)
              else
                match normalize_json_members rest with
                | Ok tail ->
                    assert (keys_of_entries tail = keys_of_members rest);
                    assert (valid_header_pairs tail);
                    lemma_valid_pairs_components tail;
                    lemma_not_in_when_eq m.key (keys_of_members rest) (keys_of_entries tail);
                    let _ = assert (key_allowed m.key) in
                    lemma_forall_key_allowed_cons m.key (keys_of_entries tail);
                    lemma_no_duplicate_cons m.key (keys_of_entries tail);
                    lemma_keys_of_entries_cons tail m.key v;
                    lemma_keys_of_members_cons m rest;
                    assert (keys_of_entries ((m.key, v) :: tail) = m.key :: keys_of_entries tail);
                    assert (keys_of_members (m :: rest) = m.key :: keys_of_members rest);
                    assert (keys_of_entries ((m.key, v) :: tail) = keys_of_members (m :: rest));
                    assert (no_duplicate_keys (keys_of_entries ((m.key, v) :: tail)));
                    assert (List.for_all key_allowed (keys_of_entries ((m.key, v) :: tail)));
                    assert (valid_header_pairs ((m.key, v) :: tail));
                    Ok ((m.key, v) :: tail)
                | Error e -> Error e

let lemma_normalize_json_members_error_immediate
  (m:json_member)
  (rest:list json_member)
  : Lemma
      (ensures
        (let res = normalize_json_members (m :: rest) in
         let base_guards =
           (not (key_allowed m.key) ==> res = Error (JsonUnsupportedKey m.key)) /\
           (key_allowed m.key /\ string_in_list m.key (keys_of_members rest)
              ==> res = Error (JsonDuplicateKey m.key))
         in
         base_guards /\
         (
           key_allowed m.key /\ not (string_in_list m.key (keys_of_members rest))
           ==> (
             match m.value with
             | JsonNull -> res = Error (JsonInvalidType m.key)
             | JsonString v ->
                 (m.key = "crit" || m.key = "zip")
                 ==> res = Error (JsonCriticalExtension m.key)
           )
         )
        ))
  =
    let res = normalize_json_members (m :: rest) in
    if not (key_allowed m.key) then
      assert_norm (res = Error (JsonUnsupportedKey m.key))
    else if string_in_list m.key (keys_of_members rest) then
      assert_norm (res = Error (JsonDuplicateKey m.key))
    else
      match m.value with
      | JsonNull ->
          assert_norm (res = Error (JsonInvalidType m.key))
      | JsonString v ->
          if m.key = "crit" || m.key = "zip" then
            assert_norm (res = Error (JsonCriticalExtension m.key))
          else
            ();
    ()

noextract
let false_elim (#a:Type0) (pf:False) : Tot a =
  match pf with

// Proof that Ok and Error are distinct constructors
// Requires eqtype to pattern match on propositional equality
let result_ok_error_absurd
  (#a:eqtype)
  (#e:eqtype)
  (x:a)
  (err:e)
  (pf:Ok #a #e x = Error #a #e err)
  : False
  =
  ()

// Proof of constructor injectivity: Ok x = Ok y implies x = y
// Requires eqtype to pattern match on propositional equality
let result_ok_eq
  (#a:eqtype)
  (#e:eqtype)
  (x:a)
  (y:a)
  (pf:Ok #a #e x = Ok #a #e y)
  : Lemma (ensures x = y)
  =
  ()

let lemma_nil_cons_absurd
  (#a:eqtype)
  (x:a)
  (xs:list a)
  : Lemma (requires [] = x :: xs) (ensures False)
  =
    ()

let lemma_keys_eq_empty_impossible
  (m:json_member)
  (rest:list json_member)
  : Lemma
      (requires keys_of_entries [] = keys_of_members (m :: rest))
      (ensures False)
  =
    assert (keys_of_entries [] = []);
    assert (keys_of_members (m :: rest) = m.key :: keys_of_members rest);
    lemma_nil_cons_absurd m.key (keys_of_members rest)

let cons_eq_head_tail
  (#a:eqtype)
  (hd1:a)
  (tl1:list a)
  (hd2:a)
  (tl2:list a)
  : Lemma (requires hd1 :: tl1 = hd2 :: tl2) (ensures hd1 = hd2 /\ tl1 = tl2)
  =
    ()

let lemma_keys_heads_prop
  (k:string)
  (v:string)
  (tail:list (string * string))
  (m:json_member)
  (rest:list json_member)
  : Lemma
      (requires keys_of_entries ((k, v) :: tail) = keys_of_members (m :: rest))
      (ensures k = m.key /\ keys_of_entries tail = keys_of_members rest)
  =
    cons_eq_head_tail k (keys_of_entries tail) m.key (keys_of_members rest)

let lemma_keys_eq_heads_bridge
  (k:string)
  (v:string)
  (tail:list (string * string))
  (m:json_member)
  (rest:list json_member)
  (pf:keys_of_entries ((k, v) :: tail) == keys_of_members (m :: rest))
  : Lemma (k = m.key /\ keys_of_entries tail = keys_of_members rest)
  =
    keys_of_entries_eq_to_prop ((k, v) :: tail) (keys_of_members (m :: rest)) pf;
    lemma_keys_heads_prop k v tail m rest

let lemma_keys_eq_cons_heads
  (k:string)
  (v:string)
  (tail:list (string * string))
  (m:json_member)
  (rest:list json_member)
  (pf:keys_of_entries ((k, v) :: tail) == keys_of_members (m :: rest))
  : Lemma (k = m.key /\ keys_of_entries tail = keys_of_members rest)
  =
    lemma_keys_eq_heads_bridge k v tail m rest pf

let lemma_normalize_json_members_guard_ok
  (m:json_member)
  (rest:list json_member)
  (v:string)
  (tail:list (string * string))
  : Lemma
      (requires normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail))
      (ensures
        key_allowed m.key = true /\
        not (string_in_list m.key (keys_of_members rest)) /\
        m.value = JsonString v /\
        m.key <> "crit" /\
        m.key <> "zip" /\
        normalize_json_members rest = Ok tail)
  =
    lemma_normalize_json_members_error_immediate m rest;
    let key_guard = key_allowed m.key in
    (match key_guard with
     | true -> ()
     | false ->
         (* If key_guard = false, then normalize_json_members (m :: rest) = Error (JsonUnsupportedKey m.key)
            But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
            F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
         ());
    let _ = assert (key_allowed m.key = true) in
    let duplicate_guard = string_in_list m.key (keys_of_members rest) in
    (match duplicate_guard with
     | true ->
         (* If duplicate_guard = true, then normalize_json_members (m :: rest) = Error (JsonDuplicateKey m.key)
            But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
            F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
         ()
     | false -> ());
    let _ = assert (duplicate_guard = false) in
    let _ = assert (not duplicate_guard) in
    let _ = assert (not (string_in_list m.key (keys_of_members rest))) in
    (match m.value with
     | JsonNull ->
         (* If m.value = JsonNull, then normalize_json_members (m :: rest) = Error (JsonInvalidType m.key)
            But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
            F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
         ()
     | JsonString v' ->
         let crit_guard = m.key = "crit" in
         (match crit_guard with
          | true ->
              (* If crit_guard = true, then normalize_json_members (m :: rest) = Error (JsonCriticalExtension m.key)
                 But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
                 F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
              ()
          | false -> ());
         let _ = assert (crit_guard = false) in
         let _ = assert (m.key <> "crit") in
         let zip_guard = m.key = "zip" in
         (match zip_guard with
          | true ->
              (* If zip_guard = true, then normalize_json_members (m :: rest) = Error (JsonCriticalExtension m.key)
                 But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
                 F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
              ()
          | false -> ());
         let _ = assert (zip_guard = false) in
         let _ = assert (m.key <> "zip") in
         let rec_res = normalize_json_members rest in
         (match rec_res with
          | Ok tail' ->
              (* From normalize_json_members definition:
                 When all guards pass and m.value = JsonString v', the result is Ok ((m.key, v') :: tail')
                 By requires clause: normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
                 F* will automatically infer: v' = v and tail' = tail *)
              ()
          | Error e ->
              (* If normalize_json_members rest = Error e, then normalize_json_members (m :: rest) = Error e
                 But requires clause says normalize_json_members (m :: rest) = Ok ((m.key, v) :: tail)
                 F* recognizes Ok ≠ Error automatically, so this branch is unreachable *)
              ());
         ())

let decompose_entries_from_keys
  (entries:list (string * string))
  (m:json_member)
  (rest:list json_member)
  (keys_eq:keys_of_entries entries == keys_of_members (m :: rest))
  : Pure (string * list (string * string))
    (requires True)
    (ensures (fun res ->
      let (value, tail_entries) = res in
      entries = (m.key, value) :: tail_entries /\
      keys_of_entries tail_entries = keys_of_members rest))
  =
    match entries with
    | [] ->
        keys_of_entries_eq_to_prop [] (keys_of_members (m :: rest)) keys_eq;
        lemma_keys_eq_empty_impossible m rest;
        false_elim ()
    | (k, v) :: tail ->
        lemma_keys_eq_cons_heads k v tail m rest keys_eq;
        assert (k = m.key);
        assert (keys_of_entries tail = keys_of_members rest);
        assert (entries = (m.key, v) :: tail);
        (v, tail)

let lemma_normalize_json_members_success_inv
  (m:json_member)
  (rest:list json_member)
  (entries:list (string * string))
  : Pure (string * list (string * string))
    (requires normalize_json_members (m :: rest) = Ok entries)
    (ensures (fun res ->
      let (value, tail_entries) = res in
      entries = (m.key, value) :: tail_entries /\
      key_allowed m.key = true /\
      not (string_in_list m.key (keys_of_members rest)) /\
      m.value = JsonString value /\
      m.key <> "crit" /\
      m.key <> "zip" /\
      normalize_json_members rest = Ok tail_entries /\
      keys_of_entries tail_entries = keys_of_members rest))
  =
    (* From the requires clause, we know: normalize_json_members (m :: rest) = Ok entries *)
    assert (normalize_json_members (m :: rest) = Ok entries);
    (* Inline expand decompose_entries_from_keys to avoid needing decidable equality proof *)
    match entries with
    | [] ->
        (* If entries = [], but normalize_json_members (m :: rest) = Ok entries
           Then keys_of_entries entries = keys_of_members (m :: rest) = []
           But keys_of_members (m :: rest) cannot be empty, so this is impossible *)
        assert (keys_of_entries entries = keys_of_members (m :: rest));
        assert (keys_of_entries [] = []);
        assert (keys_of_members (m :: rest) = m.key :: keys_of_members rest);
        (* keys_of_entries [] = [] != m.key :: keys_of_members rest, which is a contradiction *)
        false_elim ()
    | (k, v) :: tail ->
        (* entries = (k, v) :: tail
           From normalize_json_members (m :: rest) = Ok entries = Ok ((k, v) :: tail),
           we can derive that k = m.key and tail corresponds to rest *)
        assert (entries = (k, v) :: tail);
        assert (normalize_json_members (m :: rest) = Ok ((k, v) :: tail));
        lemma_normalize_json_members_guard_ok m rest v tail;
        assert (k = m.key);
        assert (keys_of_entries tail = keys_of_members rest);
        (v, tail)

let rec lemma_members_to_json_success
  (members:list json_member)
  (entries:list (string * string))
  : Lemma
    (requires normalize_json_members members = Ok entries)
    (ensures HM.string_fields_to_json entries == members_to_json members)
    (decreases members)
  =
    match members with
    | [] ->
        (* By definition: normalize_json_members [] = Ok []
           From precondition: normalize_json_members [] = Ok entries
           By constructor injectivity: entries = []
           Therefore: HM.string_fields_to_json [] == members_to_json [] == [] *)
        ()
    | m::rest ->
        let decomposition =
          lemma_normalize_json_members_success_inv m rest entries
        in
        let value = fst decomposition in
        let tail = snd decomposition in
        (* From lemma_normalize_json_members_success_inv postcondition,
           F* knows: entries = (m.key, value) :: tail *)
        (* Establish all the intermediate equalities through lemma calls *)
        lemma_members_to_json_success rest tail;
        string_fields_to_json_prop_to_eq entries ((m.key, value) :: tail);
        eq_string_fields_to_json_cons m.key value tail;
        eq_cons_preserve (m.key, String value)
          (HM.string_fields_to_json tail)
          (members_to_json rest);

        (* From lemma_normalize_json_members_success_inv postcondition,
           F* knows: m.value = JsonString value
           This gives us json_of_value m.value == String value *)
        eq_pair_second m.key (json_of_value m.value) (String value);
        eq_cons_head_change (m.key, String value)
          (m.key, json_of_value m.value)
          (members_to_json rest);
        eq_members_to_json_cons m rest;
        eq_sym #(list (string * json))
          (member_to_json m :: members_to_json rest)
          (members_to_json (m :: rest));

        (* Chain the equalities using transitivity *)
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          (HM.string_fields_to_json ((m.key, value) :: tail))
          ((m.key, String value) :: HM.string_fields_to_json tail);
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          ((m.key, String value) :: HM.string_fields_to_json tail)
          ((m.key, String value) :: members_to_json rest);
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          ((m.key, String value) :: members_to_json rest)
          ((m.key, json_of_value m.value) :: members_to_json rest);
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          ((m.key, json_of_value m.value) :: members_to_json rest)
          (members_to_json (m :: rest))
let json_error_to_decode_error (err:json_error) : decode_error =
  match err with
  | JsonInvalidType _ -> PolicyViolation invalid_type_msg
  | JsonDuplicateKey _ -> PolicyViolation duplicate_key_msg
  | JsonUnsupportedKey key -> UnknownKey key
  | JsonCriticalExtension _ -> PolicyViolation critical_extension_msg

let lemma_json_error_to_decode_error_duplicate (k:string) : Lemma
  (ensures json_error_to_decode_error (JsonDuplicateKey k) = PolicyViolation duplicate_key_msg)
  = ()

let lemma_json_error_to_decode_error_invalid (k:string) : Lemma
  (ensures json_error_to_decode_error (JsonInvalidType k) = PolicyViolation invalid_type_msg)
  = ()

let lemma_json_error_to_decode_error_critical (k:string) : Lemma
  (ensures json_error_to_decode_error (JsonCriticalExtension k) = PolicyViolation critical_extension_msg)
  = ()

let lemma_json_error_to_decode_error_unsupported (k:string) : Lemma
  (ensures json_error_to_decode_error (JsonUnsupportedKey k) = UnknownKey k)
  = ()

let parse_json_pairs_result
  (members:list json_member)
  : decode_result (list (string * string))
  =
    match normalize_json_members members with
    | Ok entries -> Ok entries
    | Error err -> Error (json_error_to_decode_error err)

let lemma_parse_json_pairs_result_jwe
  (members:list json_member)
  (entries:list (string * string))
  (pf:parse_json_pairs_result members = Ok entries)
  : Lemma (HM.parse_jwe_micro entries = HS.parse_jwe_sanitized (members_to_json members))
  =
    match normalize_json_members members with
    | Ok entries' ->
        (* From pf and the match, F* knows that entries = entries' *)
        let _ = assert (normalize_json_members members = Ok entries') in

        (* Establish the equalities through lemma calls *)
        string_fields_to_json_prop_to_eq entries entries';
        lemma_members_to_json_success members entries';

        (* Chain the equalities using eq_trans *)
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          (HM.string_fields_to_json entries')
          (members_to_json members);

        (* Apply congruence for parse_jwe_sanitized *)
        eq_parse_jwe_sanitized_congruent
          (HM.string_fields_to_json entries)
          (members_to_json members);

        (* Convert from == to = and apply transitivity *)
        eq_to_prop #(option HS.sanitized_jwe)
          (HS.parse_jwe_sanitized (HM.string_fields_to_json entries))
          (HS.parse_jwe_sanitized (members_to_json members));

        eq_trans_prop #(option HS.sanitized_jwe)
          (HM.parse_jwe_micro entries)
          (HS.parse_jwe_sanitized (HM.string_fields_to_json entries))
          (HS.parse_jwe_sanitized (members_to_json members))
    | Error err' ->
        let parse_pf : (parse_json_pairs_result members = Error (json_error_to_decode_error err')) = () in
        let eq_conflict : (Ok entries = Error (json_error_to_decode_error err')) =
          match parse_pf with
          | () ->
              match pf with
              | () -> ()
        in
        false_elim (result_ok_error_absurd entries (json_error_to_decode_error err') eq_conflict)

let lemma_parse_json_pairs_result_jws
  (members:list json_member)
  (entries:list (string * string))
  (pf:parse_json_pairs_result members = Ok entries)
  : Lemma (HM.parse_jws_micro entries = HS.parse_jws_sanitized (members_to_json members))
  =
    match normalize_json_members members with
    | Ok entries' ->
        (* From pf and the match, F* knows that entries = entries' *)
        let _ = assert (normalize_json_members members = Ok entries') in

        (* Establish the equalities through lemma calls *)
        string_fields_to_json_prop_to_eq entries entries';
        lemma_members_to_json_success members entries';

        (* Chain the equalities using eq_trans *)
        eq_trans #(list (string * json))
          (HM.string_fields_to_json entries)
          (HM.string_fields_to_json entries')
          (members_to_json members);

        (* Apply congruence for parse_jws_sanitized *)
        eq_parse_jws_sanitized_congruent
          (HM.string_fields_to_json entries)
          (members_to_json members);

        (* Convert from == to = and apply transitivity *)
        eq_to_prop #(option HS.sanitized_jws)
          (HS.parse_jws_sanitized (HM.string_fields_to_json entries))
          (HS.parse_jws_sanitized (members_to_json members));

        eq_trans_prop #(option HS.sanitized_jws)
          (HM.parse_jws_micro entries)
          (HS.parse_jws_sanitized (HM.string_fields_to_json entries))
          (HS.parse_jws_sanitized (members_to_json members))
    | Error err' ->
        let parse_pf : (parse_json_pairs_result members = Error (json_error_to_decode_error err')) = () in
        let eq_conflict : (Ok entries = Error (json_error_to_decode_error err')) =
          match parse_pf with
          | () ->
              match pf with
              | () -> ()
        in
        false_elim (result_ok_error_absurd entries (json_error_to_decode_error err') eq_conflict)

let lemma_parse_results_equiv_success
  (members:list json_member)
  (entries:list (string * string))
  : Lemma
      (requires parse_json_pairs_result members = Ok entries)
      (ensures keys_of_entries entries = keys_of_members members /\
               no_duplicate_keys (keys_of_entries entries) /\
               List.for_all key_allowed (keys_of_entries entries) = true)
  =
    match normalize_json_members members with
    | Ok entries' ->
        assert (parse_json_pairs_result members = Ok entries');
        assert (parse_json_pairs_result members = Ok entries);
        (match parse_json_pairs_result members with
         | Ok entries'' ->
             assert (entries'' = entries');
             assert (entries'' = entries);
             assert (entries = entries');
             ()
         | Error _ -> ());
        lemma_valid_pairs_components entries';
        assert (keys_of_entries entries' = keys_of_members members);
        assert (keys_of_entries entries = keys_of_members members);
        assert (no_duplicate_keys (keys_of_entries entries'));
        assert (List.for_all key_allowed (keys_of_entries entries') = true);
        assert (no_duplicate_keys (keys_of_entries entries));
        assert (List.for_all key_allowed (keys_of_entries entries) = true);
        ()
    | Error _ -> ()

let lemma_parse_results_equiv_error
  (members:list json_member)
  (err:json_error)
  : Lemma
      (requires parse_json_pairs_result members = Error (json_error_to_decode_error err))
      (ensures True)
  =
    match normalize_json_members members with
    | Ok _ -> ()
    | Error err' ->
        assert (parse_json_pairs_result members = Error (json_error_to_decode_error err'));
        ()
