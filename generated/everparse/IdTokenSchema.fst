module IdTokenSchema
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ specialize; noextract_to "krml"]
noextract
let def__len_prefixed_bytes =
  ((T_dep_pair "len"
        (DT_IType UInt32)
        (fun len ->
            (T_with_comment "bytes"
                (T_nlist "bytes" len None true (T_denoted "bytes.element" (DT_IType UInt8)))
                "Validating field bytes")))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__len_prefixed_bytes:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32 (kind_nlist kind____UINT8 None))

[@@ specialize; noextract_to "krml"]
noextract
let def'__len_prefixed_bytes:typ kind__len_prefixed_bytes Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__len_prefixed_bytes])))
    (def__len_prefixed_bytes)

[@@ noextract_to "krml"]
noextract
let type__len_prefixed_bytes = (as_type (def'__len_prefixed_bytes))

[@@ noextract_to "krml"]
noextract
let parser__len_prefixed_bytes = (as_parser (def'__len_prefixed_bytes))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__len_prefixed_bytes = as_validator "_len_prefixed_bytes" (def'__len_prefixed_bytes)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__len_prefixed_bytes:dtyp kind__len_prefixed_bytes false false Trivial Trivial Trivial =
  mk_dtyp_app kind__len_prefixed_bytes Trivial Trivial Trivial (type__len_prefixed_bytes)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__len_prefixed_bytes]];
                  T.trefl ())))
        (parser__len_prefixed_bytes)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__len_prefixed_bytes;
                          `%type__len_prefixed_bytes;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__len_prefixed_bytes))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__maybe_string =
  ((T_pair "present"
        true
        (T_with_comment "present" (T_denoted "present" (DT_IType UInt8)) "Validating field present")
        false
        (T_with_comment "value"
            (T_denoted "value" (dtyp__len_prefixed_bytes))
            "Validating field value"))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__maybe_string:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT8 kind__len_prefixed_bytes)

[@@ specialize; noextract_to "krml"]
noextract
let def'__maybe_string:typ kind__maybe_string Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__maybe_string])))
    (def__maybe_string)

[@@ noextract_to "krml"]
noextract
let type__maybe_string = (as_type (def'__maybe_string))

[@@ noextract_to "krml"]
noextract
let parser__maybe_string = (as_parser (def'__maybe_string))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__maybe_string = as_validator "_maybe_string" (def'__maybe_string)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__maybe_string:dtyp kind__maybe_string false false Trivial Trivial Trivial =
  mk_dtyp_app kind__maybe_string Trivial Trivial Trivial (type__maybe_string)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__maybe_string]];
                  T.trefl ())))
        (parser__maybe_string)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__maybe_string; `%type__maybe_string; `%coerce]];
                  T.trefl ())))
        (validate__maybe_string))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__maybe_bool =
  ((T_pair "present"
        true
        (T_with_comment "present" (T_denoted "present" (DT_IType UInt8)) "Validating field present")
        true
        (T_with_comment "value" (T_denoted "value" (DT_IType UInt8)) "Validating field value"))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__maybe_bool:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT8 kind____UINT8)

[@@ specialize; noextract_to "krml"]
noextract
let def'__maybe_bool:typ kind__maybe_bool Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__maybe_bool])))
    (def__maybe_bool)

[@@ noextract_to "krml"]
noextract
let type__maybe_bool = (as_type (def'__maybe_bool))

[@@ noextract_to "krml"]
noextract
let parser__maybe_bool = (as_parser (def'__maybe_bool))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__maybe_bool = as_validator "_maybe_bool" (def'__maybe_bool)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__maybe_bool:dtyp kind__maybe_bool false false Trivial Trivial Trivial =
  mk_dtyp_app kind__maybe_bool Trivial Trivial Trivial (type__maybe_bool)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__maybe_bool]];
                  T.trefl ())))
        (parser__maybe_bool)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__maybe_bool; `%type__maybe_bool; `%coerce]];
                  T.trefl ())))
        (validate__maybe_bool))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__maybe_timestamp =
  ((T_pair "present"
        true
        (T_with_comment "present" (T_denoted "present" (DT_IType UInt8)) "Validating field present")
        true
        (T_with_comment "value" (T_denoted "value" (DT_IType UInt64)) "Validating field value"))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__maybe_timestamp:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT8 kind____UINT64)

[@@ specialize; noextract_to "krml"]
noextract
let def'__maybe_timestamp:typ kind__maybe_timestamp Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__maybe_timestamp])))
    (def__maybe_timestamp)

[@@ noextract_to "krml"]
noextract
let type__maybe_timestamp = (as_type (def'__maybe_timestamp))

[@@ noextract_to "krml"]
noextract
let parser__maybe_timestamp = (as_parser (def'__maybe_timestamp))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__maybe_timestamp = as_validator "_maybe_timestamp" (def'__maybe_timestamp)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__maybe_timestamp:dtyp kind__maybe_timestamp false false Trivial Trivial Trivial =
  mk_dtyp_app kind__maybe_timestamp Trivial Trivial Trivial (type__maybe_timestamp)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__maybe_timestamp]];
                  T.trefl ())))
        (parser__maybe_timestamp)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__maybe_timestamp; `%type__maybe_timestamp; `%coerce]];
                  T.trefl ())))
        (validate__maybe_timestamp))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__hash_claim =
  ((T_pair "present"
        true
        (T_with_comment "present" (T_denoted "present" (DT_IType UInt8)) "Validating field present")
        false
        (T_with_comment "value"
            (T_denoted "value" (dtyp__len_prefixed_bytes))
            "Validating field value"))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__hash_claim:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT8 kind__len_prefixed_bytes)

[@@ specialize; noextract_to "krml"]
noextract
let def'__hash_claim:typ kind__hash_claim Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__hash_claim])))
    (def__hash_claim)

[@@ noextract_to "krml"]
noextract
let type__hash_claim = (as_type (def'__hash_claim))

[@@ noextract_to "krml"]
noextract
let parser__hash_claim = (as_parser (def'__hash_claim))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__hash_claim = as_validator "_hash_claim" (def'__hash_claim)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__hash_claim:dtyp kind__hash_claim false false Trivial Trivial Trivial =
  mk_dtyp_app kind__hash_claim Trivial Trivial Trivial (type__hash_claim)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__hash_claim]];
                  T.trefl ())))
        (parser__hash_claim)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__hash_claim; `%type__hash_claim; `%coerce]];
                  T.trefl ())))
        (validate__hash_claim))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__id_token_jwt_entry =
  ((T_drop
      (T_pair "header"
          false
          (T_with_comment "header"
              (T_denoted "header" (dtyp__len_prefixed_bytes))
              "Validating field header")
          false
          (T_pair "payload"
              false
              (T_with_comment "payload"
                  (T_denoted "payload" (dtyp__len_prefixed_bytes))
                  "Validating field payload")
              false
              (T_with_comment "signature"
                  (T_denoted "signature" (dtyp__len_prefixed_bytes))
                  "Validating field signature"))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__id_token_jwt_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__len_prefixed_bytes kind__len_prefixed_bytes))

[@@ specialize; noextract_to "krml"]
noextract
let def'__id_token_jwt_entry:typ kind__id_token_jwt_entry Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__id_token_jwt_entry])))
    (def__id_token_jwt_entry)

[@@ noextract_to "krml"]
noextract
let type__id_token_jwt_entry = (as_type (def'__id_token_jwt_entry))

[@@ noextract_to "krml"]
noextract
let parser__id_token_jwt_entry = (as_parser (def'__id_token_jwt_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__id_token_jwt_entry = as_validator "_id_token_jwt_entry" (def'__id_token_jwt_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__id_token_jwt_entry:dtyp kind__id_token_jwt_entry false false Trivial Trivial Trivial =
  mk_dtyp_app kind__id_token_jwt_entry Trivial Trivial Trivial (type__id_token_jwt_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__id_token_jwt_entry]];
                  T.trefl ())))
        (parser__id_token_jwt_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__id_token_jwt_entry;
                          `%type__id_token_jwt_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__id_token_jwt_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__id_token_claims_entry =
  ((T_drop
      (T_pair "iss"
          false
          (T_with_comment "iss" (T_denoted "iss" (dtyp__len_prefixed_bytes)) "Validating field iss")
          false
          (T_pair "sub"
              false
              (T_with_comment "sub"
                  (T_denoted "sub" (dtyp__len_prefixed_bytes))
                  "Validating field sub")
              false
              (T_pair "aud"
                  false
                  (T_with_comment "aud"
                      (T_denoted "aud" (dtyp__len_prefixed_bytes))
                      "Validating field aud")
                  false
                  (T_pair "exp"
                      true
                      (T_with_comment "exp"
                          (T_denoted "exp" (DT_IType UInt64))
                          "Validating field exp")
                      false
                      (T_pair "iat"
                          true
                          (T_with_comment "iat"
                              (T_denoted "iat" (DT_IType UInt64))
                              "Validating field iat")
                          false
                          (T_pair "nonce"
                              false
                              (T_with_comment "nonce"
                                  (T_denoted "nonce" (dtyp__maybe_string))
                                  "Validating field nonce")
                              false
                              (T_pair "nbf"
                                  true
                                  (T_with_comment "nbf"
                                      (T_denoted "nbf" (dtyp__maybe_timestamp))
                                      "Validating field nbf")
                                  false
                                  (T_pair "auth_time"
                                      true
                                      (T_with_comment "auth_time"
                                          (T_denoted "auth_time" (dtyp__maybe_timestamp))
                                          "Validating field auth_time")
                                      false
                                      (T_pair "azp"
                                          false
                                          (T_with_comment "azp"
                                              (T_denoted "azp" (dtyp__maybe_string))
                                              "Validating field azp")
                                          false
                                          (T_pair "acr"
                                              false
                                              (T_with_comment "acr"
                                                  (T_denoted "acr" (dtyp__maybe_string))
                                                  "Validating field acr")
                                              false
                                              (T_pair "amr"
                                                  false
                                                  (T_with_comment "amr"
                                                      (T_denoted "amr" (dtyp__len_prefixed_bytes))
                                                      " JSON-encoded AMR list")
                                                  false
                                                  (T_pair "at_hash"
                                                      false
                                                      (T_with_comment "at_hash"
                                                          (T_denoted "at_hash" (dtyp__hash_claim))
                                                          "Validating field at_hash")
                                                      false
                                                      (T_pair "c_hash"
                                                          false
                                                          (T_with_comment "c_hash"
                                                              (T_denoted "c_hash" (dtyp__hash_claim)
                                                              )
                                                              "Validating field c_hash")
                                                          false
                                                          (T_with_comment "sid"
                                                              (T_denoted "sid" (dtyp__maybe_string))
                                                              "Validating field sid")))))))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__id_token_claims_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__len_prefixed_bytes
            (and_then_kind kind__len_prefixed_bytes
                (and_then_kind kind____UINT64
                    (and_then_kind kind____UINT64
                        (and_then_kind kind__maybe_string
                            (and_then_kind kind__maybe_timestamp
                                (and_then_kind kind__maybe_timestamp
                                    (and_then_kind kind__maybe_string
                                        (and_then_kind kind__maybe_string
                                            (and_then_kind kind__len_prefixed_bytes
                                                (and_then_kind kind__hash_claim
                                                    (and_then_kind kind__hash_claim
                                                        kind__maybe_string)))))))))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__id_token_claims_entry:typ kind__id_token_claims_entry Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__id_token_claims_entry])))
    (def__id_token_claims_entry)

[@@ noextract_to "krml"]
noextract
let type__id_token_claims_entry = (as_type (def'__id_token_claims_entry))

[@@ noextract_to "krml"]
noextract
let parser__id_token_claims_entry = (as_parser (def'__id_token_claims_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__id_token_claims_entry =
  as_validator "_id_token_claims_entry" (def'__id_token_claims_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__id_token_claims_entry:dtyp kind__id_token_claims_entry false false Trivial Trivial Trivial =
  mk_dtyp_app kind__id_token_claims_entry Trivial Trivial Trivial (type__id_token_claims_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__id_token_claims_entry]];
                  T.trefl ())))
        (parser__id_token_claims_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__id_token_claims_entry;
                          `%type__id_token_claims_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__id_token_claims_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__userinfo_response_entry =
  ((T_drop
      (T_pair "sub"
          false
          (T_with_comment "sub" (T_denoted "sub" (dtyp__len_prefixed_bytes)) "Validating field sub")
          false
          (T_pair "name"
              false
              (T_with_comment "name" (T_denoted "name" (dtyp__maybe_string)) "Validating field name"
              )
              false
              (T_pair "preferred_username"
                  false
                  (T_with_comment "preferred_username"
                      (T_denoted "preferred_username" (dtyp__maybe_string))
                      "Validating field preferred_username")
                  false
                  (T_pair "email"
                      false
                      (T_with_comment "email"
                          (T_denoted "email" (dtyp__maybe_string))
                          "Validating field email")
                      false
                      (T_pair "email_verified"
                          true
                          (T_with_comment "email_verified"
                              (T_denoted "email_verified" (dtyp__maybe_bool))
                              "Validating field email_verified")
                          false
                          (T_pair "address"
                              false
                              (T_with_comment "address"
                                  (T_denoted "address" (dtyp__maybe_string))
                                  "Validating field address")
                              false
                              (T_pair "phone_number"
                                  false
                                  (T_with_comment "phone_number"
                                      (T_denoted "phone_number" (dtyp__maybe_string))
                                      "Validating field phone_number")
                                  true
                                  (T_with_comment "updated_at"
                                      (T_denoted "updated_at" (dtyp__maybe_timestamp))
                                      "Validating field updated_at")))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__userinfo_response_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__maybe_string
            (and_then_kind kind__maybe_string
                (and_then_kind kind__maybe_string
                    (and_then_kind kind__maybe_bool
                        (and_then_kind kind__maybe_string
                            (and_then_kind kind__maybe_string kind__maybe_timestamp)))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__userinfo_response_entry:typ kind__userinfo_response_entry
  Trivial
  Trivial
  Trivial
  false
  false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__userinfo_response_entry])))
    (def__userinfo_response_entry)

[@@ noextract_to "krml"]
noextract
let type__userinfo_response_entry = (as_type (def'__userinfo_response_entry))

[@@ noextract_to "krml"]
noextract
let parser__userinfo_response_entry = (as_parser (def'__userinfo_response_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__userinfo_response_entry =
  as_validator "_userinfo_response_entry" (def'__userinfo_response_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__userinfo_response_entry:dtyp kind__userinfo_response_entry
  false
  false
  Trivial
  Trivial
  Trivial =
  mk_dtyp_app kind__userinfo_response_entry Trivial Trivial Trivial (type__userinfo_response_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__userinfo_response_entry]];
                  T.trefl ())))
        (parser__userinfo_response_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__userinfo_response_entry;
                          `%type__userinfo_response_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__userinfo_response_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
