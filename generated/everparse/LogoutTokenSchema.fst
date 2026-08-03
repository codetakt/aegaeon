module LogoutTokenSchema
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
let def__logout_token_jwt_entry =
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
let kind__logout_token_jwt_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__len_prefixed_bytes kind__len_prefixed_bytes))

[@@ specialize; noextract_to "krml"]
noextract
let def'__logout_token_jwt_entry:typ kind__logout_token_jwt_entry
  Trivial
  Trivial
  Trivial
  false
  false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__logout_token_jwt_entry])))
    (def__logout_token_jwt_entry)

[@@ noextract_to "krml"]
noextract
let type__logout_token_jwt_entry = (as_type (def'__logout_token_jwt_entry))

[@@ noextract_to "krml"]
noextract
let parser__logout_token_jwt_entry = (as_parser (def'__logout_token_jwt_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__logout_token_jwt_entry =
  as_validator "_logout_token_jwt_entry" (def'__logout_token_jwt_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__logout_token_jwt_entry:dtyp kind__logout_token_jwt_entry
  false
  false
  Trivial
  Trivial
  Trivial =
  mk_dtyp_app kind__logout_token_jwt_entry Trivial Trivial Trivial (type__logout_token_jwt_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__logout_token_jwt_entry]];
                  T.trefl ())))
        (parser__logout_token_jwt_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__logout_token_jwt_entry;
                          `%type__logout_token_jwt_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__logout_token_jwt_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__logout_token_claims_entry =
  ((T_drop
      (T_pair "iss"
          false
          (T_with_comment "iss" (T_denoted "iss" (dtyp__len_prefixed_bytes)) "Validating field iss")
          false
          (T_pair "aud"
              false
              (T_with_comment "aud"
                  (T_denoted "aud" (dtyp__len_prefixed_bytes))
                  "Validating field aud")
              false
              (T_pair "iat"
                  true
                  (T_with_comment "iat" (T_denoted "iat" (DT_IType UInt64)) "Validating field iat")
                  false
                  (T_pair "jti"
                      false
                      (T_with_comment "jti"
                          (T_denoted "jti" (dtyp__len_prefixed_bytes))
                          "Validating field jti")
                      false
                      (T_pair "sid"
                          false
                          (T_with_comment "sid"
                              (T_denoted "sid" (dtyp__len_prefixed_bytes))
                              "Validating field sid")
                          false
                          (T_pair "sub"
                              false
                              (T_with_comment "sub"
                                  (T_denoted "sub" (dtyp__maybe_string))
                                  "Validating field sub")
                              false
                              (T_with_comment "events"
                                  (T_denoted "events" (dtyp__len_prefixed_bytes))
                                  "Validating field events"))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__logout_token_claims_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__len_prefixed_bytes
            (and_then_kind kind____UINT64
                (and_then_kind kind__len_prefixed_bytes
                    (and_then_kind kind__len_prefixed_bytes
                        (and_then_kind kind__maybe_string kind__len_prefixed_bytes))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__logout_token_claims_entry:typ kind__logout_token_claims_entry
  Trivial
  Trivial
  Trivial
  false
  false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__logout_token_claims_entry])))
    (def__logout_token_claims_entry)

[@@ noextract_to "krml"]
noextract
let type__logout_token_claims_entry = (as_type (def'__logout_token_claims_entry))

[@@ noextract_to "krml"]
noextract
let parser__logout_token_claims_entry = (as_parser (def'__logout_token_claims_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__logout_token_claims_entry =
  as_validator "_logout_token_claims_entry" (def'__logout_token_claims_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__logout_token_claims_entry:dtyp kind__logout_token_claims_entry
  false
  false
  Trivial
  Trivial
  Trivial =
  mk_dtyp_app kind__logout_token_claims_entry Trivial Trivial Trivial
    (type__logout_token_claims_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__logout_token_claims_entry]];
                  T.trefl ())))
        (parser__logout_token_claims_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__logout_token_claims_entry;
                          `%type__logout_token_claims_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__logout_token_claims_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
