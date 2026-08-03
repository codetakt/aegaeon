module RequestObjectSchema
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
let def__request_object_claims_entry =
  ((T_drop
      (T_pair "aud"
          false
          (T_with_comment "aud" (T_denoted "aud" (dtyp__len_prefixed_bytes)) "Validating field aud")
          false
          (T_pair "exp"
              true
              (T_with_comment "exp" (T_denoted "exp" (DT_IType UInt64)) "Validating field exp")
              false
              (T_pair "nbf"
                  true
                  (T_with_comment "nbf" (T_denoted "nbf" (DT_IType UInt64)) "Validating field nbf")
                  false
                  (T_pair "client_id"
                      false
                      (T_with_comment "client_id"
                          (T_denoted "client_id" (dtyp__len_prefixed_bytes))
                          "Validating field client_id")
                      false
                      (T_pair "redirect_uri"
                          false
                          (T_with_comment "redirect_uri"
                              (T_denoted "redirect_uri" (dtyp__len_prefixed_bytes))
                              "Validating field redirect_uri")
                          false
                          (T_pair "response_type"
                              false
                              (T_with_comment "response_type"
                                  (T_denoted "response_type" (dtyp__len_prefixed_bytes))
                                  "Validating field response_type")
                              false
                              (T_pair "scope"
                                  false
                                  (T_with_comment "scope"
                                      (T_denoted "scope" (dtyp__len_prefixed_bytes))
                                      "Validating field scope")
                                  false
                                  (T_pair "state"
                                      false
                                      (T_with_comment "state"
                                          (T_denoted "state" (dtyp__maybe_string))
                                          "Validating field state")
                                      false
                                      (T_pair "nonce"
                                          false
                                          (T_with_comment "nonce"
                                              (T_denoted "nonce" (dtyp__maybe_string))
                                              "Validating field nonce")
                                          false
                                          (T_pair "code_challenge"
                                              false
                                              (T_with_comment "code_challenge"
                                                  (T_denoted "code_challenge"
                                                      (dtyp__len_prefixed_bytes))
                                                  "Validating field code_challenge")
                                              false
                                              (T_pair "code_challenge_method"
                                                  false
                                                  (T_with_comment "code_challenge_method"
                                                      (T_denoted "code_challenge_method"
                                                          (dtyp__len_prefixed_bytes))
                                                      "Validating field code_challenge_method")
                                                  false
                                                  (T_pair "response_mode"
                                                      false
                                                      (T_with_comment "response_mode"
                                                          (T_denoted "response_mode"
                                                              (dtyp__maybe_string))
                                                          "Validating field response_mode")
                                                      false
                                                      (T_with_comment "jti"
                                                          (T_denoted "jti"
                                                              (dtyp__len_prefixed_bytes))
                                                          "Validating field jti"))))))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__request_object_claims_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind____UINT64
            (and_then_kind kind____UINT64
                (and_then_kind kind__len_prefixed_bytes
                    (and_then_kind kind__len_prefixed_bytes
                        (and_then_kind kind__len_prefixed_bytes
                            (and_then_kind kind__len_prefixed_bytes
                                (and_then_kind kind__maybe_string
                                    (and_then_kind kind__maybe_string
                                        (and_then_kind kind__len_prefixed_bytes
                                            (and_then_kind kind__len_prefixed_bytes
                                                (and_then_kind kind__maybe_string
                                                    kind__len_prefixed_bytes))))))))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__request_object_claims_entry:typ kind__request_object_claims_entry
  Trivial
  Trivial
  Trivial
  false
  false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__request_object_claims_entry])))
    (def__request_object_claims_entry)

[@@ noextract_to "krml"]
noextract
let type__request_object_claims_entry = (as_type (def'__request_object_claims_entry))

[@@ noextract_to "krml"]
noextract
let parser__request_object_claims_entry = (as_parser (def'__request_object_claims_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__request_object_claims_entry =
  as_validator "_request_object_claims_entry" (def'__request_object_claims_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__request_object_claims_entry:dtyp kind__request_object_claims_entry
  false
  false
  Trivial
  Trivial
  Trivial =
  mk_dtyp_app kind__request_object_claims_entry Trivial Trivial Trivial
    (type__request_object_claims_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__request_object_claims_entry]];
                  T.trefl ())))
        (parser__request_object_claims_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__request_object_claims_entry;
                          `%type__request_object_claims_entry;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__request_object_claims_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
