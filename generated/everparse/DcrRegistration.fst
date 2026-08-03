module DcrRegistration
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ specialize; noextract_to "krml"]
noextract
let def__dcr_registration_payload =
  ((T_drop
      (T_dep_pair "redirect_uris_length"
          (DT_IType UInt32)
          (fun redirect_uris_length ->
              (T_pair "redirect_uris"
                  false
                  (T_with_comment "redirect_uris"
                      (T_nlist "redirect_uris"
                          redirect_uris_length
                          None
                          true
                          (T_denoted "redirect_uris.element" (DT_IType UInt8)))
                      " Optional: token_endpoint_auth_method (enum)")
                  false
                  (T_pair "has_token_endpoint_auth_method"
                      true
                      (T_with_comment "has_token_endpoint_auth_method"
                          (T_denoted "has_token_endpoint_auth_method" (DT_IType UInt8))
                          "Validating field has_token_endpoint_auth_method")
                      false
                      (T_pair "token_endpoint_auth_method"
                          true
                          (T_with_comment "token_endpoint_auth_method"
                              (T_denoted "token_endpoint_auth_method" (DT_IType UInt32))
                              " PKCE declaration (required)")
                          false
                          (T_pair "requires_pkce"
                              true
                              (T_with_comment "requires_pkce"
                                  (T_denoted "requires_pkce" (DT_IType UInt8))
                                  " Optional: sender-constrained token requirement")
                              false
                              (T_pair "has_require_sender_constrained_tokens"
                                  true
                                  (T_with_comment "has_require_sender_constrained_tokens"
                                      (T_denoted "has_require_sender_constrained_tokens"
                                          (DT_IType UInt8))
                                      "Validating field has_require_sender_constrained_tokens")
                                  false
                                  (T_pair "require_sender_constrained_tokens"
                                      true
                                      (T_with_comment "require_sender_constrained_tokens"
                                          (T_denoted "require_sender_constrained_tokens"
                                              (DT_IType UInt8))
                                          " Optional: allowed sender constraint methods (canonical bytes)"
                                      )
                                      false
                                      (T_pair "has_sender_constrained_methods"
                                          true
                                          (T_with_comment "has_sender_constrained_methods"
                                              (T_denoted "has_sender_constrained_methods"
                                                  (DT_IType UInt8))
                                              "Validating field has_sender_constrained_methods")
                                          false
                                          (T_dep_pair "sender_constrained_methods_length"
                                              (DT_IType UInt32)
                                              (fun sender_constrained_methods_length ->
                                                  (T_pair "sender_constrained_methods"
                                                      false
                                                      (T_with_comment "sender_constrained_methods"
                                                          (T_nlist "sender_constrained_methods"
                                                              sender_constrained_methods_length
                                                              None
                                                              true
                                                              (T_denoted
                                                                  "sender_constrained_methods.element"
                                                                  (DT_IType UInt8)))
                                                          " Optional: DPoP requirement flag")
                                                      false
                                                      (T_pair "has_require_dpop"
                                                          true
                                                          (T_with_comment "has_require_dpop"
                                                              (T_denoted "has_require_dpop"
                                                                  (DT_IType UInt8))
                                                              "Validating field has_require_dpop")
                                                          false
                                                          (T_pair "require_dpop"
                                                              true
                                                              (T_with_comment "require_dpop"
                                                                  (T_denoted "require_dpop"
                                                                      (DT_IType UInt8))
                                                                  " Optional: mTLS requirement flag"
                                                              )
                                                              false
                                                              (T_pair "has_require_mtls"
                                                                  true
                                                                  (T_with_comment "has_require_mtls"
                                                                      (T_denoted "has_require_mtls"
                                                                          (DT_IType UInt8))
                                                                      "Validating field has_require_mtls"
                                                                  )
                                                                  false
                                                                  (T_pair "require_mtls"
                                                                      true
                                                                      (T_with_comment "require_mtls"
                                                                          (T_denoted "require_mtls"
                                                                              (DT_IType UInt8))
                                                                          " Optional: client display name"
                                                                      )
                                                                      false
                                                                      (T_pair "has_client_name"
                                                                          true
                                                                          (T_with_comment
                                                                              "has_client_name"
                                                                              (T_denoted
                                                                                  "has_client_name"
                                                                                  (DT_IType UInt8))
                                                                              "Validating field has_client_name"
                                                                          )
                                                                          false
                                                                          (T_dep_pair
                                                                              "client_name_length"
                                                                              (DT_IType UInt32)
                                                                              (fun
                                                                                  client_name_length
                                                                                  ->
                                                                                  (T_pair
                                                                                      "client_name"
                                                                                      false
                                                                                      (T_with_comment
                                                                                          "client_name"
                                                                                          (T_nlist
                                                                                              "client_name"
                                                                                              client_name_length
                                                                                              None
                                                                                              true
                                                                                              (T_denoted
                                                                                                  "client_name.element"
                                                                                                  (DT_IType
                                                                                                    UInt8
                                                                                                  ))
                                                                                          )
                                                                                          " Optional: software_id"
                                                                                      )
                                                                                      false
                                                                                      (T_pair
                                                                                          "has_software_id"
                                                                                          true
                                                                                          (T_with_comment
                                                                                              "has_software_id"
                                                                                              (T_denoted
                                                                                                  "has_software_id"
                                                                                                  (DT_IType
                                                                                                    UInt8
                                                                                                  ))
                                                                                              "Validating field has_software_id"
                                                                                          )
                                                                                          false
                                                                                          (T_dep_pair
                                                                                              "software_id_length"
                                                                                              (DT_IType
                                                                                                UInt32
                                                                                              )
                                                                                              (fun
                                                                                                  software_id_length
                                                                                                  ->
                                                                                                  (T_with_comment
                                                                                                      "software_id"
                                                                                                      (
                                                                                                        T_nlist
                                                                                                          "software_id"
                                                                                                          software_id_length
                                                                                                          None
                                                                                                          true
                                                                                                          (
                                                                                                            T_denoted
                                                                                                              "software_id.element"
                                                                                                              (
                                                                                                                DT_IType
                                                                                                                UInt8
                                                                                                              )
                                                                                                          )
                                                                                                      )
                                                                                                      "Validating field software_id"
                                                                                                  ))
                                                                                          ))))))))))
                                                  )))))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__dcr_registration_payload:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind (kind_nlist kind____UINT8 None)
            (and_then_kind kind____UINT8
                (and_then_kind kind____UINT32
                    (and_then_kind kind____UINT8
                        (and_then_kind kind____UINT8
                            (and_then_kind kind____UINT8
                                (and_then_kind kind____UINT8
                                    (and_then_kind kind____UINT32
                                        (and_then_kind (kind_nlist kind____UINT8 None)
                                            (and_then_kind kind____UINT8
                                                (and_then_kind kind____UINT8
                                                    (and_then_kind kind____UINT8
                                                        (and_then_kind kind____UINT8
                                                            (and_then_kind kind____UINT8
                                                                (and_then_kind kind____UINT32
                                                                    (and_then_kind (kind_nlist kind____UINT8
                                                                            None)
                                                                        (and_then_kind kind____UINT8
                                                                            (and_then_kind kind____UINT32
                                                                                (kind_nlist kind____UINT8
                                                                                    None))))))))))))
                                ))))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__dcr_registration_payload:typ kind__dcr_registration_payload
  Trivial
  Trivial
  Trivial
  false
  false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__dcr_registration_payload])))
    (def__dcr_registration_payload)

[@@ noextract_to "krml"]
noextract
let type__dcr_registration_payload = (as_type (def'__dcr_registration_payload))

[@@ noextract_to "krml"]
noextract
let parser__dcr_registration_payload = (as_parser (def'__dcr_registration_payload))
[@@ normalize_for_extraction specialization_steps]
let validate__dcr_registration_payload =
  as_validator "_dcr_registration_payload" (def'__dcr_registration_payload)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__dcr_registration_payload:dtyp kind__dcr_registration_payload
  false
  false
  Trivial
  Trivial
  Trivial =
  mk_dtyp_app kind__dcr_registration_payload Trivial Trivial Trivial
    (type__dcr_registration_payload)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__dcr_registration_payload]];
                  T.trefl ())))
        (parser__dcr_registration_payload)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__dcr_registration_payload;
                          `%type__dcr_registration_payload;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__dcr_registration_payload))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
