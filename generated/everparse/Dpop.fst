module Dpop
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
let def__dpop_claims =
  ((T_drop
      (T_pair "htm"
          false
          (T_with_comment "htm" (T_denoted "htm" (dtyp__len_prefixed_bytes)) "Validating field htm")
          false
          (T_pair "htu"
              false
              (T_with_comment "htu"
                  (T_denoted "htu" (dtyp__len_prefixed_bytes))
                  "Validating field htu")
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
                      (T_pair "ath"
                          false
                          (T_with_comment "ath"
                              (T_denoted "ath" (dtyp__len_prefixed_bytes))
                              "Validating field ath")
                          false
                          (T_with_comment "nonce"
                              (T_denoted "nonce" (dtyp__len_prefixed_bytes))
                              "Validating field nonce")))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__dpop_claims:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind__len_prefixed_bytes
        (and_then_kind kind__len_prefixed_bytes
            (and_then_kind kind____UINT64
                (and_then_kind kind__len_prefixed_bytes
                    (and_then_kind kind__len_prefixed_bytes kind__len_prefixed_bytes)))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__dpop_claims:typ kind__dpop_claims Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__dpop_claims])))
    (def__dpop_claims)

[@@ noextract_to "krml"]
noextract
let type__dpop_claims = (as_type (def'__dpop_claims))

[@@ noextract_to "krml"]
noextract
let parser__dpop_claims = (as_parser (def'__dpop_claims))
[@@ normalize_for_extraction specialization_steps]
let validate__dpop_claims = as_validator "_dpop_claims" (def'__dpop_claims)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__dpop_claims:dtyp kind__dpop_claims false false Trivial Trivial Trivial =
  mk_dtyp_app kind__dpop_claims Trivial Trivial Trivial (type__dpop_claims)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__dpop_claims]];
                  T.trefl ())))
        (parser__dpop_claims)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__dpop_claims; `%type__dpop_claims; `%coerce]];
                  T.trefl ())))
        (validate__dpop_claims))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
