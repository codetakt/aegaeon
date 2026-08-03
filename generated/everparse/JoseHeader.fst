module JoseHeader
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ specialize; noextract_to "krml"]
noextract
let def__jose_header_entry =
  ((T_drop
      (T_dep_pair "key_len"
          (DT_IType UInt8)
          (fun key_len ->
              (T_pair "key"
                  false
                  (T_with_comment "key"
                      (T_nlist "key"
                          (EverParse3d.Prelude.uint8_to_uint32 key_len)
                          None
                          true
                          (T_denoted "key.element" (DT_IType UInt8)))
                      "Validating field key")
                  false
                  (T_dep_pair "value_len"
                      (DT_IType UInt8)
                      (fun value_len ->
                          (T_with_comment "value"
                              (T_nlist "value"
                                  (EverParse3d.Prelude.uint8_to_uint32 value_len)
                                  None
                                  true
                                  (T_denoted "value.element" (DT_IType UInt8)))
                              "Validating field value")))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__jose_header_entry:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT8
        (and_then_kind (kind_nlist kind____UINT8 None)
            (and_then_kind kind____UINT8 (kind_nlist kind____UINT8 None))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__jose_header_entry:typ kind__jose_header_entry Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__jose_header_entry])))
    (def__jose_header_entry)

[@@ noextract_to "krml"]
noextract
let type__jose_header_entry = (as_type (def'__jose_header_entry))

[@@ noextract_to "krml"]
noextract
let parser__jose_header_entry = (as_parser (def'__jose_header_entry))
[@@ normalize_for_extraction specialization_steps]
let validate__jose_header_entry = as_validator "_jose_header_entry" (def'__jose_header_entry)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__jose_header_entry:dtyp kind__jose_header_entry false false Trivial Trivial Trivial =
  mk_dtyp_app kind__jose_header_entry Trivial Trivial Trivial (type__jose_header_entry)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__jose_header_entry]];
                  T.trefl ())))
        (parser__jose_header_entry)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [`%parser__jose_header_entry; `%type__jose_header_entry; `%coerce]
                    ];
                  T.trefl ())))
        (validate__jose_header_entry))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
