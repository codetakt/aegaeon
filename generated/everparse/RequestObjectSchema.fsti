module RequestObjectSchema
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__request_object_claims_entry:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__request_object_claims_entry:typ kind__request_object_claims_entry
  Trivial
  Trivial
  Trivial
  false
  false

val validate__request_object_claims_entry:validator_of (def'__request_object_claims_entry)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__request_object_claims_entry:dtyp_of (def'__request_object_claims_entry)
