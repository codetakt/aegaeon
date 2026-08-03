module DcrRegistration
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__dcr_registration_payload:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__dcr_registration_payload:typ kind__dcr_registration_payload
  Trivial
  Trivial
  Trivial
  false
  false

val validate__dcr_registration_payload:validator_of (def'__dcr_registration_payload)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__dcr_registration_payload:dtyp_of (def'__dcr_registration_payload)
