module IdTokenSchema
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__id_token_jwt_entry:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__id_token_jwt_entry:typ kind__id_token_jwt_entry Trivial Trivial Trivial false false

val validate__id_token_jwt_entry:validator_of (def'__id_token_jwt_entry)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__id_token_jwt_entry:dtyp_of (def'__id_token_jwt_entry)

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__id_token_claims_entry:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__id_token_claims_entry:typ kind__id_token_claims_entry Trivial Trivial Trivial false false

val validate__id_token_claims_entry:validator_of (def'__id_token_claims_entry)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__id_token_claims_entry:dtyp_of (def'__id_token_claims_entry)

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__userinfo_response_entry:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__userinfo_response_entry:typ kind__userinfo_response_entry
  Trivial
  Trivial
  Trivial
  false
  false

val validate__userinfo_response_entry:validator_of (def'__userinfo_response_entry)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__userinfo_response_entry:dtyp_of (def'__userinfo_response_entry)
