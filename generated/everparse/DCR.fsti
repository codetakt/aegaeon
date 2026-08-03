module DCR
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__registration_request:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__registration_request:typ kind__registration_request Trivial Trivial Trivial false false

val validate__registration_request:validator_of (def'__registration_request)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__registration_request:dtyp_of (def'__registration_request)

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__registration_response:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__registration_response:typ kind__registration_response Trivial Trivial Trivial false false

val validate__registration_response:validator_of (def'__registration_response)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__registration_response:dtyp_of (def'__registration_response)

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__update_request:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__update_request:typ kind__update_request Trivial Trivial Trivial false false

val validate__update_request:validator_of (def'__update_request)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__update_request:dtyp_of (def'__update_request)

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__error_response:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__error_response:typ kind__error_response Trivial Trivial Trivial false false

val validate__error_response:validator_of (def'__error_response)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__error_response:dtyp_of (def'__error_response)
