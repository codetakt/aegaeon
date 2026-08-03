module JoseHeader
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__jose_header_entry:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__jose_header_entry:typ kind__jose_header_entry Trivial Trivial Trivial false false

val validate__jose_header_entry:validator_of (def'__jose_header_entry)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__jose_header_entry:dtyp_of (def'__jose_header_entry)
