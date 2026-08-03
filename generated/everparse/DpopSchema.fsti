(* GENERATED — renamed copy of Dpop.fsti to avoid F* module name conflict with dpop/Dpop.fst.
   Source: generated/everparse/Dpop.fsti (from schemas/Dpop.3d via EverParse).
   If Dpop.3d is regenerated, this file must be re-synced:
     sed 's/^module Dpop$/module DpopSchema/' generated/everparse/Dpop.fsti > generated/everparse/DpopSchema.fsti *)
module DpopSchema
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ noextract_to "krml"]
inline_for_extraction noextract
val kind__dpop_claims:P.parser_kind true P.WeakKindStrongPrefix

[@@ noextract_to "krml"]
noextract
val def'__dpop_claims:typ kind__dpop_claims Trivial Trivial Trivial false false

val validate__dpop_claims:validator_of (def'__dpop_claims)

[@@ specialize; noextract_to "krml"]
noextract
val dtyp__dpop_claims:dtyp_of (def'__dpop_claims)
