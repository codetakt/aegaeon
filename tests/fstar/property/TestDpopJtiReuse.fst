module TestDpopJtiReuse

module U64 = FStar.UInt64
open Dpop.Claims
open Dpop.Validation
open Dpop.Signature

inline_for_extraction let u64 (n:nat) : U64.t =
  U64.uint_to_t (FStar.UInt.uint_to_t #64 n)

// A token with a fixed `jti`
let token =
  { htm = "GET"; htu = "/resource"; iat = u64 0; jti = "id" }

// An assumed signature tuple that verifies successfully
assume val good_sig :
  unit -> Tot (p:(public_key * string * string * signature){
    let k, h, pld, s = p in verify_signature k h pld s })

// The first verification should succeed and produce a replay ticket.
// Replay防止はランタイム (Redis) が担うため、Verified Core 自体は同じ jti でも ticket を返す。
let _ =
  let k, h, pld, s = good_sig () in
  match verify_dpop token "GET" "/resource" (u64 10) (u64 10) k h pld s with
  | Some ticket ->
      assert (verify_dpop token "GET" "/resource" (u64 10) (u64 10) k h pld s = Some ticket)
  | None ->
      assert False
