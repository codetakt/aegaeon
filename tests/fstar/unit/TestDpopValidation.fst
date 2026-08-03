module TestDpopValidation

module U64 = FStar.UInt64
open Dpop.Claims
open Dpop.Validation
open Dpop.Signature

inline_for_extraction let u64 (n:nat) : U64.t =
  U64.uint_to_t (FStar.UInt.uint_to_t #64 n)

let base = { htm = "GET"; htu = "/"; iat = u64 0; jti = "x" }

assume val good_sig :
  unit -> Tot (p:(public_key * string * string * signature){
    let k, h, pld, s = p in verify_signature k h pld s })

assume val bad_sig :
  unit -> Tot (p:(public_key * string * string * signature){
    let k, h, pld, s = p in not (verify_signature k h pld s) })

// A well-formed token should verify successfully
let _ =
  let k, h, pld, s = good_sig () in
  match verify_dpop base "GET" "/" (u64 10) (u64 10) k h pld s with
  | Some ticket ->
    assert (ticket.jti = base.jti)
  | None -> assert False

  let _ =
    let k, h, pld, s = good_sig () in
    assert_norm (verify_dpop ({ base with htm = "POST" }) "GET" "/" (u64 10) (u64 10) k h pld s = None)

  let _ =
    let k, h, pld, s = good_sig () in
    assert_norm (verify_dpop ({ base with htu = "/bad" }) "GET" "/" (u64 10) (u64 10) k h pld s = None)

  let _ =
    let k, h, pld, s = good_sig () in
    assert_norm (verify_dpop ({ base with iat = u64 21 }) "GET" "/" (u64 10) (u64 10) k h pld s = None)

let _ =
  let k, h, pld, s = bad_sig () in
  assert_norm (verify_dpop base "GET" "/" (u64 10) (u64 10) k h pld s = None)
