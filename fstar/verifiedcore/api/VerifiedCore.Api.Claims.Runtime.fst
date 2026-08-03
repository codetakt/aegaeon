module VerifiedCore.Api.Claims.Runtime

(**
 * Verified Core Claims Runtime — Phase D: WASM Host Boundary Internalization
 *
 * This module implements claims-based verification for DPoP and JWT tokens.
 * It operates on raw buffer inputs (pointers + lengths) without opaque handles.
 *
 * Crypto operations (SHA-256, Ed25519 verify) are performed directly via HACL*
 * functions compiled into the WASM binary, eliminating host callback boundaries.
 *
 * The ONLY remaining host callback is host_replay_store_check_and_store,
 * which requires host-side state (an atomic replay detection store).
 *
 * For adapter-promoted compatibility algorithms (for example OIDC's RS256
 * required slice on the client track), callers may set a dedicated
 * "signature preverified" flag. This means the host/runtime adapter has
 * already verified the signature and the Verified Core should continue with
 * claims/time/replay validation without re-running crypto in the WASM body.
 *)

(** ========== FFI Contract Summary ==========
 *
 * This module declares 1 host callback (down from 5 pre-Phase D):
 *
 *   host_replay_store_check_and_store: Atomic check-and-insert replay store.
 *
 * Crypto operations previously delegated to the host are now internalized:
 *   - SHA-256: via VerifiedCore.Crypto.Hacl.hacl_sha256 [HACL*]
 *   - Ed25519 verify: via VerifiedCore.Crypto.Hacl.hacl_ed25519_verify [HACL*]
 *
 * Host contract (not in verified spec -- must hold for all implementations):
 *   1. host_replay_store_check_and_store: Atomic check-and-insert;
 *      returns 0=ok, 1=replay, 2+=unavailable.
 *
 * Thread safety (host contract): The replay store callback must be safe to
 * call from any thread and must provide atomic check-and-store semantics.
 *)

open FStar.HyperStack.ST
open FStar.UInt32
open FStar.UInt64

module U8 = FStar.UInt8
module U32 = FStar.UInt32
module U64 = FStar.UInt64
module B = LowStar.Buffer

(** ========== Status Codes ========== *)

type status_code =
  | OK
  | INVALID_ARGUMENT
  | INVALID_FORMAT
  | INVALID_SIGNATURE
  | INVALID_CLAIMS
  | REPLAY
  | UNAVAILABLE
  | UNSUPPORTED
  | INTERNAL_ERROR

let status_to_u32 (s: status_code): U32.t =
  match s with
  | OK -> 0ul
  | INVALID_ARGUMENT -> 1ul
  | INVALID_FORMAT -> 2ul
  | INVALID_SIGNATURE -> 3ul
  | INVALID_CLAIMS -> 4ul
  | REPLAY -> 5ul
  | UNAVAILABLE -> 6ul
  | UNSUPPORTED -> 7ul
  | INTERNAL_ERROR -> 8ul

(** ========== Crypto Result Types ========== *)

type host_crypto_verify_result =
  | CRYPTO_VALID
  | CRYPTO_INVALID
  | CRYPTO_UNSUPPORTED
  | CRYPTO_ERROR

type replay_store_result =
  | REPLAY_OK
  | REPLAY_DETECTED
  | REPLAY_UNAVAILABLE

let replay_result_from_u32 (v: U32.t): replay_store_result =
  if v = 0ul then REPLAY_OK
  else if v = 1ul then REPLAY_DETECTED
  else REPLAY_UNAVAILABLE

(** ========== Signature Algorithm ========== *)

type signature_algorithm =
  | ES256
  | RS256
  | EdDSA

let algorithm_to_u32 (alg: signature_algorithm): U32.t =
  match alg with
  | ES256 -> 1ul
  | RS256 -> 2ul
  | EdDSA -> 3ul

let algorithm_from_bitmask (bitmask: U32.t) (alg: signature_algorithm): bool =
  let bit = match alg with
    | ES256 -> 0ul
    | RS256 -> 1ul
    | EdDSA -> 2ul
  in
  U32.((bitmask `logand` (1ul `shift_left` bit)) <> 0ul)

(** ========== Host Callback: Replay Store ========== *)

(** FFI Contract: host_replay_store_check_and_store
 * Atomically check if key_hash exists in the replay store; insert if absent.
 * This is the ONLY remaining host callback in this module.
 *
 * Pre (verified spec): both buffers are live, namespace_len is in bounds,
 *   key_hash_ptr has length >= 32, buffers are disjoint.
 * Post (verified spec): read-only (h0 == h1); store is host-side state.
 * Post (host contract, not in spec): returns 0=fresh, 1=replay, 2+=unavailable.
 * Thread safety (host contract): MUST provide atomic check-and-store.
 *)
assume val host_replay_store_check_and_store:
  namespace_ptr: B.buffer U8.t ->
  namespace_len: U32.t ->
  key_hash_ptr: B.buffer U8.t{B.length key_hash_ptr >= 32} ->
  ttl_milliseconds: U32.t ->
  Stack U32.t
  (requires fun h ->
    B.live h namespace_ptr /\ B.live h key_hash_ptr /\
    U32.v namespace_len <= B.length namespace_ptr /\
    B.disjoint namespace_ptr key_hash_ptr)
  (ensures fun h0 _r h1 -> h0 == h1)

(** ========== EdDSA Signature Verification via HACL* ========== *)

(* Verify an Ed25519 signature using HACL* internalized crypto.
   Returns CRYPTO_INVALID if key/signature lengths are wrong for Ed25519
   (pk must be 32 bytes, sig must be 64 bytes). *)
let verify_signature_eddsa
  (public_key_ptr: B.buffer U8.t)
  (public_key_len: U32.t)
  (signing_input_ptr: B.buffer U8.t)
  (signing_input_len: U32.t)
  (signature_ptr: B.buffer U8.t)
  (signature_len: U32.t)
: Stack host_crypto_verify_result
  (requires fun h ->
    B.live h public_key_ptr /\ B.live h signing_input_ptr /\ B.live h signature_ptr /\
    U32.v public_key_len <= B.length public_key_ptr /\
    U32.v signing_input_len <= B.length signing_input_ptr /\
    U32.v signature_len <= B.length signature_ptr /\
    B.disjoint public_key_ptr signing_input_ptr /\
    B.disjoint public_key_ptr signature_ptr /\
    B.disjoint signing_input_ptr signature_ptr)
  (ensures fun h0 _ h1 -> h0 == h1)
=
  (* Ed25519 requires exactly 32-byte public key and 64-byte signature *)
  if public_key_len <> 32ul then CRYPTO_INVALID
  else if signature_len <> 64ul then CRYPTO_INVALID
  else
    let valid = VerifiedCore.Crypto.Hacl.hacl_ed25519_verify
      public_key_ptr signing_input_len signing_input_ptr signature_ptr
    in
    if valid then CRYPTO_VALID
    else CRYPTO_INVALID

(* Multi-algorithm signature verification dispatch.
   Only EdDSA via HACL-star is supported in the verified WASM path.
   ES256 and RS256 return CRYPTO_UNSUPPORTED. *)
let try_verify_signature
  (allowed_algs: U32.t)
  (public_key_ptr: B.buffer U8.t)
  (public_key_len: U32.t)
  (signing_input_ptr: B.buffer U8.t)
  (signing_input_len: U32.t)
  (signature_ptr: B.buffer U8.t)
  (signature_len: U32.t)
: Stack host_crypto_verify_result
  (requires fun h ->
    B.live h public_key_ptr /\ B.live h signing_input_ptr /\ B.live h signature_ptr /\
    U32.v public_key_len <= B.length public_key_ptr /\
    U32.v signing_input_len <= B.length signing_input_ptr /\
    U32.v signature_len <= B.length signature_ptr /\
    B.disjoint public_key_ptr signing_input_ptr /\
    B.disjoint public_key_ptr signature_ptr /\
    B.disjoint signing_input_ptr signature_ptr)
  (ensures fun h0 _ h1 -> h0 == h1)
=
  if algorithm_from_bitmask allowed_algs EdDSA then
    verify_signature_eddsa public_key_ptr public_key_len
      signing_input_ptr signing_input_len signature_ptr signature_len
  else CRYPTO_UNSUPPORTED

(** ========== DPoP Flags ========== *)

let dpop_flag_require_ath: U32.t = 1ul  (* bit 0 *)
let dpop_flag_require_jti: U32.t = 2ul  (* bit 1 *)
let dpop_flag_signature_preverified: U32.t = 4ul  (* bit 2 *)

let dpop_has_flag (flags: U32.t) (flag: U32.t): bool =
  U32.((flags `logand` flag) <> 0ul)

(** ========== JWT Flags ========== *)

let jwt_flag_require_exp: U32.t = 1ul  (* bit 0 *)
let jwt_flag_require_iat: U32.t = 2ul  (* bit 1 *)
let jwt_flag_require_nbf: U32.t = 4ul  (* bit 2 *)
let jwt_flag_signature_preverified: U32.t = 8ul  (* bit 3 *)

let jwt_has_flag (flags: U32.t) (flag: U32.t): bool =
  U32.((flags `logand` flag) <> 0ul)

(** ========== Time Validation ========== *)

(* Check if iat is within acceptable window:
   now - max_age <= iat <= now + max_future_skew

   We use a formulation that avoids overflow:
   - Lower bound check: iat + max_age >= now  (instead of iat >= now - max_age)
   - Upper bound check: iat <= now + max_skew (with overflow check)
*)
let iat_in_window
  (iat_seconds: U64.t)
  (now_seconds: U64.t)
  (max_age_seconds: U32.t)
  (max_future_skew_seconds: U32.t)
: Tot bool =
  let max_age_u64 = FStar.Int.Cast.uint32_to_uint64 max_age_seconds in
  let max_skew_u64 = FStar.Int.Cast.uint32_to_uint64 max_future_skew_seconds in
  (* Lower bound: iat + max_age >= now (no underflow possible) *)
  let lower_ok =
    (* Check if iat + max_age would overflow, if so it's definitely >= now *)
    if U64.(iat_seconds >^ (0xFFFFFFFFFFFFFFFFUL -^ max_age_u64))
    then true
    else U64.((iat_seconds +^ max_age_u64) >=^ now_seconds)
  in
  (* Upper bound: iat <= now + max_skew (check overflow) *)
  let upper_ok =
    (* Check if now + max_skew would overflow *)
    if U64.(now_seconds >^ (0xFFFFFFFFFFFFFFFFUL -^ max_skew_u64))
    then true  (* overflow means upper bound is effectively infinite *)
    else U64.(iat_seconds <=^ (now_seconds +^ max_skew_u64))
  in
  lower_ok && upper_ok

(* Check if token is not expired: now <= exp *)
let not_expired (exp_seconds: U64.t) (now_seconds: U64.t): bool =
  U64.(now_seconds <=^ exp_seconds)

(* Check if token is active: now >= nbf *)
let is_active (nbf_seconds: U64.t) (now_seconds: U64.t): bool =
  U64.(now_seconds >=^ nbf_seconds)

(** ========== DPoP Claims Verification ========== *)

(*
 * Verify DPoP claims with pre-parsed, raw buffer inputs.
 *
 * Phase D: Crypto operations (SHA-256, Ed25519) are performed directly via
 * HACL* functions compiled into the WASM binary. HTTP method/URI comparison
 * is handled by the C exports layer before calling this function.
 *
 * Verification steps:
 * 1. Check inputs are non-empty
 * 2. Check jti presence if required
 * 3. Check ath presence if required
 * 4. Validate iat is within window
 * 5. Verify signature via HACL* Ed25519
 * 6. Compute replay key hash via HACL* SHA-256
 * 7. Call replay store to prevent reuse
 *)
let dpop_verify_claims_impl
  (signing_input_ptr: B.buffer U8.t)
  (signing_input_len: U32.t)
  (signature_ptr: B.buffer U8.t)
  (signature_len: U32.t)
  (public_key_ptr: B.buffer U8.t)
  (public_key_len: U32.t)
  (replay_namespace_ptr: B.buffer U8.t)
  (replay_namespace_len: U32.t)
  (has_ath: bool)
  (has_jti: bool)
  (allowed_algs_bitmask: U32.t)
  (flags: U32.t)
  (iat_seconds: U64.t)
  (now_seconds: U64.t)
  (max_age_seconds: U32.t)
  (max_future_skew_seconds: U32.t)
  (output_replay_key_hash: B.buffer U8.t)
: Stack status_code
  (requires fun h ->
    B.live h signing_input_ptr /\
    B.live h signature_ptr /\
    B.live h public_key_ptr /\
    B.live h replay_namespace_ptr /\
    B.live h output_replay_key_hash /\
    U32.v signing_input_len <= B.length signing_input_ptr /\
    U32.v signature_len <= B.length signature_ptr /\
    U32.v public_key_len <= B.length public_key_ptr /\
    U32.v replay_namespace_len <= B.length replay_namespace_ptr /\
    B.length output_replay_key_hash >= 32 /\
    (* Disjointness: output buffer must not alias any input *)
    B.disjoint output_replay_key_hash signing_input_ptr /\
    B.disjoint output_replay_key_hash signature_ptr /\
    B.disjoint output_replay_key_hash public_key_ptr /\
    B.disjoint output_replay_key_hash replay_namespace_ptr /\
    (* Disjointness: EdDSA verify requires pairwise disjoint inputs *)
    B.disjoint public_key_ptr signing_input_ptr /\
    B.disjoint public_key_ptr signature_ptr /\
    B.disjoint signing_input_ptr signature_ptr)
  (ensures fun h0 _r h1 ->
    B.modifies (B.loc_buffer output_replay_key_hash) h0 h1)
=
  (* Step 1: Check inputs are present *)
  if signing_input_len = 0ul ||
     signature_len = 0ul ||
     public_key_len = 0ul
  then INVALID_ARGUMENT

  (* Step 2: Check jti if required *)
  else if dpop_has_flag flags dpop_flag_require_jti && not has_jti
  then INVALID_CLAIMS

  (* Step 3: Check ath if required *)
  else if dpop_has_flag flags dpop_flag_require_ath && not has_ath
  then INVALID_CLAIMS

  (* Step 4: Validate iat window *)
  else if not (iat_in_window iat_seconds now_seconds max_age_seconds max_future_skew_seconds)
  then INVALID_CLAIMS

  (* Step 5: Verify signature via HACL* EdDSA *)
  else
    let crypto_result =
      if dpop_has_flag flags dpop_flag_signature_preverified
      then CRYPTO_VALID
      else try_verify_signature
        allowed_algs_bitmask public_key_ptr public_key_len
        signing_input_ptr signing_input_len signature_ptr signature_len
    in
    match crypto_result with
    | CRYPTO_INVALID -> INVALID_SIGNATURE
    | CRYPTO_UNSUPPORTED -> UNSUPPORTED
    | CRYPTO_ERROR -> INTERNAL_ERROR
    | CRYPTO_VALID ->
      (* Step 6: Compute replay key hash via HACL* SHA-256 *)
      VerifiedCore.Crypto.Hacl.hacl_sha256
        output_replay_key_hash signing_input_ptr signing_input_len;
      (* Step 7: Check replay store *)
      let ttl_ms =
        if U32.(max_age_seconds >^ 4294967ul)  (* 4294967 * 1000 < 2^32 *)
        then 0xFFFFFFFFul
        else U32.(max_age_seconds *^ 1000ul)
      in
      let replay_result = host_replay_store_check_and_store
        replay_namespace_ptr replay_namespace_len output_replay_key_hash ttl_ms
      in
      let replay_status = replay_result_from_u32 replay_result in
      match replay_status with
      | REPLAY_DETECTED -> REPLAY
      | REPLAY_UNAVAILABLE -> UNAVAILABLE
      | REPLAY_OK -> OK

(** ========== JWT Claims Verification ========== *)

(*
 * Verify JWT claims with pre-parsed, raw buffer inputs.
 *
 * Phase D: Signature verification via HACL* Ed25519.
 * Issuer/audience comparison is handled by the C exports layer.
 *
 * Verification steps:
 * 1. Check inputs are non-empty
 * 2. Check exp if required
 * 3. Check iat if required
 * 4. Check nbf if required
 * 5. Validate exp (if present)
 * 6. Validate nbf (if present)
 * 7. Verify signature via HACL* Ed25519
 *)
let jwt_verify_claims_impl
  (signing_input_ptr: B.buffer U8.t)
  (signing_input_len: U32.t)
  (signature_ptr: B.buffer U8.t)
  (signature_len: U32.t)
  (public_key_ptr: B.buffer U8.t)
  (public_key_len: U32.t)
  (allowed_algs_bitmask: U32.t)
  (flags: U32.t)
  (exp_seconds: U64.t)
  (nbf_seconds: U64.t)
  (iat_seconds: U64.t)
  (now_seconds: U64.t)
: Stack status_code
  (requires fun h ->
    B.live h signing_input_ptr /\ B.live h signature_ptr /\ B.live h public_key_ptr /\
    U32.v signing_input_len <= B.length signing_input_ptr /\
    U32.v signature_len <= B.length signature_ptr /\
    U32.v public_key_len <= B.length public_key_ptr /\
    B.disjoint public_key_ptr signing_input_ptr /\
    B.disjoint public_key_ptr signature_ptr /\
    B.disjoint signing_input_ptr signature_ptr)
  (ensures fun h0 _r h1 -> h0 == h1)
=
  (* Step 1: Check inputs are present *)
  if signing_input_len = 0ul ||
     signature_len = 0ul ||
     public_key_len = 0ul
  then INVALID_ARGUMENT

  (* Step 2: Check exp if required *)
  else if jwt_has_flag flags jwt_flag_require_exp && exp_seconds = 0UL
  then INVALID_CLAIMS

  (* Step 3: Check iat if required *)
  else if jwt_has_flag flags jwt_flag_require_iat && iat_seconds = 0UL
  then INVALID_CLAIMS

  (* Step 4: Check nbf if required *)
  else if jwt_has_flag flags jwt_flag_require_nbf && nbf_seconds = 0UL
  then INVALID_CLAIMS

  (* Step 5: Validate exp (if present) *)
  else if exp_seconds <> 0UL && not (not_expired exp_seconds now_seconds)
  then INVALID_CLAIMS

  (* Step 6: Validate nbf (if present) *)
  else if nbf_seconds <> 0UL && not (is_active nbf_seconds now_seconds)
  then INVALID_CLAIMS

  (* Step 7: Verify signature via HACL* EdDSA *)
  else
    let crypto_result =
      if jwt_has_flag flags jwt_flag_signature_preverified
      then CRYPTO_VALID
      else try_verify_signature
        allowed_algs_bitmask public_key_ptr public_key_len
        signing_input_ptr signing_input_len signature_ptr signature_len
    in
    match crypto_result with
    | CRYPTO_INVALID -> INVALID_SIGNATURE
    | CRYPTO_UNSUPPORTED -> UNSUPPORTED
    | CRYPTO_ERROR -> INTERNAL_ERROR
    | CRYPTO_VALID -> OK
