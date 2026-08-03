module HashComputation.Low

open FStar.Bytes
open FStar.HyperStack.ST
open FStar.UInt32
open FStar.HyperStack.All

module B = LowStar.Buffer
module HS = FStar.HyperStack
module U8 = FStar.UInt8
module U32 = FStar.UInt32

(* Runtime-facing hash case tags. KaRaMeL extracts these constructors into the
 * stable C enum names consumed by the local shim. *)
type hash_case =
  | HashCaseSha256
  | HashCaseSha384
  | HashCaseSha512

(* Status codes consumed by Rust FFI. *)
let hash_status_ok : U32.t = 0ul
let hash_status_invalid_algorithm : U32.t = 1ul
let hash_status_computation_failed : U32.t = 2ul

noeq type hash_result = {
  status: U32.t;
  digest: bytes;
}

let hash_error (status:U32.t) : hash_result = {
  status = status;
  digest = empty_bytes;
}

assume val bytes_prefix_of_buffer:
  buf:B.buffer U8.t ->
  len:U32.t ->
  Tot bytes

assume val evercrypt_hash_incremental_hash:
  case0:hash_case ->
  output_buf:B.buffer U8.t ->
  input:bytes ->
  input_len:U32.t ->
  Stack U32.t
  (requires (fun h ->
    B.live h output_buf /\ U32.v input_len = Bytes.length input))
  (ensures (fun h0 _ h1 ->
    B.live h1 output_buf /\ B.modifies (B.loc_buffer output_buf) h0 h1))

val compute_case_with_lengths:
  case0:hash_case ->
  full_len:U32.t{U32.v full_len > 0} ->
  trunc_len:U32.t{U32.v trunc_len <= U32.v full_len} ->
  input:bytes ->
  ST hash_result
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True))
let compute_case_with_lengths case0 full_len trunc_len input =
  let out = B.malloc HS.root 0uy full_len in
  let input_len = U32.uint_to_t (Bytes.length input) in
  let status = evercrypt_hash_incremental_hash case0 out input input_len in
  let result =
    if status = hash_status_ok then {
      status = hash_status_ok;
      digest = bytes_prefix_of_buffer out trunc_len;
    } else
      hash_error hash_status_computation_failed
  in
  B.free out;
  result

val compute_oidc_hash_bytes:
  alg:string ->
  input:bytes ->
  ST hash_result
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True))
let compute_oidc_hash_bytes alg input =
  if alg = "RS256" || alg = "ES256" || alg = "HS256" then
    compute_case_with_lengths HashCaseSha256 32ul 16ul input
  else if alg = "RS384" || alg = "ES384" || alg = "HS384" then
    compute_case_with_lengths HashCaseSha384 48ul 24ul input
  else if alg = "RS512" || alg = "ES512" || alg = "HS512" then
    compute_case_with_lengths HashCaseSha512 64ul 32ul input
  else
    hash_error hash_status_invalid_algorithm
