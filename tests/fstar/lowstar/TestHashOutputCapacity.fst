module TestHashOutputCapacity

open FStar.Bytes
open FStar.HyperStack.ST
open HashComputation.Low

module B = LowStar.Buffer
module HS = FStar.HyperStack
module U32 = FStar.UInt32

(* Check the real module explicitly before this fixture. These calls exercise
 * exact and larger capacities, independently of the OIDC dispatcher. *)
let valid_helpers (input:bytes) : ST unit
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  let _ = compute_case_with_lengths HashCaseSha256 32ul 16ul input in
  let _ = compute_case_with_lengths HashCaseSha384 48ul 24ul input in
  let _ = compute_case_with_lengths HashCaseSha512 64ul 32ul input in
  let _ = compute_case_with_lengths HashCaseSha256 33ul 16ul input in
  let _ = compute_case_with_lengths HashCaseSha384 49ul 24ul input in
  let _ = compute_case_with_lengths HashCaseSha512 65ul 32ul input in
  ()

let valid_foreign_calls (input:bytes) : ST unit
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  let input_len = U32.uint_to_t (Bytes.length input) in
  let out256 = B.malloc HS.root 0uy 32ul in
  let _ = evercrypt_hash_incremental_hash HashCaseSha256 out256 input input_len in
  B.free out256;
  let out384 = B.malloc HS.root 0uy 48ul in
  let _ = evercrypt_hash_incremental_hash HashCaseSha384 out384 input input_len in
  B.free out384;
  let out512 = B.malloc HS.root 0uy 64ul in
  let _ = evercrypt_hash_incremental_hash HashCaseSha512 out512 input input_len in
  B.free out512

(* Each negative differs from a valid call only in output capacity. F* must
 * report exactly one failed proof obligation (Error 19); syntax errors,
 * unknown names, missing dependencies or an unexpectedly valid call fail
 * this fixture. No negative is executed or extracted. *)
[@@ expect_failure [19]]
let short_helper_sha256 (input:bytes) : ST hash_result
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  compute_case_with_lengths HashCaseSha256 31ul 16ul input

[@@ expect_failure [19]]
let short_helper_sha384 (input:bytes) : ST hash_result
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  compute_case_with_lengths HashCaseSha384 47ul 24ul input

[@@ expect_failure [19]]
let short_helper_sha512 (input:bytes) : ST hash_result
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  compute_case_with_lengths HashCaseSha512 63ul 32ul input

[@@ expect_failure [19]]
let short_foreign_sha256 (input:bytes) : ST unit
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  let out = B.malloc HS.root 0uy 31ul in
  let input_len = U32.uint_to_t (Bytes.length input) in
  let _ = evercrypt_hash_incremental_hash HashCaseSha256 out input input_len in
  B.free out

[@@ expect_failure [19]]
let short_foreign_sha384 (input:bytes) : ST unit
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  let out = B.malloc HS.root 0uy 47ul in
  let input_len = U32.uint_to_t (Bytes.length input) in
  let _ = evercrypt_hash_incremental_hash HashCaseSha384 out input input_len in
  B.free out

[@@ expect_failure [19]]
let short_foreign_sha512 (input:bytes) : ST unit
  (requires (fun _ -> True))
  (ensures (fun _ _ _ -> True)) =
  let out = B.malloc HS.root 0uy 63ul in
  let input_len = U32.uint_to_t (Bytes.length input) in
  let _ = evercrypt_hash_incremental_hash HashCaseSha512 out input input_len in
  B.free out
