module Drbg.HmacSha256

(** HMAC-SHA256 DRBG per NIST SP 800-90A Section 10.1.2.
    0 assume val -- delegates to HACL* via Verified.Crypto.Bridge.
    All functions fully verified: 0 admit, 0 assume val.

    Restricted profile (per docs/verification/rng-plan.md §2):
    - No nonce or personalization_string: the 32-byte seed parameter IS the
      full seed_material. The OS CSPRNG (getrandom) provides sufficient entropy
      that a separate nonce is not required (SP 800-90A Section 8.6.7).
    - No additional_input: drbg_generate always uses empty additional_input.
      This simplifies the API (no pre-generation Update step needed).
    - Per-request instantiation: no DRBG state carried across requests.
    - provided_data bounded to <=32 bytes (sufficient: seed=32, entropy=32, empty=0).
    - Reseed limit enforced via precondition (runtime enforcement is caller's
      responsibility in the Rust FFI layer). *)

open FStar.Bytes
module VCB = Verified.Crypto.Bridge

(* ── Constants per SP 800-90A ─────────────────────────── *)

let reseed_limit: nat = 281474976710656  (* 2^48 *)
let max_bytes_per_request: nat = 65536   (* 2^16 = 2^19 bits *)
let max_blocks_per_request: nat = 2048   (* max_bytes_per_request / 32 *)

(* ── HACL* delegation ──────────────────────────────── *)

(** HMAC-SHA256 via HACL* Spec.Agile.HMAC.
    Delegates to Verified.Crypto.Bridge.hmac_sha256.
    Strong-constraint compliant: real HACL* computation, not assume val.
    Local wrapper adds DRBG-specific precondition (key = 32 bytes, data ≤ 65 bytes)
    and verifies Bridge preconditions are satisfied. *)
private
let hmac_sha256
  (key: bytes{Bytes.length key = 32})
  (data: bytes{Bytes.length data <= 65})
  : Tot (r:bytes{Bytes.length r = 32})
  = VCB.hmac_sha256 key data

(* ── State type ───────────────────────────────────────── *)

(** DRBG state per SP 800-90A Section 10.1.2.
    Invariant: key and v are always 32 bytes. *)
type drbg_state = {
  key: k:bytes{Bytes.length k = 32};
  v:   v:bytes{Bytes.length v = 32};
  reseed_counter: nat;
}

(* ── Internal helpers ─────────────────────────────────── *)

private
let byte_0x00 : b:bytes{Bytes.length b = 1} = Bytes.create 1ul 0uy

private
let byte_0x01 : b:bytes{Bytes.length b = 1} = Bytes.create 1ul 1uy

(** HMAC_DRBG Update per SP 800-90A Section 10.1.2.2.
    Steps 1-2: K = HMAC(K, V || 0x00 || provided_data), V = HMAC(K_new, V).
    Steps 3-5: If provided_data non-empty, additional round with 0x01.
    Precondition: provided_data length bounded so appends fit UInt32. *)
private
let drbg_update
  (key: bytes{Bytes.length key = 32})
  (v: bytes{Bytes.length v = 32})
  (provided_data: bytes{Bytes.length provided_data <= 32})
  : Tot (p:(bytes * bytes){Bytes.length (fst p) = 32 /\ Bytes.length (snd p) = 32})
  =
  (* Step 1: K = HMAC(K, V || 0x00 || provided_data) *)
  let k1 = hmac_sha256 key (Bytes.append v (Bytes.append byte_0x00 provided_data)) in
  (* Step 2: V = HMAC(K_new, V_old) *)
  let v1 = hmac_sha256 k1 v in
  (* Step 3: If provided_data is empty, return *)
  if Bytes.length provided_data = 0 then
    (k1, v1)
  else begin
    (* Step 4: K = HMAC(K, V || 0x01 || provided_data) *)
    let k2 = hmac_sha256 k1 (Bytes.append v1 (Bytes.append byte_0x01 provided_data)) in
    (* Step 5: V = HMAC(K_new, V) *)
    let v2 = hmac_sha256 k2 v1 in
    (k2, v2)
  end

(** Recursive block generation: produces blocks*32 bytes of output.
    V is chained: each iteration computes V' = HMAC(K, V_prev).
    K is not modified during generation (per SP 800-90A).
    Precondition: blocks bounded so total output fits UInt32. *)
private
let rec generate_blocks
  (key: bytes{Bytes.length key = 32})
  (v: bytes{Bytes.length v = 32})
  (blocks: nat{blocks <= max_blocks_per_request})
  : Tot (p:(bytes * bytes){Bytes.length (fst p) = op_Multiply blocks 32 /\ Bytes.length (snd p) = 32})
  (decreases blocks)
  =
  if blocks = 0 then
    (empty_bytes, v)
  else begin
    let v' = hmac_sha256 key v in
    let blocks' : nat = blocks - 1 in
    let p = generate_blocks key v' blocks' in
    let result = Bytes.append v' (fst p) in
    (result, snd p)
  end

(** Ceiling division helper: ((n+31)/32)*32 >= n for n > 0.
    Proof: (n+31)/32 * 32 = n + 31 - ((n+31) mod 32) >= n + 31 - 31 = n. *)
private
let lemma_ceil_div_ge (n: nat{n > 0 /\ n <= max_bytes_per_request})
  : Lemma (let blocks = (n + 31) / 32 in
           op_Multiply blocks 32 >= n /\ blocks > 0 /\ blocks <= max_blocks_per_request)
  = ()

(* ── Public API ───────────────────────────────────────── *)

(** Instantiate: create DRBG state from 32-byte entropy seed.
    SP 800-90A Section 10.1.2.3:
    K = 0x00*32, V = 0x01*32, (K,V) = Update(K, V, seed), counter = 1. *)
val drbg_instantiate:
  seed:bytes{Bytes.length seed = 32} ->
  Tot (st:drbg_state{st.reseed_counter = 1})
let drbg_instantiate seed =
  let k0 = Bytes.create 32ul 0uy in
  let v0 = Bytes.create 32ul 1uy in
  let kv = drbg_update k0 v0 seed in
  { key = fst kv; v = snd kv; reseed_counter = 1 }

(** Generate: produce n bytes of pseudorandom output.
    SP 800-90A Section 10.1.2.5:
    Loop to generate ceil(n/32) blocks, truncate to n bytes,
    update state, increment reseed_counter. *)
val drbg_generate:
  st:drbg_state{st.reseed_counter <= reseed_limit} ->
  n:nat{n > 0 /\ n <= max_bytes_per_request} ->
  Tot (p:(drbg_state * bytes){
    (fst p).reseed_counter = st.reseed_counter + 1 /\
    Bytes.length (snd p) = n})
let drbg_generate st n =
  let blocks_needed = (n + 31) / 32 in
  lemma_ceil_div_ge n;
  let gb = generate_blocks st.key st.v blocks_needed in
  let output = Bytes.sub (fst gb) 0ul (FStar.UInt32.uint_to_t n) in
  let kv = drbg_update st.key (snd gb) empty_bytes in
  let st' = { key = fst kv; v = snd kv; reseed_counter = st.reseed_counter + 1 } in
  (st', output)

(** Reseed: re-key DRBG state with fresh entropy.
    SP 800-90A Section 10.1.2.4:
    (K, V) = Update(K, V, entropy), counter = 1. *)
val drbg_reseed:
  st:drbg_state ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (st':drbg_state{st'.reseed_counter = 1})
let drbg_reseed st entropy =
  let kv = drbg_update st.key st.v entropy in
  { key = fst kv; v = snd kv; reseed_counter = 1 }

(* ── Lemmas ───────────────────────────────────────────── *)

(** Output length guarantee: generate produces exactly n bytes. *)
val lemma_generate_output_length:
  st:drbg_state{st.reseed_counter <= reseed_limit} ->
  n:nat{n > 0 /\ n <= max_bytes_per_request} ->
  Lemma (Bytes.length (snd (drbg_generate st n)) = n)
let lemma_generate_output_length _st _n = ()

(** Counter monotonicity: generate increments reseed_counter by 1. *)
val lemma_generate_counter_increment:
  st:drbg_state{st.reseed_counter <= reseed_limit} ->
  n:nat{n > 0 /\ n <= max_bytes_per_request} ->
  Lemma ((fst (drbg_generate st n)).reseed_counter = st.reseed_counter + 1)
let lemma_generate_counter_increment _st _n = ()

(** Instantiate sets counter to 1. *)
val lemma_instantiate_counter:
  seed:bytes{Bytes.length seed = 32} ->
  Lemma ((drbg_instantiate seed).reseed_counter = 1)
let lemma_instantiate_counter _seed = ()

(** Reseed resets counter to 1. *)
val lemma_reseed_counter:
  st:drbg_state ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Lemma ((drbg_reseed st entropy).reseed_counter = 1)
let lemma_reseed_counter _st _entropy = ()

(** Determinism: same inputs yield same outputs (trivial by Tot purity). *)
val lemma_generate_deterministic:
  st:drbg_state{st.reseed_counter <= reseed_limit} ->
  n:nat{n > 0 /\ n <= max_bytes_per_request} ->
  Lemma (drbg_generate st n == drbg_generate st n)
let lemma_generate_deterministic _st _n = ()
