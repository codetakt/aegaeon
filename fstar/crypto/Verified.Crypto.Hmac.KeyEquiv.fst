module Verified.Crypto.Hmac.KeyEquiv

module FB = FStar.Bytes
module SH = Spec.Hash.Definitions
module SHMAC = Spec.Agile.HMAC
module LI = Lib.IntTypes
open Verified.Crypto.Bridge

friend Spec.Agile.HMAC

let lemma_short_key_admissible key =
  lemma_sha2_limits_exceed_bytes ()

private let lemma_zero_byte ()
  : Lemma (pub_to_sec 0uy == LI.u8 0)
  = LI.v_injective (pub_to_sec 0uy);
    LI.v_injective (LI.u8 0)

(** The HACL* image of the zero-padded key is the padded HACL* image. *)
private let lemma_padded_key_seq (key: FB.bytes{short_admissible_key key})
  : Lemma (fb_to_hacl (FB.append key (FB.create 1ul 0uy)) ==
           Seq.append (fb_to_hacl key) (Seq.create 1 (LI.u8 0)))
  = let z = FB.create 1ul 0uy in
    let key' = FB.append key z in
    let s1 = fb_to_hacl key' in
    let s2 = Seq.append (fb_to_hacl key) (Seq.create 1 (LI.u8 0)) in
    assert (FB.length key' = FB.length key + 1);
    let aux (j: nat{j < FB.length key'}) : Lemma (Seq.index s1 j == Seq.index s2 j) =
      lemma_fb_to_hacl_index key' j;
      if j < FB.length key then begin
        lemma_fb_to_hacl_index key j;
        Seq.lemma_index_app1 (FB.reveal key) (FB.reveal z) j;
        Seq.lemma_index_app1 (fb_to_hacl key) (Seq.create 1 (LI.u8 0)) j
      end else begin
        Seq.lemma_index_app2 (FB.reveal key) (FB.reveal z) j;
        Seq.lemma_index_app2 (fb_to_hacl key) (Seq.create 1 (LI.u8 0)) j;
        assert (FB.index z 0 == 0uy);
        lemma_zero_byte ()
      end
    in
    FStar.Classical.forall_intro aux;
    Seq.lemma_eq_intro s1 s2

(** HACL* level: wrap pads short keys with zero bytes, so the padded key
    wraps to the same block. *)
private let lemma_wrap_zero_pad
  (k: Seq.seq LI.uint8{0 < Seq.length k /\ Seq.length k < SH.block_length SH.SHA2_256 /\
                       Seq.length k `SH.less_than_max_input_length` SH.SHA2_256 /\
                       (Seq.length k + 1) `SH.less_than_max_input_length` SH.SHA2_256})
  : Lemma (SHMAC.wrap SH.SHA2_256 k ==
           SHMAC.wrap SH.SHA2_256 (Seq.append k (Seq.create 1 (LI.u8 0))))
  = let k' = Seq.append k (Seq.create 1 (LI.u8 0)) in
    let n = SH.block_length SH.SHA2_256 in
    assert (Seq.length k' = Seq.length k + 1);
    Seq.lemma_eq_intro (Seq.append k (Seq.create (n - Seq.length k) (LI.u8 0)))
                       (Seq.append k' (Seq.create (n - Seq.length k') (LI.u8 0)))

let lemma_hmac_sha256_zero_pad key data =
  reveal_opaque (`%hmac_sha256) hmac_sha256;
  lemma_padded_key_seq key;
  lemma_wrap_zero_pad (fb_to_hacl key)

let lemma_hmac_sha256_zero_pad_key_equiv key =
  let key' = FB.append key (FB.create 1ul 0uy) in
  assert (FB.length key' <> FB.length key);
  let aux (data: FB.bytes)
    : Lemma (hmac_sha256_data_admissible data ==> hmac_sha256 key data = hmac_sha256 key' data)
    = if FStar.StrongExcludedMiddle.strong_excluded_middle (hmac_sha256_data_admissible data)
      then lemma_hmac_sha256_zero_pad key data
      else ()
  in
  FStar.Classical.forall_intro aux
