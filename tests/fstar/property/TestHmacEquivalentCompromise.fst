module TestHmacEquivalentCompromise
open Jose.Jwk_structure
open Jose.Alg_policy
open Verified.Crypto.Bridge
open Verified.Crypto.Hmac.KeyEquiv
open Jose.Jws.Verify
module FB = FStar.Bytes
module SH = Spec.Hash.Definitions

let leaked_equivalent_key_is_excluded_from_forgery
  (key:jwk{key.alg = HS256 /\ 32 <= FB.length key.k /\
           FB.length key.k < SH.block_length SH.SHA2_256})
  (token:string)
  : Lemma
      (requires jws_verify {key with k = FB.append key.k (FB.create 1ul 0uy)} token = true)
      (ensures ~(jws_mac_forgery [{kg_alg = HS256; kg_key = key.k}]
                  [] [FB.append key.k (FB.create 1ul 0uy)] key token))
  = lemma_short_key_admissible key.k;
    assert (mac_key_generated [{kg_alg = HS256; kg_key = key.k}] HS256 key.k);
    let key' = {key with k = FB.append key.k (FB.create 1ul 0uy)} in
    lemma_hmac_sha256_zero_pad_key_equiv key.k;
    lemma_mac_key_equiv_hs256 key'.k key.k;
    assert (FStar.List.Tot.mem key'.k [key'.k]);
    lemma_jws_verify_hs_key_equiv key key' token;
    lemma_jws_verify_true_shape key token
