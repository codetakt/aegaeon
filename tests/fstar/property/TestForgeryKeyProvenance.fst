module TestForgeryKeyProvenance
open Jose.Jwk_structure
open Jose.Alg_policy
open Verified.Crypto.Bridge
open Jose.Jws.Verify
module FB = FStar.Bytes

let generated_mac_key_is_in_the_security_domain
  (a:alg) (k:FB.bytes{hs_security_key_admissible a k})
  : Lemma (mac_key_generated [{kg_alg = a; kg_key = k}] a k)
  = assert (hs_key_admissible a k);
    let reflexive (d:FB.bytes)
      : Lemma (hs_data_admissible a d ==> hs_mac a k d = hs_mac a k d)
      = ()
    in
    FStar.Classical.forall_intro reflexive;
    assert (mac_key_equiv a k k);
    let generated = {kg_alg = a; kg_key = k} in
    assert (FStar.List.Tot.mem generated [generated])

let unissued_accepted_mac_is_a_qualified_forgery
  (key:jwk{hs_security_key_admissible key.alg key.k}) (token:string)
  : Lemma (requires jws_verify key token = true)
          (ensures jws_mac_forgery [{kg_alg = key.alg; kg_key = key.k}] [] [] key token)
  = generated_mac_key_is_in_the_security_domain key.alg key.k;
    lemma_jws_verify_true_shape key token

let short_mac_key_is_outside_the_forgery_game
  (keys:list mac_key_generation_event) (history:list mac_event)
  (compromised:list FB.bytes) (key:jwk{FB.length key.k < 32}) (token:string)
  : Lemma (~(jws_mac_forgery keys history compromised key token))
  = ()

let unregistered_mac_key_is_outside_the_forgery_game
  (history:list mac_event) (compromised:list FB.bytes) (key:jwk) (token:string)
  : Lemma (~(jws_mac_forgery [] history compromised key token))
  = ()

let hs384_requires_48_bytes
  (keys:list mac_key_generation_event) (k:FB.bytes{FB.length k < 48})
  : Lemma (~(mac_key_generated keys HS384 k))
  = ()

let hs512_requires_64_bytes
  (keys:list mac_key_generation_event) (k:FB.bytes{FB.length k < 64})
  : Lemma (~(mac_key_generated keys HS512 k))
  = ()

let registration_is_algorithm_specific
  (a:alg) (other:alg{a <> other}) (k generated:FB.bytes)
  : Lemma (~(mac_key_generated [{kg_alg = other; kg_key = generated}] a k))
  = ()

let generated_ed25519_key_is_in_the_security_domain
  (pk:FB.bytes{FB.length pk = 32})
  : Lemma (ed25519_key_generated [pk] pk)
  = ()

let unsigned_accepted_ed25519_signature_is_a_qualified_forgery
  (pk:FB.bytes{FB.length pk = 32})
  (msg:FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t})
  (sig_:FB.bytes{FB.length sig_ = 64})
  : Lemma (requires ed25519_verify pk msg sig_ = true)
          (ensures ed25519_forgery [pk] [] [] pk msg sig_)
  = ()

let unsigned_accepted_jws_ed25519_signature_is_a_qualified_forgery
  (key:jwk{key.alg = EdDSA}) (token:string)
  : Lemma (requires jws_verify key token = true)
          (ensures jws_eddsa_forgery [key.k] [] [] key token)
  = lemma_jws_verify_true_shape key token

let unregistered_ed25519_key_is_outside_the_forgery_game
  (history:list ed25519_signing_event) (compromised:list FB.bytes)
  (pk:FB.bytes{FB.length pk = 32})
  (msg:FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t})
  (sig_:FB.bytes{FB.length sig_ = 64})
  : Lemma (~(ed25519_forgery [] history compromised pk msg sig_))
  = ()

let unregistered_jws_ed25519_key_is_outside_the_forgery_game
  (history:list ed25519_signing_event) (compromised:list FB.bytes)
  (key:jwk) (token:string)
  : Lemma (~(jws_eddsa_forgery [] history compromised key token))
  = ()
