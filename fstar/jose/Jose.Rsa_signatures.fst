module Jose.Rsa_signatures

open FStar.Bytes
open FStar.HyperStack.All
open FStar.UInt32
open Verified.Crypto.Bridge

(** RSA-PSS verification — compat allowlist only (ring/aws-lc-rs at runtime).
    Not in verified allowlist. Conservative `false` (deny by default).
    Marked `irreducible` — downstream sees only the type signature. *)
irreducible
let verify_rsa_pss
  (key:bytes) (key_len:UInt32.t)
  (data:bytes) (data_len:UInt32.t)
  (signature:bytes) (sig_len:UInt32.t)
  : Tot bool
  = false

(** Ed25519 verification via HACL* Spec.Ed25519.
    Real cryptographic computation — NOT false.
    Delegates to Verified.Crypto.Bridge.ed25519_verify.
    Marked `irreducible` — downstream sees only the type signature. *)
irreducible
let verify_ed25519
  (key:bytes) (data_len:UInt32.t)
  (data:bytes) (signature:bytes)
  : Tot bool
  = if Bytes.length key = 32 &&
       Bytes.length data <= Lib.IntTypes.max_size_t &&
       Bytes.length signature = 64
    then ed25519_verify key data signature
    else false
