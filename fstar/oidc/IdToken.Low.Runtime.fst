module IdToken.Low.Runtime

(* Low* runtime for ID Token FFI (Stack-based, caller-owned buffers).
 * Error codes are uint32_t: 0=OK, 1=CAP_TOO_SMALL, 2=AUD_BAD_FORMAT, 3=OVERFLOW.
 * Inputs are ptr+len (+tag) only; Spec types are not exposed.
 *)

open LowStar
module B = LowStar.Buffer
module U32 = FStar.UInt32
module U8 = FStar.UInt8
open FStar.HyperStack.ST
open FStar.Bytes

// Error codes
let idtok_e_ok : U32.t = 0ul
let idtok_e_cap_too_small : U32.t = 1ul
let idtok_e_aud_bad_format : U32.t = 2ul
let idtok_e_overflow : U32.t = 3ul

// Caller-owned byte slice
noeq type c_bytes = { ptr: B.buffer U8.t; cap: U32.t; len: U32.t }

noeq type c_option_bytes = { tag: U8.t; value: c_bytes }
noeq type c_option_u8    = { tag: U8.t; value: U8.t }
noeq type c_option_u32   = { tag: U8.t; value: U32.t }

// Audience flat layout "aud1\0aud2\0...audN\0"
noeq type c_audience = {
  buf: B.buffer U8.t;
  cap: U32.t;
  len: U32.t;
  count: U32.t
}

// Result type aliases (error code + updated record)
type result_bytes         = U32.t & c_bytes
type result_audience      = U32.t & c_audience
type result_option_bytes  = U32.t & c_option_bytes
type result_option_u8     = U32.t & c_option_u8
type result_option_u32    = U32.t & c_option_u32

noeq type result_idtoken = {
  fst: U32.t;
  snd: c_bytes;          // issuer
  thd: c_bytes;          // subject
  f3: c_audience;        // audience
  f4: c_option_bytes;    // nonce
  f5: c_option_bytes;    // at_hash
  f6: c_option_bytes     // c_hash
}

// Top-level loops to avoid nested-recursion warnings in extraction
// NOTE: OIDC Low* runtime remains opt-in; keep helpers noextract until promoted.
noextract
let rec copy_bytes_loop (src:bytes) (dst:c_bytes) (slen:nat{slen <= U32.v dst.cap /\ slen = Bytes.length src}) (i:nat{i <= slen}) : ST unit
  (requires (fun h -> B.live h dst.ptr /\ B.length dst.ptr >= U32.v dst.cap))
  (ensures (fun h0 _ h1 -> B.live h1 dst.ptr /\ B.modifies (B.loc_buffer dst.ptr) h0 h1))
=
  if i = slen then ()
  else (
    B.upd dst.ptr (U32.uint_to_t i) (Bytes.index src i);
    copy_bytes_loop src dst slen (i + 1)
  )

noextract
let rec copy_audience_loop (aud_bytes:bytes) (dst:c_audience) (needed:nat{needed <= U32.v dst.cap /\ needed = Bytes.length aud_bytes}) (i:nat{i <= needed}) (nuls:nat{nuls <= i}) : ST nat
  (requires (fun h -> B.live h dst.buf /\ B.length dst.buf >= U32.v dst.cap))
  (ensures (fun h0 n h1 -> B.live h1 dst.buf /\ B.modifies (B.loc_buffer dst.buf) h0 h1 /\ n <= needed))
=
  if i = needed then nuls
  else (
    let b = Bytes.index aud_bytes i in
    B.upd dst.buf (U32.uint_to_t i) b;
    let nuls' = if b = 0uy then nuls + 1 else nuls in
    copy_audience_loop aud_bytes dst needed (i + 1) nuls'
  )

// Helpers ------------------------------------------------------------
noextract
let mk_none_bytes (v:c_bytes) : c_option_bytes =
  { tag = 0uy; value = { v with len = 0ul } }

noextract
let mk_some_bytes (v:c_bytes) : c_option_bytes =
  { tag = 1uy; value = v }

noextract
let mk_none_u8 (d:U8.t) : c_option_u8 = { tag = 0uy; value = d }
noextract
let mk_some_u8 (v:U8.t) : c_option_u8 = { tag = 1uy; value = v }
noextract
let mk_none_u32 (d:U32.t) : c_option_u32 = { tag = 0uy; value = d }
noextract
let mk_some_u32 (v:U32.t) : c_option_u32 = { tag = 1uy; value = v }

// Copy bytes into buffer, return updated c_bytes with new len
noextract
val copy_bytes_checked : src:bytes -> dst:c_bytes -> ST result_bytes
  (requires (fun h ->
    B.live h dst.ptr /\ B.length dst.ptr >= U32.v dst.cap))
  (ensures (fun h0 (res, dst') h1 ->
    B.live h1 dst'.ptr /\ dst'.ptr == dst.ptr /\
    B.modifies (B.loc_buffer dst.ptr) h0 h1 /\
    (res = idtok_e_ok ==> U32.v dst'.len = Bytes.length src)))

noextract
let copy_bytes_checked src dst =
  let slen = Bytes.length src in
  if slen > U32.v dst.cap then
    (idtok_e_cap_too_small, dst)
  else begin
    copy_bytes_loop src dst slen 0;
    let dst' : c_bytes = { ptr = dst.ptr; cap = dst.cap; len = U32.uint_to_t slen } in
    (idtok_e_ok, dst')
  end

// Validate audience and copy flat bytes; computes count
noextract
val copy_audience_checked : aud_bytes:bytes -> dst:c_audience -> ST result_audience
  (requires (fun h ->
    B.live h dst.buf /\ B.length dst.buf >= U32.v dst.cap))
  (ensures (fun h0 (res, dst') h1 ->
    B.live h1 dst'.buf /\ dst'.buf == dst.buf /\
    B.modifies (B.loc_buffer dst.buf) h0 h1 /\
    (res = idtok_e_ok ==> U32.v dst'.len = Bytes.length aud_bytes)))

noextract
let copy_audience_checked aud_bytes dst =
  let needed = Bytes.length aud_bytes in
  if needed > U32.v dst.cap then
    (idtok_e_cap_too_small, dst)
  else if needed = 0 then
    let dst' : c_audience = { buf = dst.buf; cap = dst.cap; len = 0ul; count = 0ul } in
    (idtok_e_ok, dst')
  else begin
    // Must end with '\0'
    if Bytes.index aud_bytes (needed - 1) <> 0uy then
      (idtok_e_aud_bad_format, dst)
    else begin
      let nuls = copy_audience_loop aud_bytes dst needed 0 0 in
      if nuls = 0 then
        (idtok_e_aud_bad_format, dst)
      else begin
        let len32 : U32.t = U32.uint_to_t needed in
        let count32 : U32.t = U32.uint_to_t nuls in
        let dst' : c_audience = { buf = dst.buf; cap = dst.cap; len = len32; count = count32 } in
        (idtok_e_ok, dst')
      end
    end
  end

// Optional bytes field
noextract
let process_optional_bytes (data:bytes) (is_some:bool) (dst:c_bytes) : ST result_option_bytes
  (requires (fun h ->
    B.live h dst.ptr /\ B.length dst.ptr >= U32.v dst.cap))
  (ensures (fun h0 (res, opt) h1 ->
    B.live h1 opt.value.ptr /\ opt.value.ptr == dst.ptr /\
    B.modifies (B.loc_buffer dst.ptr) h0 h1))
=
  if not is_some then
    (idtok_e_ok, mk_none_bytes dst)
  else
    let (r, dst') = copy_bytes_checked data dst in
    if r <> idtok_e_ok then
      (r, mk_none_bytes dst)
    else
      (idtok_e_ok, mk_some_bytes dst')

// Public APIs --------------------------------------------------------

noextract
val write_id_token_low :
  issuer:bytes ->
  subject:bytes ->
  aud_flat:bytes ->
  nonce:bytes -> nonce_tag:U8.t ->
  at_hash:bytes -> at_hash_tag:U8.t ->
  c_hash:bytes -> c_hash_tag:U8.t ->
  exp:U32.t -> iat:U32.t ->
  out_issuer:c_bytes ->
  out_sub:c_bytes ->
  out_aud:c_audience ->
  out_nonce:c_bytes ->
  out_at_hash:c_bytes ->
  out_c_hash:c_bytes ->
  ST result_idtoken
    (requires (fun h ->
      B.live h out_issuer.ptr /\ B.length out_issuer.ptr >= U32.v out_issuer.cap /\
      B.live h out_sub.ptr /\ B.length out_sub.ptr >= U32.v out_sub.cap /\
      B.live h out_aud.buf /\ B.length out_aud.buf >= U32.v out_aud.cap /\
      B.live h out_nonce.ptr /\ B.length out_nonce.ptr >= U32.v out_nonce.cap /\
      B.live h out_at_hash.ptr /\ B.length out_at_hash.ptr >= U32.v out_at_hash.cap /\
      B.live h out_c_hash.ptr /\ B.length out_c_hash.ptr >= U32.v out_c_hash.cap /\
      // disjoint buffers to satisfy liveness across sequential writes
      B.disjoint out_issuer.ptr out_sub.ptr /\
      B.disjoint out_issuer.ptr out_aud.buf /\
      B.disjoint out_issuer.ptr out_nonce.ptr /\
      B.disjoint out_issuer.ptr out_at_hash.ptr /\
      B.disjoint out_issuer.ptr out_c_hash.ptr /\
      B.disjoint out_sub.ptr out_aud.buf /\
      B.disjoint out_sub.ptr out_nonce.ptr /\
      B.disjoint out_sub.ptr out_at_hash.ptr /\
      B.disjoint out_sub.ptr out_c_hash.ptr /\
      B.disjoint out_aud.buf out_nonce.ptr /\
      B.disjoint out_aud.buf out_at_hash.ptr /\
      B.disjoint out_aud.buf out_c_hash.ptr /\
      B.disjoint out_nonce.ptr out_at_hash.ptr /\
      B.disjoint out_nonce.ptr out_c_hash.ptr /\
      B.disjoint out_at_hash.ptr out_c_hash.ptr))
    (ensures (fun h0 r h1 ->
      (r.fst = idtok_e_ok ==> B.live h1 r.snd.ptr /\ B.live h1 r.thd.ptr /\ B.live h1 r.f3.buf /\
         B.live h1 r.f4.value.ptr /\ B.live h1 r.f5.value.ptr /\ B.live h1 r.f6.value.ptr /\
         U32.v r.snd.len = Bytes.length issuer /\
         U32.v r.thd.len = Bytes.length subject)))

noextract
let write_id_token_low issuer subject aud_flat nonce nonce_tag at_hash at_hash_tag c_hash c_hash_tag exp iat out_issuer out_sub out_aud out_nonce out_at_hash out_c_hash =
  let (r1, issuer') = copy_bytes_checked issuer out_issuer in
  if r1 <> idtok_e_ok then { fst = r1; snd = issuer'; thd = out_sub; f3 = out_aud; f4 = mk_none_bytes out_nonce; f5 = mk_none_bytes out_at_hash; f6 = mk_none_bytes out_c_hash } else
  let (r2, sub') = copy_bytes_checked subject out_sub in
  if r2 <> idtok_e_ok then { fst = r2; snd = issuer'; thd = sub'; f3 = out_aud; f4 = mk_none_bytes out_nonce; f5 = mk_none_bytes out_at_hash; f6 = mk_none_bytes out_c_hash } else
  let (r3, aud') = copy_audience_checked aud_flat out_aud in
  if r3 <> idtok_e_ok then { fst = r3; snd = issuer'; thd = sub'; f3 = aud'; f4 = mk_none_bytes out_nonce; f5 = mk_none_bytes out_at_hash; f6 = mk_none_bytes out_c_hash } else
  let (r4, nonce_opt) = process_optional_bytes nonce (nonce_tag = 1uy) out_nonce in
  if r4 <> idtok_e_ok then { fst = r4; snd = issuer'; thd = sub'; f3 = aud'; f4 = nonce_opt; f5 = mk_none_bytes out_at_hash; f6 = mk_none_bytes out_c_hash } else
  let (r5, at_opt) = process_optional_bytes at_hash (at_hash_tag = 1uy) out_at_hash in
  if r5 <> idtok_e_ok then { fst = r5; snd = issuer'; thd = sub'; f3 = aud'; f4 = nonce_opt; f5 = at_opt; f6 = mk_none_bytes out_c_hash } else
  let (r6, c_opt) = process_optional_bytes c_hash (c_hash_tag = 1uy) out_c_hash in
  { fst = r6; snd = issuer'; thd = sub'; f3 = aud'; f4 = nonce_opt; f5 = at_opt; f6 = c_opt }

noextract
val write_userinfo_low :
  name:bytes -> name_tag:U8.t ->
  email:bytes -> email_tag:U8.t ->
  email_verified:U8.t -> email_verified_tag:U8.t ->
  updated_at:U32.t -> updated_at_tag:U8.t ->
  out_name:c_bytes ->
  out_email:c_bytes ->
  out_email_verified:c_option_u8 ->
  out_updated_at:c_option_u32 ->
  ST (U32.t & c_option_bytes & c_option_bytes & c_option_u8 & c_option_u32)
    (requires (fun h ->
      B.live h out_name.ptr /\ B.length out_name.ptr >= U32.v out_name.cap /\
      B.live h out_email.ptr /\ B.length out_email.ptr >= U32.v out_email.cap))
    (ensures (fun h0 (res, name', email', ev', ua') h1 ->
      B.live h1 name'.value.ptr /\ B.live h1 email'.value.ptr /\
      (res = idtok_e_ok ==> True)))

noextract
let write_userinfo_low name name_tag email email_tag email_verified email_verified_tag updated_at updated_at_tag out_name out_email out_email_verified out_updated_at =
  let (r1, name_opt) = process_optional_bytes name (name_tag = 1uy) out_name in
  if r1 <> idtok_e_ok then (r1, name_opt, mk_none_bytes out_email, mk_none_u8 out_email_verified.value, mk_none_u32 out_updated_at.value) else
  let (r2, email_opt) = process_optional_bytes email (email_tag = 1uy) out_email in
  if r2 <> idtok_e_ok then (r2, name_opt, email_opt, mk_none_u8 out_email_verified.value, mk_none_u32 out_updated_at.value) else
  let ev_opt =
    if email_verified_tag = 1uy then mk_some_u8 email_verified else mk_none_u8 out_email_verified.value
  in
  let ua_opt =
    if updated_at_tag = 1uy then mk_some_u32 updated_at else mk_none_u32 out_updated_at.value
  in
  (idtok_e_ok, name_opt, email_opt, ev_opt, ua_opt)
