module Dpop.Iat_validation

module U64 = FStar.UInt64

inline_for_extraction let abs_diff (a:U64.t) (b:U64.t) : U64.t =
  if U64.gte a b then U64.sub a b else U64.sub b a

inline_for_extraction let validate_iat
  (now:U64.t)
  (iat:U64.t)
  (window:U64.t)
  : Tot bool
  = U64.lte (abs_diff now iat) window
