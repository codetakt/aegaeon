module Steel.Effect

open FStar.All

// Minimal shim for a Steel-like effect layered over Pure.
// This keeps signatures stable while we integrate real Steel later.

effect Steel (a:Type) (pre:Type0) (post:a -> Type0) =
  Pure a (requires pre) (ensures post)

val return: #a:Type -> x:a -> Steel a True (fun y -> y == x)
let return #a x = x
