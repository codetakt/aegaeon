module Jose.ListMapLemmas

open FStar.List.Tot

let eq_map_nil
  (#a:Type0)
  (#b:Type0)
  (f:a -> b)
  : Lemma (ensures map f [] == [])
  = ()

let eq_map_cons
  (#a:Type0)
  (#b:Type0)
  (f:a -> b)
  (x:a)
  (xs:list a)
  : Lemma (ensures map f (x :: xs) == f x :: map f xs)
  = ()
