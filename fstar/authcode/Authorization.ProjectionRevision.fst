module Authorization.ProjectionRevision

(* Arithmetic contract only; authority, transaction and audit checks are
   independent obligations of the management operation. *)
let max_i64 : int = 9223372036854775807

let next (base:int) (source:int) (enabled:bool) : Tot (option int) =
  let ceiling = max_i64 - (if enabled then 2 else 1) in
  let successor = base + 1 in
  if 1 <= successor && successor <= ceiling && 1 <= source && source <= ceiling
  then Some successor
  else None

let lemma_exact_successor (base:int) (source:int) (enabled:bool) (revision:int)
  : Lemma
    (requires (next base source enabled = Some revision))
    (ensures (revision = base + 1 /\ 1 <= revision /\ revision < max_i64))
  = ()

let lemma_enable_reserves_disable (base:int) (source:int) (revision:int)
  : Lemma
    (requires (next base source true = Some revision))
    (ensures (next revision (source + 1) false = Some (revision + 1)))
  = ()

let lemma_exhausted_tombstone (source:int)
  : Lemma (next (max_i64 - 1) source true = None)
  = ()

let lemma_disable_boundary_reachable ()
  : Lemma (next (max_i64 - 2) (max_i64 - 1) false = Some (max_i64 - 1))
  = ()
