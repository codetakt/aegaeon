module Jose.BufferListLemmas

open FStar.List.Tot
open FStar.Seq
open FStar.Math.Lemmas
open LowStar.Buffer

module Seq = FStar.Seq
module Buffer = LowStar.Buffer

/// Tot lemma: Seq.upd preserves trivial_preorder from before to after
let lemma_upd_preserves_trivial_preorder
  (#a:Type)
  (before:Seq.seq a)
  (idx:nat{idx < Seq.length before})
  (value:a)
  : Tot (squash (Buffer.trivial_preorder a before (Seq.upd before idx value)))
  = ()

/// Tot lemma: idx < buffer length from idx + tail_len + 1 <= total_len
let lemma_idx_lt_from_tail_tot
  (idx:nat)
  (tail_len:nat)
  (total_len:nat{idx + tail_len + 1 <= total_len})
  : Tot (squash (idx < total_len))
  = ()

/// Tot lemma: idx < pow2 32 from idx < total_len <= pow2 32
let lemma_idx_lt_pow2_tot
  (idx:nat)
  (total_len:nat{idx < total_len /\ total_len <= pow2 32})
  : Tot (squash (idx < pow2 32))
  = ()

/// Tot lemma: (idx + 1) bounds from idx + tail_len + 1 <= total_len
/// This is a trivial arithmetic lemma; Z3 SMT solver should prove it automatically
/// with sufficient resources. If it continues to fail, consider using admit()
/// as this is purely arithmetic reasoning.
#push-options "--z3rlimit 50 --fuel 10 --ifuel 5"
let lemma_idx_succ_bound_for_rest
  (idx:nat)
  (tail_len:nat)
  (total_len:nat{idx + tail_len + 1 <= total_len})
  : Tot (squash (idx + 1 + tail_len <= total_len /\ idx + 1 <= total_len))
  = ()
#pop-options

/// Lemma alias for use in Stack code (non-Tot version)
let lemma_idx_lt_from_tail = lemma_idx_lt_from_tail_tot
