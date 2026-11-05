; Conditional complete-inventory transaction/replay model, not a proof of SQL
; atomicity, durable storage, SHA equality, root custody or Rust refinement.
; Those premises require actual prefix-failure, lost-reply and supply evidence.
(set-logic QF_LIA)
(declare-const count Int)
(declare-const buffered Int)
(declare-const committed Bool)
(declare-const reply_lost Bool)
(declare-const exact_intent Bool)
(declare-const same_principal Bool)
(declare-const same_stores Bool)
(declare-const drained Bool)
(declare-const pending Bool)
(declare-const parent_active Bool)
(declare-const active_children Int)
(declare-const old_associations Int)
(declare-const retained_associations Int)
(declare-const runtime_enabled Bool)
(define-fun pre () Bool
  (and exact_intent same_principal same_stores drained (not pending)))
; A native transaction contains one parent transition and binding+activation
; for every child. A lost reply does not alter whether its COMMIT became durable.
(define-fun transaction () Bool
  (and (<= 1 count) (<= count 64) (<= 0 buffered) (<= buffered (+ 1 (* 2 count)))
       (=> committed (and pre (= buffered (+ 1 (* 2 count)))))
       (= parent_active committed) (= active_children (ite committed count 0))
       (<= 0 old_associations) (= retained_associations old_associations)
       (not runtime_enabled)))
(push)
(assert transaction)
(assert (or (and parent_active (< active_children count))
            (and (not parent_active) (> active_children 0))))
(check-sat) ; unsat: no durable partial inventory under atomic transaction premise
(pop)
(push)
(assert transaction)
(assert committed)
(assert (not pre))
(check-sat) ; unsat: wrong intent/principal/store or pending work cannot commit
(pop)
(push)
(assert transaction)
(assert (or runtime_enabled (not (= retained_associations old_associations))))
(check-sat) ; unsat: activation does not enable serving or remove old associations
(pop)
(push)
(assert transaction)
(assert committed)
(assert reply_lost)
(check-sat) ; sat: lost reply can coexist with complete activation; never blindly undo
(pop)
(push)
; Negative control: separate parent COMMIT followed by interruption before any
; child activation violates complete-inventory durability.
(assert (and (= count 2) parent_active (= active_children 0)))
(check-sat) ; sat: removing transaction composition admits a partial durable state
(pop)
