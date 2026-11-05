; Conditional preparation-prefix model. SHA equality, durable SQL and root secret
; custody are premises, not proved supplier properties or automatic refinement.
(set-logic QF_LIA)
(declare-const step Int)
(declare-const predecessor Int)
(declare-const next_step Int)
(declare-const same_plan Bool)
(declare-const same_fence Bool)
(declare-const same_receipt Bool)
(declare-const active Bool)
(declare-const next_active Bool)
(define-fun transition () Bool
  (and (<= 0 step) (< step 8) (<= 0 predecessor) (< predecessor 7)
       same_plan same_fence (= next_active active)
       (or (and (= step predecessor) (= next_step (+ step 1)))
           (and (= step (+ predecessor 1)) same_receipt (= next_step step)))))
(push)
(assert transition)
(assert (or (< next_step step) (> next_step (+ step 1))))
(check-sat) ; unsat: no skipped or reversed phase
(pop)
(push)
(assert transition)
(assert (or (not same_plan) (not same_fence)))
(check-sat) ; unsat: exact plan and fence remain necessary
(pop)
(push)
(assert transition)
(assert (not active))
(assert next_active)
(check-sat) ; unsat: no preparation transition enables serving
(pop)
(push)
(assert transition)
(assert (= step (+ predecessor 1)))
(assert (not same_receipt))
(check-sat) ; unsat: replay cannot replace the preceding receipt
(pop)
(push)
(assert (and (= step 0) (= predecessor 0) (= next_step 1) same_fence (not same_plan)))
(check-sat) ; sat: omitting plan comparison accepts a conflicting plan
(pop)
(push)
(assert (and (= step 0) (= predecessor 3) (= next_step 4) same_fence same_plan))
(check-sat) ; sat: omitting predecessor comparison skips unchecked effects
(pop)
