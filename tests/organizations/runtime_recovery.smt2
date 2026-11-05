; Conditional model only. Actual SQL/Redis/service observations and source/supply
; correspondence remain separate obligations; no new atomic discharge.
(set-logic QF_LIA)
(declare-const pending Bool)
(declare-const next_pending Bool)
(declare-const fenced Bool)
(declare-const next_fenced Bool)
(declare-const exact_state Bool)
(declare-const excluded Bool)
(declare-const stopped Bool)
(declare-const sql_drained Bool)
(declare-const redis_drained Bool)
(declare-const persistent Bool)
(declare-const receipt Bool)
(declare-const generation Int)
(declare-const next_generation Int)
(declare-const unfinished Bool)
(declare-const next_unfinished Bool)
(define-fun ready () Bool
 (and fenced exact_state excluded stopped sql_drained redis_drained persistent receipt))
(define-fun transition () Bool
 (and (= next_fenced fenced) (= next_generation generation)
      (= next_unfinished unfinished)
      (or (= next_pending pending) (and pending ready (not next_pending)))))
(push)
(assert (and pending (not ready) transition (not next_pending)))
(check-sat) ; unsat: missing external premise never clears pending
(pop)
(push)
(assert (and unfinished transition (not next_unfinished)))
(check-sat) ; unsat: termination cannot invent successful store progress
(pop)
(push)
(assert (and fenced transition (or (not next_fenced) (not (= generation next_generation)))))
(check-sat) ; unsat: no activation or generation rebinding
(pop)
(push)
(assert (and pending fenced exact_state excluded stopped sql_drained persistent receipt))
(assert (not redis_drained))
(assert (not next_pending))
(check-sat) ; sat: removing token-store drain permits unsafe release
(pop)
