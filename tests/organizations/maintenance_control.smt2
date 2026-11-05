; Conditional transition model of schema-v9 maintenance ownership.
; PostgreSQL row-lock linearization, catalog/TLS/durability and the trusted
; caller's actual worker/connection completion are external premises.
; This is not an automatic SQL refinement or product proof discharge.
(set-logic QF_LIA)
(declare-const phase Int)
(declare-const pending Bool)
(declare-const generation Int)
(declare-const next_phase Int)
(declare-const next_pending Bool)
(declare-const next_generation Int)
(declare-const drained Bool)
(declare-const exact_fence Bool)
(declare-const exact_owner Bool)
(declare-const actual_completion Bool)
(define-fun maximum () Int 9223372036854775807)
(define-fun valid ((p Int) (held Bool) (g Int)) Bool
  (and (<= 0 p) (<= p 2) (<= 0 g) (<= g maximum)
       (=> held (and (= p 0) (> g 0)))))
; phase: 0=fenced, 1=prepared, 2=active.
(define-fun unchanged () Bool
  (and (= next_phase phase) (= next_pending pending) (= next_generation generation)))
(define-fun transition () Bool
  (or
    ; Re-fencing preserves all pending work and generations.
    (and (= next_phase 0) (= next_pending pending) (= next_generation generation))
    ; Prepare and activate require no retained maintenance.
    (and (= phase 0) (not pending) drained exact_fence
         (= next_phase 1) (not next_pending) (= next_generation generation))
    (and (= phase 1) (not pending) drained exact_fence
         (= next_phase 2) (not next_pending) (= next_generation generation))
    ; Acquisition is exclusive and cannot wrap the generation.
    (and (= phase 0) (not pending) drained exact_fence (< generation maximum)
         (= next_phase 0) next_pending (= next_generation (+ generation 1)))
    ; exact_owner includes principal/work/generation/plan, not caller assertion.
    (and pending exact_owner actual_completion
         (= next_phase phase) (not next_pending) (= next_generation generation))
    ; Refusal, lost response, cancellation and process loss do not clear ownership.
    unchanged))
(assert (valid phase pending generation))
(push)
(assert transition)
(assert (not (and (valid next_phase next_pending next_generation)
                 (>= next_generation generation))))
(check-sat) ; unsat: inductive exclusion and bounded monotone generation
(pop)
(push)
(assert pending)
(assert (not (and exact_owner actual_completion)))
(assert transition)
(assert (not next_pending))
(check-sat) ; unsat: uncertain/unowned completion cannot clear pending
(pop)
(push)
; The same missing prepare guard exercised by the real PostgreSQL negative case.
(assert (= phase 0))
(assert pending)
(assert (= next_phase 1))
(assert next_pending)
(assert (= next_generation generation))
(assert (not (valid next_phase next_pending next_generation)))
(check-sat) ; sat: the guard-removal counterexample must remain detectable
(pop)
