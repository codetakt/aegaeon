; Offline recovery transition. Actual service/SQL observations, inventory,
; administrator custody and nonrollback supply remain external premises.
; This is not automatic Python/SQL refinement or atomic product discharge.
(set-logic QF_UF)
(declare-const pending Bool)
(declare-const next_pending Bool)
(declare-const fenced Bool)
(declare-const next_fenced Bool)
(declare-const exact_owner Bool)
(declare-const credentials_excluded Bool)
(declare-const workers_stopped Bool)
(declare-const backends_gone Bool)
(declare-const no_prepared Bool)
(declare-const exact_stores Bool)
(declare-const durable_receipt Bool)
(define-fun ready () Bool
  (and fenced exact_owner credentials_excluded workers_stopped backends_gone
       no_prepared exact_stores durable_receipt))
(define-fun transition () Bool
  (and (= next_fenced fenced)
       (or (= next_pending pending) (and pending ready (not next_pending)))))
(push)
(assert pending)
(assert (not ready))
(assert transition)
(assert (not next_pending))
(check-sat) ; unsat: no uncertainty fallback
(pop)
(push)
(assert fenced)
(assert transition)
(assert (not next_fenced))
(check-sat) ; unsat: recovery cannot activate
(pop)
(push)
(assert pending)
(assert fenced)
(assert exact_owner)
(assert (not credentials_excluded))
(assert (and workers_stopped backends_gone no_prepared exact_stores durable_receipt))
(assert (not next_pending))
(check-sat) ; sat: omission of credential exclusion admits unsafe clear
(pop)
(push)
(assert pending)
(assert fenced)
(assert exact_owner)
(assert (and credentials_excluded backends_gone no_prepared exact_stores durable_receipt))
(assert (not workers_stopped))
(assert (not next_pending))
(check-sat) ; sat: backend census alone does not establish worker termination
(pop)
