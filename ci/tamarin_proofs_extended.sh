#!/usr/bin/env bash
# Extended Tamarin models kept outside the blocking CI baseline.
# These models provide additional assurance but are not referenced by the
# current compliance-matrix claim set.

PROOFS_EXTENDED=(
	# --- stepup (RFC 9470 ACR/max_age extended model) ---
	"stepup/stepup_acr_enforcement.spthy:"
	"acr_level_enforcement,challenge_session_binding,no_acr_downgrade,"
	"step_up_preserves_identity,challenge_single_use,max_age_triggers_reauth"

	# --- federation trust-anchor lifecycle model ---
	"federation/trust_anchor_rotation.spthy:"
	"anchor_continuity,no_trust_gap_during_rotation,revoked_anchor_no_trust,"
	"new_anchor_requires_admin,anchor_key_authenticity,no_stale_anchor_cache,"
	"rollback_prevention"
)
