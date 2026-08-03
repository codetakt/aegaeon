use super::super::{
    account_link_inactive_target_handling_label, account_link_low_confidence_handling_label,
    account_link_reassignment_audit_severity, account_link_refresh_token_action_label,
    AccountLinkAuditEvent, AccountLinkConnectionRecord,
};
use super::plan::AccountLinkConflictResolutionPlan;
use crate::management::types::{AccountLinkSummary, User};

pub(super) fn account_link_conflict_resolved_audit_event<'a>(
    connection: &'a AccountLinkConnectionRecord,
    upstream_subject_hash: &'a str,
    existing_account_link: &'a AccountLinkSummary,
    resolved_account_link: &'a AccountLinkSummary,
    target_user: &'a User,
    plan: &'a AccountLinkConflictResolutionPlan,
) -> AccountLinkAuditEvent<'a> {
    AccountLinkAuditEvent {
        event_type: "management.accountLink.conflictResolved.v1",
        severity: account_link_reassignment_audit_severity(
            plan.refresh_token_action,
            plan.low_confidence_action,
            plan.inactive_target_action,
        ),
        target_id: &resolved_account_link.id,
        data: serde_json::json!({
            "accountLinkId": &resolved_account_link.id,
            "connectionId": &resolved_account_link.connection_id,
            "connectionIdentifier": &connection.connection_identifier,
            "connectionName": &connection.name,
            "upstreamIssuer": &resolved_account_link.upstream_issuer,
            "upstreamSubjectHash": upstream_subject_hash,
            "previousEndUserId": &existing_account_link.end_user_id,
            "previousEndUserSubject": &existing_account_link.end_user_subject,
            "previousEndUserEmail": &existing_account_link.end_user_email,
            "endUserId": &resolved_account_link.end_user_id,
            "endUserSubject": &resolved_account_link.end_user_subject,
            "endUserEmail": &resolved_account_link.end_user_email,
            "selectedCandidateMatchReasons": plan
                .selected_candidate
                .as_ref()
                .map_or_else(Vec::new, |candidate| candidate.match_reasons.clone()),
            "targetUserStatus": &target_user.status,
            "hasRefreshToken": resolved_account_link.has_refresh_token,
            "upstreamRefreshTokenHandling": account_link_refresh_token_action_label(
                plan.refresh_token_action
            ),
            "lowConfidenceHandling": account_link_low_confidence_handling_label(
                plan.low_confidence_action
            ),
            "inactiveTargetHandling": account_link_inactive_target_handling_label(
                plan.inactive_target_action
            ),
        }),
    }
}
