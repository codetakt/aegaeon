use super::BulkAccountLinkRelinkPlan;
use crate::management::types::*;
use crate::web::management::{
    account_link_inactive_target_handling_label, account_link_reassignment_audit_severity,
    account_link_refresh_token_action_label, AccountLinkAuditEvent, AccountLinkRefreshTokenAction,
};
use uuid::Uuid;

pub(in crate::web::management) fn bulk_account_link_relinked_audit_event<'a>(
    target_user: &'a User,
    ordered_account_links: &'a [AccountLinkSummary],
    existing_account_links: &'a [AccountLinkSummary],
    requested_account_link_ids: &'a [String],
    plan: &'a BulkAccountLinkRelinkPlan,
) -> AccountLinkAuditEvent<'a> {
    AccountLinkAuditEvent {
        event_type: "management.accountLink.relinked.v1",
        severity: account_link_reassignment_audit_severity(
            plan.refresh_token_action,
            None,
            plan.inactive_target_action,
        ),
        target_id: &target_user.id,
        data: serde_json::json!({
            "bulk": true,
            "bulkSize": ordered_account_links.len(),
            "accountLinkIds": requested_account_link_ids,
            "movingAccountLinkIds": &plan.moving_requested_account_link_ids,
            "movingRefreshTokenCount": plan.moving_refresh_token_count,
            "previousLinks": existing_account_links.iter().map(|account_link| {
                serde_json::json!({
                    "accountLinkId": account_link.id,
                    "connectionId": account_link.connection_id,
                    "connectionIdentifier": account_link.connection_identifier,
                    "connectionName": account_link.connection_name,
                    "upstreamIssuer": account_link.upstream_issuer,
                    "previousEndUserId": account_link.end_user_id,
                    "previousEndUserSubject": account_link.end_user_subject,
                    "previousEndUserEmail": account_link.end_user_email,
                    "hasRefreshToken": account_link.has_refresh_token,
                })
            }).collect::<Vec<_>>(),
            "endUserId": &target_user.id,
            "endUserSubject": &target_user.subject,
            "endUserEmail": &target_user.email,
            "targetUserStatus": &target_user.status,
            "upstreamRefreshTokenHandling": account_link_refresh_token_action_label(plan.refresh_token_action),
            "inactiveTargetHandling": account_link_inactive_target_handling_label(plan.inactive_target_action),
        }),
    }
}

pub(in crate::web::management) fn relink_account_link_audit_event<'a>(
    existing_account_link: &'a AccountLinkSummary,
    updated_account_link: &'a AccountLinkSummary,
    target_user: &'a User,
    account_link_id: Uuid,
    refresh_token_action: Option<AccountLinkRefreshTokenAction>,
    inactive_target_action: Option<AccountLinkInactiveTargetHandling>,
) -> AccountLinkAuditEvent<'a> {
    AccountLinkAuditEvent {
        event_type: "management.accountLink.relinked.v1",
        severity: account_link_reassignment_audit_severity(
            refresh_token_action,
            None,
            inactive_target_action,
        ),
        target_id: &updated_account_link.id,
        data: serde_json::json!({
            "accountLinkId": account_link_id.to_string(),
            "connectionId": &updated_account_link.connection_id,
            "connectionIdentifier": &updated_account_link.connection_identifier,
            "connectionName": &updated_account_link.connection_name,
            "upstreamIssuer": &updated_account_link.upstream_issuer,
            "previousEndUserId": &existing_account_link.end_user_id,
            "previousEndUserSubject": &existing_account_link.end_user_subject,
            "previousEndUserEmail": &existing_account_link.end_user_email,
            "endUserId": &updated_account_link.end_user_id,
            "endUserSubject": &updated_account_link.end_user_subject,
            "endUserEmail": &updated_account_link.end_user_email,
            "targetUserStatus": &target_user.status,
            "hasRefreshToken": updated_account_link.has_refresh_token,
            "upstreamRefreshTokenHandling": account_link_refresh_token_action_label(refresh_token_action),
            "inactiveTargetHandling": account_link_inactive_target_handling_label(inactive_target_action),
        }),
    }
}
