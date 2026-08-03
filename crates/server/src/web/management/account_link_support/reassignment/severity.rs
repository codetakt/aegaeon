use super::refresh_token::AccountLinkRefreshTokenAction;
use crate::management::types::{
    AccountLinkInactiveTargetHandling, AccountLinkLowConfidenceHandling,
};

pub(in crate::web::management) fn account_link_reassignment_audit_severity(
    refresh_token_action: Option<AccountLinkRefreshTokenAction>,
    low_confidence_action: Option<AccountLinkLowConfidenceHandling>,
    inactive_target_action: Option<AccountLinkInactiveTargetHandling>,
) -> &'static str {
    if matches!(
        refresh_token_action,
        Some(AccountLinkRefreshTokenAction::Retain)
    ) || low_confidence_action.is_some()
        || inactive_target_action.is_some()
    {
        "WARNING"
    } else {
        "INFO"
    }
}
