use uuid::Uuid;

use crate::management::types::{
    AccountLinkConflictCandidate, AccountLinkInactiveTargetHandling,
    AccountLinkLowConfidenceHandling,
};
use crate::web::management::AccountLinkRefreshTokenAction;

#[derive(Debug, Clone)]
pub(in crate::web::management::account_link_conflict) struct AccountLinkConflictResolutionPlan {
    pub(in crate::web::management::account_link_conflict) existing_account_link_id: Uuid,
    pub(in crate::web::management::account_link_conflict) moving_to_different_user: bool,
    pub(in crate::web::management::account_link_conflict) selected_candidate:
        Option<AccountLinkConflictCandidate>,
    pub(in crate::web::management::account_link_conflict) refresh_token_action:
        Option<AccountLinkRefreshTokenAction>,
    pub(in crate::web::management::account_link_conflict) low_confidence_action:
        Option<AccountLinkLowConfidenceHandling>,
    pub(in crate::web::management::account_link_conflict) inactive_target_action:
        Option<AccountLinkInactiveTargetHandling>,
}
