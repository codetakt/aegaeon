mod audit;
mod mapper;
mod reassignment;
mod scope;
mod store;

pub(in crate::web::management) use audit::{write_account_link_audit_event, AccountLinkAuditEvent};
pub(in crate::web::management) use mapper::{
    account_link_from_row_result, AccountLinkConnectionRecord,
};
pub(in crate::web::management) use reassignment::{
    account_link_candidate_is_low_confidence, account_link_inactive_target_handling_label,
    account_link_low_confidence_handling_label, account_link_reassignment_audit_severity,
    account_link_refresh_token_action_label, resolve_account_link_inactive_target_handling,
    resolve_account_link_low_confidence_handling, resolve_account_link_refresh_token_action,
    AccountLinkRefreshTokenAction,
};
pub(in crate::web::management) use scope::{
    normalize_account_link_upstream_subject_filter, parse_account_link_subject,
    require_account_link_lifecycle_scope,
};
pub(in crate::web::management) use store::{
    account_link_exists_by_upstream_subject, delete_account_link_row,
    ensure_account_link_target_not_deleted, insert_account_link_id,
    load_account_link_conflict_candidates, load_account_link_connection,
    load_account_link_connection_for_update, load_account_link_summary_by_id_for_update,
    load_account_link_summary_by_id_required, load_account_link_summary_by_upstream_subject,
    load_account_link_summary_by_upstream_subject_for_update,
    load_account_link_target_user_for_update,
};

#[cfg(test)]
pub(in crate::web::management) use store::{
    LOAD_ACCOUNT_LINK_CONFLICT_CANDIDATES_SQL, LOAD_ACCOUNT_LINK_CONNECTION_SQL,
    LOAD_ACCOUNT_LINK_SUMMARY_BY_ID_SQL, LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL,
    LOAD_ACCOUNT_LINK_TARGET_USER_SQL,
};
