mod candidates;
mod links;
mod targets;

pub(in crate::web::management) use candidates::load_account_link_conflict_candidates;
pub(in crate::web::management) use links::{
    account_link_exists_by_upstream_subject, delete_account_link_row, insert_account_link_id,
    load_account_link_summary_by_id_for_update, load_account_link_summary_by_id_required,
    load_account_link_summary_by_upstream_subject,
    load_account_link_summary_by_upstream_subject_for_update,
};
pub(in crate::web::management) use targets::{
    ensure_account_link_target_not_deleted, load_account_link_connection,
    load_account_link_connection_for_update, load_account_link_target_user_for_update,
};

#[cfg(test)]
pub(in crate::web::management) use candidates::LOAD_ACCOUNT_LINK_CONFLICT_CANDIDATES_SQL;
#[cfg(test)]
pub(in crate::web::management) use links::{
    LOAD_ACCOUNT_LINK_SUMMARY_BY_ID_SQL, LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL,
};
#[cfg(test)]
pub(in crate::web::management) use targets::{
    LOAD_ACCOUNT_LINK_CONNECTION_SQL, LOAD_ACCOUNT_LINK_TARGET_USER_SQL,
};
