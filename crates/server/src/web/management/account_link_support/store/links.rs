mod identity;
mod summary;

pub(in crate::web::management) use identity::{
    account_link_exists_by_upstream_subject, delete_account_link_row, insert_account_link_id,
};
pub(in crate::web::management) use summary::{
    load_account_link_summary_by_id_for_update, load_account_link_summary_by_id_required,
    load_account_link_summary_by_upstream_subject,
    load_account_link_summary_by_upstream_subject_for_update,
};

#[cfg(test)]
pub(in crate::web::management) use summary::{
    LOAD_ACCOUNT_LINK_SUMMARY_BY_ID_SQL, LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL,
};
