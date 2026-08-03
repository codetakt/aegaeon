mod by_id;
mod by_upstream_subject;

pub(in crate::web::management) use by_id::{
    load_account_link_summary_by_id_for_update, load_account_link_summary_by_id_required,
};
pub(in crate::web::management) use by_upstream_subject::{
    load_account_link_summary_by_upstream_subject,
    load_account_link_summary_by_upstream_subject_for_update,
};

#[cfg(test)]
pub(in crate::web::management) use by_id::LOAD_ACCOUNT_LINK_SUMMARY_BY_ID_SQL;
#[cfg(test)]
pub(in crate::web::management) use by_upstream_subject::LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL;
