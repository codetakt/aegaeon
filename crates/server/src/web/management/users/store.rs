mod list;
mod profile_update;
mod status;

pub(super) use list::list_user_rows;
pub(super) use profile_update::{build_user_update_patch, update_user_fields_row};
pub(super) use status::{
    load_user_row_for_status, update_user_status_row, UserStatusUpdateMessages,
};

#[cfg(test)]
pub(in crate::web::management) use list::LIST_USER_ROWS_SQL;
#[cfg(test)]
pub(in crate::web::management) use profile_update::UPDATE_USER_FIELDS_ROW_SQL;
#[cfg(test)]
pub(in crate::web::management) use status::{
    load_user_for_status_sql_for_test, update_user_status_sql_for_test,
};
