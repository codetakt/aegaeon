mod lifecycle;
mod mapper;
mod mutation;
mod read;

pub(in crate::web::management) use lifecycle::{
    load_retirable_oauth_profile, retire_oauth_profile, RetirableOAuthProfile,
};
pub(in crate::web::management) use mapper::oauth_profile_from_row_result;
pub(in crate::web::management) use mutation::{
    clear_default_oauth_profiles, insert_oauth_profile_row, update_oauth_profile_row,
};
pub(in crate::web::management) use read::{
    list_oauth_profile_rows, load_oauth_profile, oauth_profile_not_found,
};
#[cfg(test)]
pub(in crate::web::management) use read::{
    LIST_OAUTH_PROFILE_ROWS_SQL, LOAD_OAUTH_PROFILE_ROW_SQL,
};
