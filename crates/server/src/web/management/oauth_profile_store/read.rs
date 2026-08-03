mod error;
mod list;
mod load;

pub(in crate::web::management) use error::oauth_profile_not_found;
pub(in crate::web::management) use list::list_oauth_profile_rows;
#[cfg(test)]
pub(in crate::web::management) use list::LIST_OAUTH_PROFILE_ROWS_SQL;
pub(in crate::web::management) use load::load_oauth_profile;
#[cfg(test)]
pub(in crate::web::management) use load::LOAD_OAUTH_PROFILE_ROW_SQL;
