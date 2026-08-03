mod create;
mod delete;
mod update;

pub(in crate::web::management) use create::insert_client_row;
pub(in crate::web::management) use delete::delete_client_row;
#[cfg(test)]
pub(in crate::web::management) use delete::DELETE_CLIENT_ROW_SQL;
pub(in crate::web::management) use update::{load_client_for_update, update_client_row};
#[cfg(test)]
pub(in crate::web::management) use update::{LOAD_CLIENT_FOR_UPDATE_SQL, UPDATE_CLIENT_ROW_SQL};
