mod error;
mod list;
mod load;

pub(in crate::web::management) use error::client_not_found;
pub(in crate::web::management) use list::list_client_rows;
#[cfg(test)]
pub(in crate::web::management) use list::LIST_CLIENT_ROWS_SQL;
pub(in crate::web::management) use load::load_visible_client;
#[cfg(test)]
pub(in crate::web::management) use load::LOAD_VISIBLE_CLIENT_ROW_SQL;
