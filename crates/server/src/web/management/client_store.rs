mod mapper;
mod mutation;
mod read;

pub(super) use mapper::client_from_row_result;
pub(super) use mutation::{
    delete_client_row, insert_client_row, load_client_for_update, update_client_row,
};
#[cfg(test)]
pub(super) use mutation::{
    DELETE_CLIENT_ROW_SQL, LOAD_CLIENT_FOR_UPDATE_SQL, UPDATE_CLIENT_ROW_SQL,
};
pub(super) use read::{client_not_found, list_client_rows, load_visible_client};
#[cfg(test)]
pub(super) use read::{LIST_CLIENT_ROWS_SQL, LOAD_VISIBLE_CLIENT_ROW_SQL};
