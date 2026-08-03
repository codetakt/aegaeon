mod insert;
mod update;

pub(in crate::web::management) use insert::insert_connection_row;
pub(in crate::web::management) use update::update_connection_row;
