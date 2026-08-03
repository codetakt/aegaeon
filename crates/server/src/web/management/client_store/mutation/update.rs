mod apply;
mod load;

pub(in crate::web::management) use apply::update_client_row;
#[cfg(test)]
pub(in crate::web::management) use apply::UPDATE_CLIENT_ROW_SQL;
pub(in crate::web::management) use load::load_client_for_update;
#[cfg(test)]
pub(in crate::web::management) use load::LOAD_CLIENT_FOR_UPDATE_SQL;
