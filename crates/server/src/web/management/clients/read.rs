mod get;
mod list;

pub(super) use get::get_client;
pub(in crate::web::management) use get::get_client_inner;
pub(super) use list::list_clients;
