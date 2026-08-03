mod action;
mod presence;

pub(in crate::web::management) use action::apply_connection_client_secret_action;
pub(in crate::web::management) use presence::connection_client_secret_present;
