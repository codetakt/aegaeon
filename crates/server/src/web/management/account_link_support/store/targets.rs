mod connection;
mod user;

pub(in crate::web::management) use connection::{
    load_account_link_connection, load_account_link_connection_for_update,
};
pub(in crate::web::management) use user::{
    ensure_account_link_target_not_deleted, load_account_link_target_user_for_update,
};

#[cfg(test)]
pub(in crate::web::management) use connection::LOAD_ACCOUNT_LINK_CONNECTION_SQL;
#[cfg(test)]
pub(in crate::web::management) use user::LOAD_ACCOUNT_LINK_TARGET_USER_SQL;
