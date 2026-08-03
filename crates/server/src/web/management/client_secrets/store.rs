mod issue;
mod read;
mod revoke;

pub(super) use issue::insert_client_secret_row;
pub(super) use read::list_client_secret_rows;
pub(super) use revoke::{revoke_all_client_secrets_rows, revoke_client_secret_row};

#[cfg(test)]
pub(in crate::web::management) use read::LIST_CLIENT_SECRET_ROWS_SQL;
#[cfg(test)]
pub(in crate::web::management) use revoke::{
    REVOKE_ALL_CLIENT_SECRETS_ROWS_SQL, REVOKE_CLIENT_SECRET_ROW_SQL,
};
