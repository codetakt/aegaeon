mod activate;
mod revoke;
mod scope;

pub(in crate::web::management) use activate::activate_next_runtime_key_inner;
pub(in crate::web::management) use revoke::revoke_runtime_key_inner;
