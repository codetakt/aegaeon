mod create;
mod delete;
mod read;
mod update;

pub(super) use create::create_tenant;
pub(super) use delete::delete_tenant;
pub(in crate::web::management) use read::get_tenant_inner;
pub(super) use read::{get_tenant, list_tenants};
pub(super) use update::update_tenant;
