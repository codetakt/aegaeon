mod get;
mod list;

pub(in crate::web::management::topology) use get::get_tenant;
pub(in crate::web::management) use get::get_tenant_inner;
pub(in crate::web::management::topology) use list::list_tenants;
