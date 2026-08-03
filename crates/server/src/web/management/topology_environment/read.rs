mod get;
mod list;

pub(in crate::web::management) use get::get_environment;
pub(in crate::web::management) use get::get_environment_inner;
pub(in crate::web::management) use list::list_environments;
