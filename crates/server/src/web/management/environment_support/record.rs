mod locked;
mod mapper;
mod read;

pub(in crate::web::management) use locked::load_management_environment_record_for_update;
pub(in crate::web::management) use read::load_management_environment_record;
