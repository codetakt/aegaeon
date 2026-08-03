mod activate;
mod insert;
mod number;

pub(in crate::web::management) use activate::switch_active_configuration_version;
pub(in crate::web::management) use insert::insert_configuration_version_row;
pub(in crate::web::management) use number::load_next_configuration_version_number;
