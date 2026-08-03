mod defaults;
mod insert;
mod update;

pub(in crate::web::management) use defaults::clear_default_oauth_profiles;
pub(in crate::web::management) use insert::insert_oauth_profile_row;
pub(in crate::web::management) use update::update_oauth_profile_row;
