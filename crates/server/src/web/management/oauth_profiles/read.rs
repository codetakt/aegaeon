mod get;
mod list;

pub(super) use get::get_oauth_profile;
pub(in crate::web::management) use get::get_oauth_profile_inner;
pub(super) use list::list_oauth_profiles;
