mod create;
mod types;
mod update;

pub(in crate::web::management) use create::oauth_profile_input_from_create;
pub(in crate::web::management) use types::OAuthProfileInput;
pub(in crate::web::management) use update::oauth_profile_input_from_update;
