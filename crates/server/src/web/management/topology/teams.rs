mod mutation;
mod read;
mod support;

pub(super) use mutation::{create_team, delete_team, update_team};
pub(in crate::web::management) use read::get_team_inner;
pub(super) use read::{get_team, list_teams};
