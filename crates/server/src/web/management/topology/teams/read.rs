mod get;
mod list;

pub(in crate::web::management::topology) use get::get_team;
pub(in crate::web::management) use get::get_team_inner;
pub(in crate::web::management::topology) use list::list_teams;
