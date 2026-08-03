mod create;
mod delete;
mod update;

pub(in crate::web::management::topology) use create::create_team;
pub(in crate::web::management::topology) use delete::delete_team;
pub(in crate::web::management::topology) use update::update_team;
