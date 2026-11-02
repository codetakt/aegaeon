mod admission;
mod auth;
mod capacity;
pub(super) use capacity::registration_update_capacity;
mod delete;
mod read;
#[cfg(test)]
mod tests;
mod update;

pub(super) use delete::register_delete;
pub(super) use read::register_read;
pub(super) use update::register_update;
