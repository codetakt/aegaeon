mod admission;
mod auth;
mod delete;
mod read;
#[cfg(test)]
mod tests;
mod update;

pub(super) use delete::register_delete;
pub(super) use read::register_read;
pub(super) use update::register_update;
