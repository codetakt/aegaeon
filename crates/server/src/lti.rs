//! LTI Platform capability, separate from ordinary client grants.
pub mod claims;
pub(crate) mod intents;
pub mod model;
pub mod request;
pub mod store;
mod validation;

pub use validation::{validate_configuration, validate_transition};

#[derive(Debug, thiserror::Error)]
pub enum LtiError {
    #[error("invalid LTI configuration or request")]
    Invalid,
    #[error("LTI authority does not permit this operation")]
    Denied,
    #[error("LTI revision changed")]
    Conflict,
    #[error("LTI launch admission limit reached")]
    Capacity,
    #[error("LTI dependency unavailable")]
    Unavailable,
    #[error("LTI mapping failed")]
    Mapping(#[from] aegaeon_attribute_mapping::MappingError),
    #[error("LTI storage operation failed")]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests;
