mod model;
mod normalization;
mod resolution;

pub use model::{ProfileError, ResolvedProfile};
pub(crate) use normalization::{merge_sender_constraints, normalize_response_type};
pub use resolution::{
    resolve_default_profile, resolve_downstream_profile, resolve_upstream_profile,
};
