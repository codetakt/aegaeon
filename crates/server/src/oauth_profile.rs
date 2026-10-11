mod model;
mod normalization;
mod resolution;

pub use model::{ProfileError, ResolvedProfile};
pub(crate) use normalization::{merge_sender_constraints, normalize_response_type};
pub use resolution::{
    resolve_default_profile, resolve_downstream_profile, resolve_upstream_profile,
};

pub(crate) use resolution::{observe_downstream_profile_in_tx, resolve_downstream_profile_in_tx};

pub(crate) use resolution::resolve_upstream_profile_in_tx;
