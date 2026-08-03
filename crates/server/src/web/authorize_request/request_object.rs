mod claims;
mod error;
mod replay;
mod resolution;
mod types;

pub(in crate::web) use claims::request_object_extra_string;
pub(in crate::web) use error::{
    request_object_resolution_error_json_response, request_object_resolution_error_response,
};
#[cfg(test)]
pub(in crate::web) use replay::enforce_request_object_jti;
pub(in crate::web) use replay::request_object_jti_authorization_code_commit_context;
#[cfg(test)]
pub(in crate::web) use replay::request_object_jti_retention;
pub(in crate::web) use resolution::{
    resolve_authorize_request_object, resolve_authorize_request_object_blocking,
};
pub(in crate::web) use types::{
    OwnedRequestObjectAuthorizeDeps, RequestObjectAuthorizeDeps, RequestObjectReplayPolicy,
    ResolvedAuthorizeRequestObject,
};
