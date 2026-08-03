mod authorization_server;
mod client_auth;
mod protected_resource;
mod request_object;
mod runtime_config;

pub use authorization_server::{
    validate_public_base_url, AuthorizationServerMetadata, MtlsEndpointAliases,
};
pub(crate) use client_auth::{advertised_client_auth_methods, alg_allowed_with_promoted_rsa};
pub use protected_resource::ProtectedResourceMetadata;
pub(crate) use request_object::advertised_request_object_signing_algs;
pub use runtime_config::MetadataRuntimeConfig;

#[cfg(test)]
mod tests;
