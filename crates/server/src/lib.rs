#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(deprecated))]
#![allow(clippy::multiple_crate_versions)]
// The server pulls multiple ecosystem stacks (Axum, sqlx, crypto, OpenTelemetry)
// that currently depend on divergent support-crate versions. We allow this
// narrowly at the crate boundary until the dependency graph converges.
pub(crate) mod audit_safety;
pub mod authcode;
pub mod bcp_policy;
pub mod client_registry;
pub mod config;
pub mod db;
pub mod dcr;
pub mod dcr_persistence;
pub mod device_authz;
pub mod end_user_profiles;
pub mod federation;
pub mod form_post;
pub mod jwk_types;
pub mod management;
pub mod metadata;
pub mod middleware;
pub mod oauth_profile;
pub(crate) mod oauth_scope;
pub mod oidc;
#[cfg(feature = "openapi")]
pub mod openapi;
pub mod outbound_http;
pub mod par;
pub mod request_object;
pub mod request_object_store;
pub mod resource_audience;
pub mod runtime_authority;
pub(crate) mod runtime_authority_queries;
pub mod runtime_clients;
pub mod runtime_configuration;
pub mod runtime_fatal;
pub mod runtime_keys;
pub mod runtime_restart;
pub mod stepup;
pub mod upstream;
pub mod util;
pub mod web;

pub mod key_encryption;
#[cfg(test)]
pub mod key_rotation;
pub mod kms;
pub mod local_credentials;
pub mod metrics_integration;
pub mod metrics_support;
pub mod policy;
pub mod ssrf;
#[cfg(test)]
mod test_utils;

#[cfg(kani)]
mod kani_test;

#[cfg(test)]
mod rfc_tests;

/// Install the process-wide rustls crypto provider used by TLS clients.
pub fn install_rustls_crypto_provider() {
    aegaeon_crypto::tls::install_rustls_crypto_provider();
}
