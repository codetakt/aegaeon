use super::*;
use crate::config::ConfigError;
use std::error::Error as StdError;
use std::io;

mod core;
mod mtls;
mod private_key_jwt;
mod resource;
mod runtime_snapshot;

type TestResult = Result<(), Box<dyn StdError>>;

fn secure_metadata(base_url: &str) -> AuthorizationServerMetadata {
    AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        base_url,
        &MetadataRuntimeConfig::default(),
    )
    .expect("test metadata base URL is valid")
}

fn runtime_with_dcr_enabled() -> MetadataRuntimeConfig {
    MetadataRuntimeConfig {
        dcr_enabled: true,
        ..MetadataRuntimeConfig::default()
    }
}

fn secure_metadata_with_runtime(
    base_url: &str,
    runtime: &MetadataRuntimeConfig,
) -> Result<AuthorizationServerMetadata, crate::config::ConfigError> {
    AuthorizationServerMetadata::try_new_secure_with_runtime_config(base_url, runtime)
}
