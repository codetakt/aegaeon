//! Attribute policy configuration and adapters for resolved Aegaeon identities.
//! Source authentication and account linking remain outside the mapping engine.
mod configuration;
mod output;
mod store;
pub(crate) use output::load_oidc_mapping;
pub use output::OidcMappingSnapshot;

pub use configuration::{
    AttributeDefinition, MappingConfiguration, PolicyDefinition, RecipientSelector,
    SourceDefinition,
};
pub use store::{
    load_attribute_sources, replace_local_attributes, AttributeSourceRecord, AttributeStoreError,
};

#[cfg(test)]
pub(crate) mod tests;
