//! Versioned attributes for already resolved local user identities.
//! Management authority, source authentication and protocol disclosure are separate.
mod store;

pub use store::{
    load_attribute_sources, replace_local_attributes, AttributeSourceRecord, AttributeStoreError,
};
