use serde_json::Value;

use crate::management::types::PolicyDocument;

#[derive(Clone, Debug)]
pub struct RuntimeConfigurationState {
    pub policy: PolicyDocument,
    pub scope_allowlist: Vec<String>,
    pub key_store: RuntimeKeyStoreConfiguration,
}

#[derive(Clone, Debug)]
pub struct RuntimeKeyStoreConfiguration {
    pub key_store_type: String,
    pub configuration: Value,
    pub redacted: bool,
}
