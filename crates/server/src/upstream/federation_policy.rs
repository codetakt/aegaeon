mod attribute_mapping;
mod attribute_projection;
mod claim_release;
mod domain;
mod jit;
mod logout;

pub use self::attribute_mapping::parse_upstream_attribute_mappings;
pub use self::attribute_projection::{
    merge_upstream_custom_claims, project_upstream_attribute_mappings,
};
pub use self::claim_release::{
    filter_downstream_custom_claims, parse_upstream_claim_release_policy,
};
pub use self::domain::{email_allowed_by_domain_allowlist, extract_email_domain};
pub use self::jit::parse_upstream_jit_provisioning_policy;
pub use self::logout::parse_upstream_logout_policy;
