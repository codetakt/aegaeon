mod document;
mod policy;

pub(in crate::web::management) use document::validate_configuration_document_federation;
pub(in crate::web::management) use policy::validate_federation_policy_for_environment;
