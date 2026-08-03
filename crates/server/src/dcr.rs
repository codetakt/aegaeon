mod everparse;
mod registration;
mod software_statement;
mod validation;

pub use everparse::{everparse_self_check_registration_with_runtime, DcrEverparseSelfCheckError};
pub use registration::{
    empty_client_registration, parse_client_registration, ClientRegistration,
    ClientRegistrationParseError,
};
pub use software_statement::{
    software_statement_profile_redirect_uris, software_statement_redirect_uris,
    validate_software_statement_metadata_consistency,
    verify_software_statement_profile_v1_with_config, SoftwareStatementProfileV1,
    SoftwareStatementVerificationError,
};
pub(crate) use validation::{
    runtime_supported_sender_constrained_method, RUNTIME_SUPPORTED_DCR_SENDER_METHODS,
};
pub use validation::{
    validate_redirect_uris, validate_registration, validate_registration_with_config,
    DcrValidationConfig, SoftwareStatementValidationConfig,
};

pub(crate) use crate::policy::{JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};

#[cfg(test)]
mod tests;
