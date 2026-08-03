#[cfg(feature = "kms-aws")]
pub(crate) mod aws_kms_signer;
pub mod config;
pub mod discovery;
pub mod id_token;
pub(crate) mod required_rs256;
pub mod session;
pub mod userinfo;

pub use config::{OidcConfig, OidcConfigError, OidcSigningError, OidcSigningKey};
pub use discovery::OidcDiscovery;
pub use id_token::{Audience, IdToken, IdTokenBuilder, IdTokenClaims, IdTokenValidationContext};
pub use session::{OidcLogoutEvent, OidcSessionContext, OidcSessionStore};
pub(crate) use session::{OidcSessionGrantCommit, RedisOidcSessionGrantCommit};
pub use userinfo::{filter_claims_by_scope, Address, Userinfo, UserinfoEndpoint};
#[cfg(test)]
pub use userinfo::{InMemoryUserProvider, SubjectOnlyUserProvider};
