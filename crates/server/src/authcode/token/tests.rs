#![allow(clippy::match_wildcard_for_single_variants)]

include!("tests/common.rs");
mod jwt_access;
include!("tests/runtime_ttls.rs");
include!("tests/oidc_claims.rs");
include!("tests/basic_flow.rs");
include!("tests/resource_audience.rs");
include!("tests/jwt_bearer.rs");
include!("tests/oidc_id_token.rs");
include!("tests/token_exchange.rs");
