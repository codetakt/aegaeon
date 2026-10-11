//! Real loopback token exchanges and signed Federation acquisition. No database
//! operations, external provider, TLS/SSRF override, or lifecycle bypass is claimed.
use super::*;
use crate::federation::{
    EntityStatement, FederationError, ResolvedTrustChain, TrustAnchor, TrustChain,
};
use crate::kms::{FederationKeyManager, InMemoryKeyManager};
use crate::oidc::OidcDiscovery;
use crate::upstream::{UpstreamAuthRequest, UpstreamConnectionContext};
use crate::web::upstream_authorize::{
    context::UpstreamAuthorizeContext, input::UpstreamAuthorizeInput,
};
use crate::web::upstream_callback_exchange::perform_upstream_callback_exchange_with;
use crate::web::upstream_refresh::{
    exchange::perform_upstream_refresh_exchange_with, validate_upstream_refresh_exchange,
};
use crate::web::upstream_refresh_links::UpstreamRefreshLink;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

mod harness;
use harness::*;
mod authorize;
mod callback;
mod inline_jwks;
mod refresh;

fn run(future: impl std::future::Future<Output = ManagementTestResult>) -> ManagementTestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

fn response_error(response: axum::response::Response) -> Box<dyn std::error::Error> {
    std::io::Error::other(format!("unexpected response {}", response.status())).into()
}

fn fail_acquisition(
    _: Vec<TrustAnchor>,
    _: i64,
) -> std::future::Ready<Result<ResolvedTrustChain, FederationError>> {
    std::future::ready(Err(FederationError::Fetch(
        "unexpected fresh acquisition".into(),
    )))
}
