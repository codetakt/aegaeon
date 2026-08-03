// DPoP verification uses `ffi::verify_dpop` which is hardcoded to EdDSA
// (Ed25519 via HACL*/EverCrypt). This is inherently within the verified
// crypto allowlist — no CryptoProfile check is needed.
#[cfg(not(test))]
use ffi::verify_dpop_with_iat_window;

#[cfg(test)]
use crate::test_utils::mock_dpop::verify_dpop_with_iat_window;
use crate::util::{self, compute_dpop_jkt_from_proof_with_max_len};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header::AUTHORIZATION, Method, Request, Uri};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use super::replay_store::InMemoryReplayStore;
use super::replay_store::{
    replay_key_material, RedisReplayStore, ReplayEntry, ReplayStore, ReplayStoreError,
};
use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};

mod nonce;
pub use nonce::DpopNonceStore;

#[cfg(test)]
const DEFAULT_REPLAY_TTL_SECS: u64 = 360; // 5 minutes + 60s skew
const DEFAULT_IAT_WINDOW_SECS: u64 = 300;
pub const DPOP_HEADER: &str = "DPoP";

/// Expose the production DPoP `typ` predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_dpop_typ_for_spec_oracle(typ: &str) -> bool {
    ffi::validate_dpop_typ(typ)
}

/// Sender binding derived from a verified `DPoP` proof (RFC 9449).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpopBinding {
    pub jkt: String,
}

/// Errors that can arise while processing a `DPoP` proof.
#[derive(Debug)]
pub enum DpopError {
    /// The request lacked a `DPoP` header.
    MissingProof,
    /// The `DPoP` header could not be parsed or failed verification.
    InvalidProof,
    /// The `jti` in the proof was observed previously.
    Replay,
    /// The replay store backend was unavailable; the request must fail closed.
    BackendUnavailable(String),
    /// The proof requires a server-issued nonce; carries the fresh nonce value.
    UseDpopNonce(String),
}

impl PartialEq for DpopError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MissingProof, Self::MissingProof)
            | (Self::InvalidProof, Self::InvalidProof)
            | (Self::Replay, Self::Replay) => true,
            (Self::BackendUnavailable(a), Self::BackendUnavailable(b))
            | (Self::UseDpopNonce(a), Self::UseDpopNonce(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for DpopError {}

// ---------------------------------------------------------------------------
// DPoP Middleware
// ---------------------------------------------------------------------------

/// Middleware that validates incoming `DPoP` proofs.
pub struct DpopMiddleware {
    replay_store: Arc<dyn ReplayStore>,
    namespace: Arc<str>,
    replay_ttl: Duration,
    iat_window_secs: u64,
    jose_header_max_len: usize,
    origin: Arc<str>,
    nonce_store: Option<Arc<DpopNonceStore>>,
}

impl Clone for DpopMiddleware {
    fn clone(&self) -> Self {
        Self {
            replay_store: Arc::clone(&self.replay_store),
            namespace: Arc::clone(&self.namespace),
            replay_ttl: self.replay_ttl,
            iat_window_secs: self.iat_window_secs,
            jose_header_max_len: self.jose_header_max_len,
            origin: Arc::clone(&self.origin),
            nonce_store: self.nonce_store.clone(),
        }
    }
}

impl DpopMiddleware {
    /// Construct a new middleware instance.
    pub(crate) fn new(
        namespace: impl Into<String>,
        origin: impl Into<String>,
        replay_store: Arc<dyn ReplayStore>,
        replay_ttl: Duration,
    ) -> Self {
        let namespace = namespace.into();
        let origin = origin.into();
        Self {
            replay_store,
            namespace: Arc::from(namespace.into_boxed_str()),
            replay_ttl,
            iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            origin: Arc::from(origin.trim_end_matches('/').to_string().into_boxed_str()),
            nonce_store: None,
        }
    }

    /// Construct a middleware instance over the supported shared Redis replay store.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the DPoP replay Redis URL is missing, malformed,
    /// or cannot initialize a Redis replay backend.
    pub fn try_from_shared_store_env(
        namespace: impl Into<String>,
        origin: impl Into<String>,
        replay_ttl: Duration,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url = require_shared_runtime_store_url("DPoP replay store", "AEGAEON_DPOP_REDIS_URL")?;
        let store = RedisReplayStore::new(url.as_str(), runtime_state_namespace, "dpop-replay")
            .map_err(|err| ConfigError::InvalidValue {
                key: url.env_key().to_string(),
                value: "[redacted]".to_string(),
                reason: err.to_string(),
            })?;
        tracing::info!("DPoP replay store backend: redis ({})", url.env_key());
        Ok(Self::new(namespace, origin, Arc::new(store), replay_ttl))
    }

    /// Construct a process-local middleware for unit tests, fuzzing, and model harnesses.
    ///
    /// Production code must use [`Self::try_from_shared_store_env`] so the replay store is the
    /// supported shared Redis runtime boundary.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new(
            "default",
            "http://localhost",
            Arc::new(InMemoryReplayStore::new()),
            Duration::from_secs(DEFAULT_REPLAY_TTL_SECS),
        )
    }

    /// Apply the operator-selected `iat` acceptance window in seconds.
    #[must_use]
    pub fn with_iat_window_secs(mut self, iat_window_secs: u64) -> Self {
        self.iat_window_secs = iat_window_secs;
        self
    }

    /// Apply the DB-managed JOSE protected-header length bound for DPoP header admission.
    #[must_use]
    pub fn with_jose_header_max_len(mut self, jose_header_max_len: usize) -> Self {
        self.jose_header_max_len = jose_header_max_len;
        self
    }

    /// Enable `DPoP` nonce enforcement (RFC 9449 Section 5).
    #[must_use]
    pub fn with_nonce_store(mut self, store: Arc<DpopNonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// Return the current `DPoP` nonce if a nonce store is configured.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::BackendUnavailable`] when the configured nonce
    /// store cannot retain the challenge value for later validation.
    pub fn current_nonce(&self) -> Result<Option<String>, DpopError> {
        self.nonce_store
            .as_ref()
            .map(|store| store.get_current_nonce())
            .transpose()
    }

    fn map_store_error(err: ReplayStoreError) -> DpopError {
        match err {
            ReplayStoreError::Replay => DpopError::Replay,
            ReplayStoreError::BackendUnavailable(msg) => DpopError::BackendUnavailable(msg),
            ReplayStoreError::RetentionOverflow => {
                DpopError::BackendUnavailable("replay entry ttl cannot be represented".to_string())
            }
        }
    }

    fn replay_material(jti: &str, jkt: &str) -> Vec<u8> {
        replay_key_material(&[jkt.as_bytes(), jti.as_bytes()])
    }

    /// Exposed helper used by tests to exercise the replay store.
    ///
    /// # Errors
    ///
    /// Returns an error if the JTI has already been observed or if the replay
    /// store backend is unavailable.
    #[cfg(test)]
    pub fn check_and_store_jti(&self, jti: &str) -> Result<(), DpopError> {
        let material = Self::replay_material(jti, "test-jkt");
        let entry = ReplayEntry::new(&self.namespace, &material, self.replay_ttl);
        self.replay_store
            .check_and_store(entry)
            .map_err(Self::map_store_error)
    }

    fn verify_internal<B>(&self, req: &Request<B>) -> Result<DpopBinding, DpopError> {
        let proof = util::single_header_str(req.headers(), DPOP_HEADER)
            .map_err(|_| DpopError::InvalidProof)?
            .ok_or(DpopError::MissingProof)?;
        let auth = util::single_header_str(req.headers(), AUTHORIZATION.as_str())
            .map_err(|_| DpopError::InvalidProof)?;
        self.verify_components(req.method(), req.uri(), proof, auth)
    }

    /// Verify the `DPoP` header on an incoming request without mutating extensions.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is missing a `DPoP` proof, the proof
    /// fails validation, replay detection fails closed, or a fresh nonce is
    /// required by policy.
    pub fn verify<B>(&self, req: &Request<B>) -> Result<(), DpopError> {
        self.verify_internal(req).map(|_| ())
    }

    /// Verify the request and attach the derived sender-binding (JKT) to extensions.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::verify`].
    pub fn verify_and_attach<B>(&self, req: &mut Request<B>) -> Result<(), DpopError> {
        let binding = self.verify_internal(req)?;
        req.extensions_mut().insert(binding);
        Ok(())
    }

    /// Verify `DPoP` header components (method/path/proof/auth) and derive sender binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the proof does not match the request, replay
    /// detection fails closed, or nonce policy requires a fresh server nonce.
    pub fn verify_components(
        &self,
        method: &Method,
        uri: &Uri,
        proof: &str,
        authorization: Option<&str>,
    ) -> Result<DpopBinding, DpopError> {
        let jkt = compute_dpop_jkt_from_proof_with_max_len(proof, self.jose_header_max_len)
            .ok_or(DpopError::InvalidProof)?;
        let method_upper = method.as_str().to_ascii_uppercase();
        let uri_string = expected_htu(&self.origin, uri.path());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DpopError::InvalidProof)?
            .as_secs();

        let expected_ath = authorization
            .and_then(extract_access_token)
            .map(compute_ath);

        let verified_proof = verify_dpop_with_iat_window(
            proof,
            &method_upper,
            &uri_string,
            now,
            expected_ath.as_deref(),
            self.iat_window_secs,
        )
        .ok_or(DpopError::InvalidProof)?;

        // RFC 9449 Section 5: validate nonce if the server requires it.
        if let Some(ref store) = self.nonce_store {
            let nonce_valid = match verified_proof.nonce.as_deref() {
                Some(nonce) => store.try_validate_nonce(nonce)?,
                None => false,
            };
            if !nonce_valid {
                // Nonce missing or invalid — tell client to use a fresh one.
                return Err(DpopError::UseDpopNonce(store.try_get_current_nonce()?));
            }
        }

        let material = Self::replay_material(&verified_proof.jti, &jkt);
        let entry = ReplayEntry::new(&self.namespace, &material, self.replay_ttl);
        self.replay_store
            .check_and_store(entry)
            .map_err(Self::map_store_error)?;

        Ok(DpopBinding { jkt })
    }
}

fn expected_htu(origin: &str, path: &str) -> String {
    // RFC 9449: htu is the target URI without query and fragment parts.
    // We reconstruct a canonical absolute target URI based on configured origin and request path.
    if path.starts_with('/') {
        format!("{origin}{path}")
    } else {
        format!("{origin}/{path}")
    }
}

fn extract_access_token(header: &str) -> Option<&str> {
    let mut parts = header.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower == "dpop" || scheme_lower == "bearer" {
        Some(token)
    } else {
        None
    }
}

fn compute_ath(token: &str) -> String {
    let digest = aegaeon_crypto::hash::sha256_digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Expose the production DPoP `ath` predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_dpop_ath_for_spec_oracle(token: &str, claim: &str) -> bool {
    compute_ath(token) == claim
}

#[cfg(test)]
mod tests;
