use aegaeon_jose::jwk::{Jwk, JwkSet};

use super::unix_epoch_now_i64;

#[derive(Clone, Debug)]
pub struct RegisteredClientJwks {
    set: JwkSet,
    value: serde_json::Value,
}

impl RegisteredClientJwks {
    /// Parse and validate an inline client JWKS admitted through DCR.
    ///
    /// # Errors
    ///
    /// Returns an error when the JWKS is malformed, has duplicate `kid` values,
    /// omits a required `kid`, or contains no signature-capable key.
    pub fn from_value(value: serde_json::Value, require_kid: bool) -> Result<Self, String> {
        let set =
            JwkSet::from_value(value.clone()).map_err(|err| format!("invalid jwks: {err}"))?;
        set.ensure_unique_kid()
            .map_err(|err| format!("duplicate kid: {err}"))?;
        if require_kid {
            set.ensure_all_have_kid()
                .map_err(|_| "private_key_jwt requires jwks with kid".to_string())?;
        }
        if set.signature_keys().next().is_none() {
            return Err("jwks must include signature-capable keys".to_string());
        }
        Ok(Self { set, value })
    }

    #[must_use]
    pub fn as_value(&self) -> &serde_json::Value {
        &self.value
    }

    pub(super) fn select(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self
                .set
                .keys()
                .iter()
                .find(|jwk| jwk.kid() == Some(kid) && jwk.is_signature_capable()),
            None => {
                let mut keys = self.set.signature_keys();
                let key = keys.next()?;
                keys.next().is_none().then_some(key)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub token_endpoint_auth_method: String, // e.g., client_secret_basic, client_secret_post
    pub jwks_pem: Option<String>,           // Public key PEM for private_key_jwt
    pub inline_jwks: Option<RegisteredClientJwks>, // Inline JWKS for private_key_jwt
    pub jwks_uri: Option<String>,           // JWKS URI for private_key_jwt
    pub token_endpoint_auth_signing_alg: Option<String>, // Per-client client assertion alg
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<String>, // e.g., authorization_code, refresh_token, client_credentials
    /// RFC 7592: Bearer token for client configuration management (read/update/delete).
    pub registration_access_token: Option<String>,
    /// RFC 7591 §3.2.1: Timestamp of when the client was registered (epoch seconds).
    pub client_id_issued_at: Option<u64>,
}

impl RegisteredClient {
    #[must_use]
    #[cfg(test)]
    pub fn to_par_client(&self) -> crate::par::Client {
        crate::par::Client {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            redirect_uris: self.redirect_uris.clone(),
            allowed_scopes: self.allowed_scopes.clone(),
        }
    }
}

pub(super) fn select_registration_token_match<'a>(
    clients: impl IntoIterator<Item = &'a RegisteredClient>,
    token: &str,
) -> Option<RegisteredClient> {
    clients.into_iter().fold(None, |matched, client| {
        let is_match = client
            .registration_access_token
            .as_deref()
            .is_some_and(|rat| crate::util::constant_time_eq(rat.as_bytes(), token.as_bytes()));
        if is_match {
            Some(client.clone())
        } else {
            matched
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSecretCredential {
    secret_hash: String,
    expires_at_epoch_secs: i64,
}

impl ClientSecretCredential {
    #[must_use]
    pub fn new(secret_hash: String, expires_at_epoch_secs: i64) -> Self {
        Self {
            secret_hash,
            expires_at_epoch_secs,
        }
    }

    #[must_use]
    pub fn is_active_at(&self, now_epoch_secs: i64) -> bool {
        self.expires_at_epoch_secs > now_epoch_secs
    }

    #[must_use]
    fn verify_at(&self, provided_secret: &str, now_epoch_secs: i64) -> bool {
        self.is_active_at(now_epoch_secs)
            && crate::local_credentials::verify_password(provided_secret, &self.secret_hash)
    }
}

#[must_use]
pub fn verify_client_secret_credentials(
    provided_secret: &str,
    credentials: &[ClientSecretCredential],
) -> bool {
    let Some(now_epoch_secs) = unix_epoch_now_i64("client secret credential validation clock")
    else {
        return false;
    };
    credentials.iter().fold(false, |matched, credential| {
        credential.verify_at(provided_secret, now_epoch_secs) | matched
    })
}

#[must_use]
pub(crate) fn verify_client_secret_material(
    plaintext_secret: Option<&str>,
    credentials: &[ClientSecretCredential],
    provided_secret: &str,
) -> bool {
    let plaintext_match = plaintext_secret.is_some_and(|secret| {
        crate::util::constant_time_eq(secret.as_bytes(), provided_secret.as_bytes())
    });
    let credential_match = verify_client_secret_credentials(provided_secret, credentials);
    verify_dummy_client_secret(provided_secret);
    plaintext_match | credential_match
}

fn dummy_client_secret_hash() -> Option<&'static str> {
    static DUMMY_HASH: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
        crate::local_credentials::hash_password("aegaeon-client-secret-dummy-verifier").ok()
    });
    DUMMY_HASH.as_deref()
}

pub(super) fn verify_dummy_client_secret(provided_secret: &str) {
    let _ = dummy_client_secret_hash()
        .is_some_and(|hash| crate::local_credentials::verify_password(provided_secret, hash));
}
