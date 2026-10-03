//! Explicit, frozen suppliers for private OAuth load tests.
use anyhow::{bail, ensure, Context, Result};
use reqwest::{header::HeaderValue, Url};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SenderPolicy {
    None,
    Dpop,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParPolicy {
    Optional,
    Required,
}

/// Nonsecret receipt supplied by the producer of the activated runtime profile.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSupply {
    pub issuer: String,
    pub environment_id: String,
    pub configuration_version_id: String,
    pub oauth_profile_id: String,
    pub activation: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub client_auth: ClientAuth,
    pub scope: String,
    pub oidc_scope: Option<String>,
    pub subject: String,
    pub sender_policy: SenderPolicy,
    pub par_policy: ParPolicy,
    pub resource: Option<String>,
    pub id_token_alg: Option<String>,
}

/// Private receipt linking a genuine public-login session to its producer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSupply {
    issuer: String,
    subject: String,
    method: String,
    producer: String,
    profile_sha256: String,
    session_sha256: String,
}

#[derive(Clone)]
pub struct ClientProfile {
    pub supply: ProfileSupply,
    pub secret: String,
    pub session_cookie: HeaderValue,
    pub profile_sha256: String,
    pub session_provenance_sha256: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

pub fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("required input {name} is missing"))?;
    ensure!(!value.trim().is_empty(), "required input {name} is empty");
    Ok(value)
}

pub fn issuer_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid issuer URL")?;
    ensure!(
        url.scheme() == "https" && url.host_str().is_some(),
        "issuer must use HTTPS"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid issuer URL components"
    );
    ensure!(
        !value.ends_with('/'),
        "issuer input must be exact and have no trailing slash"
    );
    Ok(url)
}

pub fn scopes(value: &str) -> Result<BTreeSet<&str>> {
    ensure!(!value.is_empty(), "scope must be nonempty");
    let mut result = BTreeSet::new();
    for token in value.split(' ') {
        ensure!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|c| c == 0x21 || (0x23..=0x5b).contains(&c) || (0x5d..=0x7e).contains(&c)),
            "invalid OAuth scope syntax"
        );
        ensure!(result.insert(token), "duplicate OAuth scope");
    }
    Ok(result)
}

impl ProfileSupply {
    pub fn validate(&self, target: &str, needs_oidc: bool, needs_dpop: bool) -> Result<()> {
        issuer_url(&self.issuer)?;
        ensure!(
            self.issuer == target,
            "target must equal the exact declared issuer"
        );
        for value in [
            &self.environment_id,
            &self.configuration_version_id,
            &self.oauth_profile_id,
            &self.client_id,
            &self.subject,
        ] {
            ensure!(
                !value.trim().is_empty(),
                "activated profile has a missing identity"
            );
        }
        ensure!(
            self.activation == "ACTIVE",
            "profile supplier must identify an ACTIVE configuration"
        );
        let redirect = Url::parse(&self.redirect_uri).context("invalid registered redirect URI")?;
        ensure!(
            redirect.scheme() == "https"
                && redirect.host_str().is_some()
                && redirect.username().is_empty()
                && redirect.password().is_none()
                && redirect.fragment().is_none(),
            "registered redirect must be HTTPS without credentials or fragment"
        );
        for (name, _) in redirect.query_pairs() {
            ensure!(
                ![
                    "state",
                    "iss",
                    "code",
                    "error",
                    "error_description",
                    "error_uri"
                ]
                .contains(&name.as_ref()),
                "registered static query conflicts with authorization response fields"
            );
        }
        scopes(&self.scope)?;
        if needs_dpop {
            ensure!(
                self.sender_policy == SenderPolicy::Dpop,
                "selected scenario requires declared DPoP policy"
            );
        }
        if let Some(resource) = &self.resource {
            let url = Url::parse(resource).context("invalid resource indicator")?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "invalid HTTPS resource indicator"
            );
        }
        let scope_oidc = scopes(&self.scope)?.contains("openid");
        if needs_oidc {
            let scope = self
                .oidc_scope
                .as_deref()
                .context("selected scenario requires explicit oidc_scope")?;
            ensure!(
                scopes(scope)?.contains("openid"),
                "oidc_scope must contain openid"
            );
            // This selection consumes the issuer UserInfo audience, independently of an OAuth resource.
        }
        if needs_oidc || scope_oidc {
            ensure!(
                self.id_token_alg.as_deref() == Some("RS256"),
                "only explicitly approved RS256 ID Tokens are supported"
            );
        }
        Ok(())
    }
}

impl ClientProfile {
    pub fn from_env(target: &str, needs_oidc: bool, needs_dpop: bool) -> Result<Self> {
        let bytes = fs::read(required_env("AEG_LOADTEST_PROFILE_MANIFEST")?)
            .context("cannot read activated profile manifest")?;
        let supply: ProfileSupply =
            serde_json::from_slice(&bytes).context("invalid activated profile manifest")?;
        supply.validate(target, needs_oidc, needs_dpop)?;
        let profile_sha256 = sha256(&bytes);
        let secret = required_env("AEG_LOADTEST_CLIENT_SECRET")?;
        let session = fs::read(required_env("AEG_LOADTEST_SESSION_FILE")?)
            .context("cannot read issuer session file")?;
        let session = std::str::from_utf8(&session)
            .context("issuer session is not UTF-8")?
            .trim_end_matches('\n');
        let value = session
            .strip_prefix("aegaeon_auth_session=")
            .context("session file must contain only aegaeon_auth_session=<value>")?;
        ensure!(
            !value.is_empty()
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
            "invalid issuer session cookie value"
        );
        let mut session_cookie =
            HeaderValue::from_str(session).context("invalid issuer session header")?;
        session_cookie.set_sensitive(true);
        let provenance = fs::read(required_env("AEG_LOADTEST_SESSION_PROVENANCE")?)
            .context("cannot read public-login provenance")?;
        let receipt: SessionSupply =
            serde_json::from_slice(&provenance).context("invalid public-login provenance")?;
        ensure!(
            receipt.issuer == supply.issuer
                && receipt.subject == supply.subject
                && receipt.method == "public-login"
                && !receipt.producer.trim().is_empty()
                && receipt.profile_sha256 == profile_sha256
                && receipt.session_sha256 == sha256(session.as_bytes()),
            "public-login receipt does not bind the supplied issuer/session/profile/subject"
        );
        if std::env::var_os("AEG_LOADTEST_PROOF_ORIGIN").is_some()
            || std::env::var_os("AEG_LOADTEST_PUBLIC_ORIGIN").is_some()
            || std::env::var_os("AEG_LOADTEST_CLIENT_SECRET_POST").is_some()
        {
            bail!("legacy origin/auth overrides are unsupported; use the exact activated profile");
        }
        Ok(Self {
            supply,
            secret,
            session_cookie,
            profile_sha256,
            session_provenance_sha256: sha256(&provenance),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_profile_rejects_unsafe_or_unactivated_inputs() {
        let mut supply: ProfileSupply = serde_json::from_value(serde_json::json!({
            "issuer":"https://issuer.example.test", "environment_id":"environment", "configuration_version_id":"version",
            "oauth_profile_id":"profile", "activation":"ACTIVE", "client_id":"registered-client",
            "redirect_uri":"https://client.example.test/callback?fixed=1", "client_auth":"client_secret_post",
            "scope":"read offline_access", "oidc_scope":"openid", "subject":"current-subject",
            "sender_policy":"dpop", "par_policy":"required", "resource":null, "id_token_alg":"RS256"
        })).unwrap();
        assert!(supply
            .validate("https://issuer.example.test", true, true)
            .is_ok());
        supply.activation = "DRAFT".into();
        assert!(supply
            .validate("https://issuer.example.test", true, true)
            .is_err());
        supply.activation = "ACTIVE".into();
        for redirect in [
            "http://client.example.test/callback",
            "https://client.example.test/callback?state=static",
            "https://user@client.example.test/callback",
            "https://client.example.test/callback#fragment",
        ] {
            supply.redirect_uri = redirect.into();
            assert!(supply
                .validate("https://issuer.example.test", true, true)
                .is_err());
        }
        assert!(scopes("read  write").is_err());
        assert!(scopes("read read").is_err());
        assert!(scopes("read\twrite").is_err());
    }
}
