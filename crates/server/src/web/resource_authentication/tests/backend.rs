use super::{fixture::*, policy::accepted};
use crate::{
    kms::{KeyManager, KeyManagerError},
    web::test_support::TestResult,
};
use axum::{body::Body, http::StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::UNIX_EPOCH,
};

struct SwitchableKeys {
    key: Ed25519KeyPair,
    unavailable: AtomicBool,
    verifications: AtomicUsize,
}
impl KeyManager for SwitchableKeys {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(self.key.sign(msg).as_ref().to_vec())
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(KeyManagerError::OperationFailed);
        }
        Ok(
            UnparsedPublicKey::new(&ED25519, self.key.public_key().as_ref())
                .verify(msg, sig)
                .is_ok(),
        )
    }
    fn key_id(&self) -> String {
        "switchable-fixture".into()
    }
    fn jwt_signing_alg(&self) -> &'static str {
        "EdDSA"
    }
    fn rotate(&self) -> Result<(), KeyManagerError> {
        Err(KeyManagerError::OperationFailed)
    }
    fn revoke(&self) -> Result<(), KeyManagerError> {
        Err(KeyManagerError::OperationFailed)
    }
}

async fn stored_signed_jwt(
    fixture: &Fixture,
    keys: &SwitchableKeys,
    path: &str,
    dpop: bool,
) -> TestResult<String> {
    // Synthetic issuance through the real store; no token endpoint issuance is claimed.
    let opaque = fixture.token(path, "openid read", dpop, false).await?;
    let mut access = fixture
        .state
        .tokens
        .store
        .try_verify_access_token(&opaque)?
        .ok_or("fixture access token")?;
    let mut meta = fixture
        .state
        .tokens
        .store
        .try_get_bearer_meta(&opaque)?
        .ok_or("fixture metadata")?;
    let header = json!({"alg":keys.jwt_signing_alg(),"kid":keys.key_id(),"typ":"at+jwt"});
    let mut payload = json!({"iss":fixture.environment.issuer_url,"sub":access.user_id,"aud":meta.audience,"iat":meta.issued_at.duration_since(UNIX_EPOCH)?.as_secs(),"exp":meta.expires_at.duration_since(UNIX_EPOCH)?.as_secs(),"jti":uuid::Uuid::new_v4().to_string(),"client_id":access.client_id,"scope":access.scope});
    if let Some(cnf) = &access.cnf {
        payload["cnf"] = serde_json::to_value(cnf)?;
    }
    let signing = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    );
    let token = format!(
        "{signing}.{}",
        URL_SAFE_NO_PAD.encode(keys.sign(signing.as_bytes())?)
    );
    access.token = token.clone();
    meta.token_id = token.clone();
    fixture
        .state
        .tokens
        .store
        .store_issued_grant_async(access, None, meta)
        .await?;
    Ok(token)
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real routers and signed JWTs with instance-local verification fault"]
async fn resource_authentication_token_backend_failure_never_challenges_or_runs_before_admission(
) -> TestResult {
    let mut fixture = Fixture::new().await?;
    let keys = Arc::new(SwitchableKeys {
        key: Ed25519KeyPair::from_seed_unchecked(&[43; 32]).map_err(|_| "fixture key")?,
        unavailable: AtomicBool::new(true),
        verifications: AtomicUsize::new(0),
    });
    let validator = crate::authcode::TokenValidator::with_policy(
        fixture.state.tokens.store.as_ref().clone(),
        keys.clone(),
        crate::policy::SecurityPolicy::default()
            .with_sender_constraint(crate::policy::SenderConstraint::None),
    )
    .with_jwt_access_tokens_enabled(true)
    .with_issuer(Some(fixture.environment.issuer_url.clone()));
    fixture.state.tokens.validator = Arc::new(validator.clone());
    fixture.state.oidc.userinfo_endpoint =
        Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
            validator,
            fixture.database.pool.clone(),
            fixture.environment.issuer_url.clone(),
        )));
    let result = async {
        for (method, path) in SURFACES {
            keys.unavailable.store(true, Ordering::SeqCst);
            for auth in [
                None,
                Some("Unknown token"),
                Some("Bearer"),
                Some("DPoP token extra"),
            ] {
                let before = keys.verifications.load(Ordering::SeqCst);
                let response = request(
                    &fixture.state,
                    method,
                    path,
                    headers(auth, Some("unvalidated-proof"), method == "POST")?,
                    Body::empty(),
                )
                .await?;
                assert!(response.status().is_client_error());
                assert_eq!(keys.verifications.load(Ordering::SeqCst), before);
            }
            for scheme in ["Bearer", "DPoP"] {
                let token =
                    stored_signed_jwt(&fixture, keys.as_ref(), path, scheme == "DPoP").await?;
                let auth = format!("{scheme} {token}");
                keys.unavailable.store(true, Ordering::SeqCst);
                let proof = (scheme == "DPoP")
                    .then(|| signed_proof(method, path, Some(&token), None))
                    .transpose()?;
                let before = keys.verifications.load(Ordering::SeqCst);
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), proof.as_deref(), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    Some("server_error"),
                    false,
                )
                .await?;
                assert_eq!(keys.verifications.load(Ordering::SeqCst), before + 1);
                // The identical JWT is accepted when the same instance's real Ed25519 verifier recovers.
                keys.unavailable.store(false, Ordering::SeqCst);
                let proof = (scheme == "DPoP")
                    .then(|| signed_proof(method, path, Some(&token), None))
                    .transpose()?;
                accepted(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), proof.as_deref(), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    path,
                )
                .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
