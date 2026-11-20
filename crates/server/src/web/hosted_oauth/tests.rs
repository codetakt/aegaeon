use super::*;
use crate::authcode::types::AuthorizationRequest;

#[test]
fn hosted_authorization_binds_nonce_state_pkce_dpop_and_exclusive_time(
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = "https://issuer.example";
    let started = now()?;
    let domain = Uuid::new_v4();
    let a = Authorization::begin(issuer, domain, started + 60)?;
    let serialized = serde_json::to_vec(&a)?;
    let reopened: Authorization = serde_json::from_slice(&serialized)?;
    let url = Url::parse(&reopened.url()?)?;
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    assert_eq!(params["iss"], issuer);
    assert_eq!(params["scope"], SOURCE_SCOPES);
    assert_eq!(params["prompt"], "login consent");
    assert_eq!(params["max_age"], "0");
    assert_eq!(params["resource"], "https://issuer.example/userinfo");
    assert_eq!(
        params["redirect_uri"],
        "https://issuer.example/organization-invitations/hosted/callback"
    );
    assert!(!url.as_str().contains(&a.verifier));
    let mut fields = serde_json::to_value(&params)?;
    fields["max_age"] = json!(0);
    let request: AuthorizationRequest = serde_json::from_value(fields.clone())?;
    reopened.matches(&request, issuer, a.started_at)?;
    assert_eq!(
        reopened.matches(&request, issuer, a.started_at - 1),
        Err(Error::Refused)
    );
    for name in [
        "state",
        "nonce",
        "resource",
        "iss",
        "scope",
        "code_challenge",
        "redirect_uri",
    ] {
        let mut altered = fields.clone();
        altered[name] = json!("another");
        let changed = serde_json::from_value(altered)?;
        assert_eq!(
            reopened.matches(&changed, issuer, a.started_at),
            Err(Error::Refused)
        );
    }
    let other = Authorization::begin(issuer, domain, a.deadline)?;
    assert_ne!(other.state, a.state);
    assert_ne!(other.key.jkt()?, a.key.jkt()?);
    assert_ne!(other.challenge(), a.challenge());
    let mut expired = reopened;
    expired.deadline = started;
    assert_eq!(
        expired.matches(&request, issuer, a.started_at),
        Err(Error::Refused)
    );
    assert!(Authorization::begin(issuer, domain, started).is_err());
    assert!(Authorization::begin("http://issuer.example", domain, started + 60).is_err());
    Ok(())
}

#[test]
fn hosted_request_proof_signs_exact_endpoint_access_hash_and_new_jti(
) -> Result<(), Box<dyn std::error::Error>> {
    let a = Authorization::begin("https://issuer.example", Uuid::new_v4(), now()? + 60)?;
    let url = "https://issuer.example/organization-invitations/test/preview";
    let first = a.key.proof(url, Some("test-only-access"), None)?;
    let second = a
        .key
        .proof(url, Some("test-only-access"), Some("test-nonce"))?;
    let decode = |proof: &str| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let (input, signature) = proof.rsplit_once('.').ok_or("compact")?;
        let (_, jwk) = a.key.public()?;
        aegaeon_crypto::signature::verify_ed25519(
            &URL_SAFE_NO_PAD.decode(jwk["x"].as_str().ok_or("jwk")?)?,
            input.as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature)?,
        )?;
        Ok(serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(input.split_once('.').ok_or("payload")?.1)?,
        )?)
    };
    let p = decode(&first)?;
    let n = decode(&second)?;
    assert_eq!(p["htu"], url);
    assert_eq!(p["htm"], "POST");
    assert_eq!(
        p["ath"],
        URL_SAFE_NO_PAD.encode(sha256_digest(b"test-only-access"))
    );
    assert!(p.get("nonce").is_none());
    assert_eq!(n["nonce"], "test-nonce");
    assert_ne!(p["jti"], n["jti"]);
    assert_eq!(
        crate::util::compute_dpop_jkt_from_proof_with_max_len(&second, 8192),
        Some(a.key.jkt()?)
    );
    Ok(())
}

#[test]
fn hosted_callback_accepts_only_matching_fresh_signed_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::oidc::{
        id_token::IdTokenBuilder,
        required_rs256::{apply_required_hashes, sign_required_id_token},
        OidcSigningKey,
    };
    let auth = Authorization::begin("https://issuer.example", Uuid::new_v4(), now()? + 90)?;
    let key = OidcSigningKey::from_rsa_pem(
        "hosted-test".into(),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )),
    )?;
    let builder =
        IdTokenBuilder::try_new(auth.issuer.clone(), "recipient".into(), auth.client_id())?
            .nonce(auth.nonce.clone())
            .auth_time(auth.started_at)
            .session_id("oidc-session".into());
    let original = apply_required_hashes(builder, "parent", "code")?
        .build()
        .claims;
    let check = |claims: &crate::oidc::IdTokenClaims| -> Result<bool, Box<dyn std::error::Error>> {
        let token = sign_required_id_token(claims, &key)?;
        Ok(protocol::verified_id(&key.jwks(), 8192, &auth, "code", "parent", &token).is_ok())
    };
    assert!(check(&original)?);
    for change in 0..8 {
        let mut claims = original.clone();
        match change {
            0 => claims.iss = "https://other.example".into(),
            1 => claims.aud = crate::oidc::Audience::Single("another-client".into()),
            2 => claims.nonce = Some("another-nonce".into()),
            3 => claims.auth_time = Some(auth.started_at - 1),
            4 => claims.auth_time = Some(auth.started_at - 301),
            5 => claims.auth_time = Some(auth.started_at + 3600),
            6 => claims.at_hash = Some("different-parent".into()),
            _ => claims.c_hash = Some("different-code".into()),
        };
        assert!(!check(&claims)?);
    }
    Ok(())
}

#[test]
fn hosted_deadlines_use_the_issuers_second_when_requests_cross_a_clock_tick() {
    // The caller sent at 99, the issuer minted at 101, the response arrived at 103.
    let child = json!({"expires_in":300, "expires_at":401});
    assert_eq!(protocol::child_deadline(&child, 103, 800), Ok(401));
    assert_eq!(
        protocol::child_deadline(&child, 401, 800),
        Err(Error::Expired)
    );
    assert_eq!(
        protocol::child_deadline(&child, 103, 400),
        Err(Error::Refused)
    );
    assert_eq!(
        protocol::child_deadline(&json!({"expires_in":300}), 103, 800),
        Err(Error::Refused)
    );
    assert_eq!(
        protocol::child_deadline(&json!({"expires_in":300,"expires_at":404}), 103, 800),
        Err(Error::Refused)
    );
    let payload = URL_SAFE_NO_PAD.encode(br#"{"iat":101,"exp":401}"#);
    let parent = format!("header.{payload}.signature");
    assert_eq!(
        protocol::parent_deadline(&child, &parent, 103, 800),
        Ok(401)
    );
    assert_eq!(
        protocol::parent_deadline(&child, &parent, 401, 800),
        Err(Error::Expired)
    );
    assert_eq!(
        protocol::parent_deadline(&child, "opaque", 103, 800),
        Ok(403)
    );
    assert_eq!(
        protocol::parent_deadline(&child, "opaque", 103, 400),
        Ok(400)
    );
}
