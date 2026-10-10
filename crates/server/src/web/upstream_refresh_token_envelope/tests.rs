use super::*;
use crate::oidc::{Audience, IdToken, IdTokenBuilder};
use crate::upstream::upstream_subject_link_hash;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct KeyGuard(Option<std::ffi::OsString>);
impl KeyGuard {
    fn install(value: Option<&str>) -> Self {
        let old = std::env::var_os(KEY_ENCRYPTION_KEY_ENV);
        if let Some(value) = value {
            std::env::set_var(KEY_ENCRYPTION_KEY_ENV, value);
        } else {
            std::env::remove_var(KEY_ENCRYPTION_KEY_ENV);
        }
        Self(old)
    }
}
impl Drop for KeyGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.0 {
            std::env::set_var(KEY_ENCRYPTION_KEY_ENV, value);
        } else {
            std::env::remove_var(KEY_ENCRYPTION_KEY_ENV);
        }
    }
}

fn token() -> Result<IdToken, Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 32];
    aegaeon_crypto::rand::fill_random(&mut nonce).map_err(|e| format!("{e:?}"))?;
    Ok(IdTokenBuilder::try_new(
        "https://issuer.example".into(),
        "private-subject".into(),
        "client".into(),
    )
    .map_err(std::io::Error::other)?
    .nonce(URL_SAFE_NO_PAD.encode(nonce))
    .auth_time(1_700_000_000)
    .build())
}
fn context(token: &IdToken) -> Result<UpstreamRefreshAuthenticationContext, String> {
    UpstreamRefreshAuthenticationContext::from_validated_id_token(
        token,
        "client",
        &token.claims.iss,
        &upstream_subject_link_hash(&token.claims.iss, &token.claims.sub),
    )
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn upstream_refresh_v3_envelope_round_trips_original_context_without_plaintext() -> TestResult {
    let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key lock")?;
    let _key = KeyGuard::install(Some(&URL_SAFE_NO_PAD.encode([0x41; 32])));
    let original_token = token()?;
    let original = context(&original_token)?;
    let env = uuid::Uuid::new_v4();
    let conn = uuid::Uuid::new_v4();
    let issuer = &original_token.claims.iss;
    let hash = upstream_subject_link_hash(issuer, &original_token.claims.sub);
    let sealed = seal_upstream_refresh_token(
        "private-refresh-token",
        env,
        issuer,
        &hash,
        conn,
        1,
        &original,
    )
    .map_err(|e| format!("{e:?}"))?;
    let text = std::str::from_utf8(&sealed)?;
    assert!(text.starts_with(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX));
    for secret in [
        "private-refresh-token",
        "private-subject",
        original_token
            .claims
            .nonce
            .as_deref()
            .ok_or("original nonce")?,
        issuer,
    ] {
        assert!(!text.contains(secret));
    }
    let grant = open_upstream_refresh_token(&sealed, env, issuer, &hash, conn, 1)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(grant.refresh_token, "private-refresh-token");
    assert!(grant.original == original);
    assert!(
        open_upstream_refresh_token(&sealed, uuid::Uuid::new_v4(), issuer, &hash, conn, 1).is_err()
    );
    assert!(
        open_upstream_refresh_token(&sealed, env, "https://other.example", &hash, conn, 1).is_err()
    );
    assert!(open_upstream_refresh_token(&sealed, env, issuer, "wrong-subject", conn, 1).is_err());
    assert!(
        open_upstream_refresh_token(&sealed, env, issuer, &hash, uuid::Uuid::new_v4(), 1).is_err()
    );
    assert!(open_upstream_refresh_token(&sealed, env, issuer, &hash, conn, 2).is_err());
    let _wrong_key = KeyGuard::install(Some(&URL_SAFE_NO_PAD.encode([0x42; 32])));
    assert!(open_upstream_refresh_token(&sealed, env, issuer, &hash, conn, 1).is_err());
    Ok(())
}

#[test]
fn upstream_refresh_v3_rejects_legacy_malformed_and_invalid_context() -> TestResult {
    let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key lock")?;
    let _key = KeyGuard::install(Some(&URL_SAFE_NO_PAD.encode([0x43; 32])));
    let token = token()?;
    let original = context(&token)?;
    let env = uuid::Uuid::new_v4();
    let conn = uuid::Uuid::new_v4();
    let hash = upstream_subject_link_hash(&token.claims.iss, &token.claims.sub);
    let open =
        |bytes: &[u8]| open_upstream_refresh_token(bytes, env, &token.claims.iss, &hash, conn, 1);
    assert!(matches!(
        open(b"aeg-upstream-refresh-token-v2.any-old-value"),
        Err(UpstreamRefreshTokenEnvelopeError::ReauthenticationRequired)
    ));
    for bytes in [
        b"plaintext".as_slice(),
        b"aeg-upstream-refresh-token-v3.invalid",
        &vec![b'x'; MAX_ENVELOPE_BYTES + 1],
    ] {
        assert!(open(bytes).is_err());
    }
    for invalid in ["", "   "] {
        assert!(seal_upstream_refresh_token(
            invalid,
            env,
            &token.claims.iss,
            &hash,
            conn,
            1,
            &original
        )
        .is_err());
    }
    assert!(seal_upstream_refresh_token(
        "token",
        env,
        &token.claims.iss,
        "wrong-hash",
        conn,
        1,
        &original
    )
    .is_err());
    let mut value = serde_json::to_value(&original)?;
    value["audiences"] = serde_json::json!(["client", "client"]);
    let invalid = serde_json::from_value(value)?;
    assert!(
        seal_upstream_refresh_token("token", env, &token.claims.iss, &hash, conn, 1, &invalid)
            .is_err()
    );
    let sealed =
        seal_upstream_refresh_token("token", env, &token.claims.iss, &hash, conn, 1, &original)
            .map_err(|e| format!("{e:?}"))?;
    let text = std::str::from_utf8(&sealed)?
        .strip_prefix(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX)
        .ok_or("prefix")?;
    let mut bytes = URL_SAFE_NO_PAD.decode(text)?;
    bytes[13] ^= 1;
    assert!(open(
        format!(
            "{UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        )
        .as_bytes()
    )
    .is_err());
    let _missing = KeyGuard::install(None);
    assert!(matches!(
        seal_upstream_refresh_token("token", env, &token.claims.iss, &hash, conn, 1, &original),
        Err(UpstreamRefreshTokenEnvelopeError::KeyMissing)
    ));
    Ok(())
}

#[test]
fn upstream_refresh_original_context_preserves_semantic_audience_and_optional_claims() -> TestResult
{
    let mut original_token = token()?;
    original_token.claims.aud =
        Audience::Multiple(vec!["other".into(), "client".into(), "other".into()]);
    let original = context(&original_token)?;
    for audience in [vec!["client", "other"], vec!["other", "client", "client"]] {
        let mut refreshed = token()?;
        refreshed.claims.nonce = original_token.claims.nonce.clone();
        refreshed.claims.aud =
            Audience::Multiple(audience.into_iter().map(str::to_owned).collect());
        assert!(original.validate_refreshed_id_token(&refreshed).is_ok());
        refreshed.claims.auth_time = None;
        refreshed.claims.nonce = None;
        assert!(original.validate_refreshed_id_token(&refreshed).is_ok());
    }
    for field in ["sub", "iss", "aud", "nonce", "auth_time"] {
        let mut value = serde_json::to_value(&original_token.claims)?;
        value[field] = match field {
            "aud" => serde_json::json!(["client"]),
            "auth_time" => serde_json::json!(1_700_000_001),
            _ => serde_json::json!("changed"),
        };
        let refreshed = IdToken {
            claims: serde_json::from_value(value)?,
            signing_alg: "RS256".into(),
        };
        assert!(
            original.validate_refreshed_id_token(&refreshed).is_err(),
            "{field}"
        );
    }
    let mut singleton = token()?;
    let original = context(&singleton)?;
    let original_nonce = singleton.claims.nonce.clone();
    singleton.claims.aud = Audience::Multiple(vec!["client".into()]);
    assert!(original.validate_refreshed_id_token(&singleton).is_ok());
    singleton.claims.nonce = None;
    singleton.claims.auth_time = None;
    let absent = context(&singleton)?;
    assert!(absent.validate_refreshed_id_token(&token()?).is_err());
    let mut nonce_only = token()?;
    nonce_only.claims.nonce = original_nonce;
    nonce_only.claims.auth_time = None;
    assert!(absent.validate_refreshed_id_token(&nonce_only).is_err());
    let mut auth_time_only = token()?;
    auth_time_only.claims.nonce = None;
    assert!(absent.validate_refreshed_id_token(&auth_time_only).is_err());
    assert!(original.validate_refreshed_id_token(&nonce_only).is_ok());
    assert!(original
        .validate_refreshed_id_token(&auth_time_only)
        .is_ok());
    Ok(())
}

#[test]
fn upstream_refresh_v3_strict_plaintext_decode_rejects_extra_fields_and_identity_mismatch(
) -> TestResult {
    let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key lock")?;
    let key = [0x44; 32];
    let _key = KeyGuard::install(Some(&URL_SAFE_NO_PAD.encode(key)));
    let token = token()?;
    let original = context(&token)?;
    let env = uuid::Uuid::new_v4();
    let conn = uuid::Uuid::new_v4();
    let hash = upstream_subject_link_hash(&token.claims.iss, &token.claims.sub);
    let grant = UpstreamRefreshGrant {
        refresh_token: "private-refresh-token".into(),
        original,
    };
    let baseline = serde_json::to_value(&grant)?;
    for field in [
        "unknown",
        "issuer",
        "subject",
        "client_id",
        "audiences",
        "nonce",
        "auth_time",
    ] {
        let mut value = baseline.clone();
        match field {
            "unknown" => value["unknown"] = serde_json::json!(true),
            "audiences" => value["original"][field] = serde_json::json!([]),
            "auth_time" => value["original"][field] = serde_json::json!(-1),
            "nonce" | "client_id" => value["original"][field] = serde_json::json!(""),
            _ => value["original"][field] = serde_json::json!("wrong"),
        }
        let mut nonce = [0u8; 12];
        aegaeon_crypto::rand::fill_random(&mut nonce).map_err(|e| format!("{e:?}"))?;
        let aad = upstream_refresh_token_aad_v3(env, &token.claims.iss, &hash, conn, 1);
        let sealed =
            aegaeon_crypto::jwe::encrypt_a256gcm(&key, &nonce, &serde_json::to_vec(&value)?, &aad)
                .map_err(|e| format!("{e:?}"))?;
        let mut bytes = nonce.to_vec();
        bytes.extend(sealed);
        let envelope = format!(
            "{UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        );
        assert!(
            open_upstream_refresh_token(
                envelope.as_bytes(),
                env,
                &token.claims.iss,
                &hash,
                conn,
                1
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(seal_upstream_refresh_token(
        &"x".repeat(super::super::UPSTREAM_MAX_BODY_BYTES + 1),
        env,
        &token.claims.iss,
        &hash,
        conn,
        1,
        &grant.original
    )
    .is_err());
    Ok(())
}
