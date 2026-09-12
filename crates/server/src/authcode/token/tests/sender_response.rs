//! Response, JWT and saved-record agreement across the actual issuance entry points.
use super::*;
use crate::authcode::types::{CnfClaim, SenderBinding};

fn binding_cases() -> Vec<(Option<CnfClaim>, Option<SenderBinding>, &'static str)> {
    let fingerprint = "ab".repeat(32);
    vec![
        (None, None, "Bearer"),
        (
            Some(CnfClaim::X5tS256(
                crate::middleware::tls::mtls_fingerprint_to_x5t_s256(&fingerprint)
                    .expect("valid test fingerprint"),
            )),
            Some(SenderBinding::Mtls { fingerprint }),
            "Bearer",
        ),
        (
            Some(CnfClaim::Jkt(URL_SAFE_NO_PAD.encode([7u8; 32]))),
            Some(SenderBinding::DPoP {
                jkt: URL_SAFE_NO_PAD.encode([7u8; 32]),
            }),
            "DPoP",
        ),
    ]
}

fn fixture() -> Result<(TokenIssuer, TokenRequest), String> {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(PublicJwtTestKeyManager::new(
        "sender-response",
    )?))
    .with_issuer("https://issuer.example".into())
    .with_jwt_access_tokens_enabled(true);
    let (code, _) = issuer.issue_authorization_code(
        authorization_request("read offline_access", None),
        "sender-user".into(),
    )?;
    Ok((issuer, token_request_for_code(code, None)))
}

fn check(
    issuer: &TokenIssuer,
    response: TokenResponse,
    cnf: Option<&CnfClaim>,
    binding: Option<&SenderBinding>,
    expected_type: &str,
) -> TestResult {
    let TokenResponse::Success {
        access_token,
        token_type,
        expires_in,
        refresh_token: Some(refresh),
        ..
    } = response
    else {
        return Err(format!("expected offline grant success: {response:?}"));
    };
    assert_eq!(token_type, expected_type, "response token type");
    let saved = issuer
        .token_store
        .try_verify_access_token(&access_token)?
        .ok_or("saved access missing")?;
    assert_eq!(saved.token_type, expected_type, "persisted type");
    assert_eq!(saved.cnf.as_ref(), cnf);
    assert_eq!(saved.expires_in, expires_in);
    let meta = issuer
        .token_store
        .try_get_bearer_meta(&access_token)?
        .ok_or("saved meta missing")?;
    assert_eq!(meta.sender_binding.as_ref(), binding);
    let next = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or("saved refresh missing")?;
    assert_eq!(next.sender_binding.as_ref(), binding);
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access_token.split('.').nth(1).ok_or("JWT payload")?)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(claims["sub"], "sender-user");
    match cnf {
        Some(CnfClaim::Jkt(jkt)) => assert_eq!(claims["cnf"], serde_json::json!({"jkt":jkt})),
        Some(CnfClaim::X5tS256(x5t)) => {
            assert_eq!(claims["cnf"], serde_json::json!({"x5t#S256":x5t}))
        }
        None => assert!(claims.get("cnf").is_none()),
    }
    Ok(())
}

#[tokio::test]
async fn sender_response_code_sync_and_async_agree_with_saved_confirmation() -> TestResult {
    for (cnf, binding, kind) in binding_cases() {
        for asynchronous in [false, true] {
            let (issuer, req) = fixture()?;
            let response = if asynchronous {
                issuer
                    .exchange_code_for_tokens_bound_with_grant_policy_async(
                        req,
                        cnf.as_ref(),
                        binding.as_ref(),
                        true,
                        true,
                    )
                    .await?
            } else {
                issuer.exchange_code_for_tokens_bound_with_grant_policy(
                    req,
                    cnf.as_ref(),
                    binding.as_ref(),
                    true,
                    true,
                )?
            };
            check(&issuer, response, cnf.as_ref(), binding.as_ref(), kind)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sender_response_all_refresh_entry_points_agree_with_saved_confirmation() -> TestResult {
    for (cnf, binding, kind) in binding_cases() {
        for entry in 0..3 {
            let (issuer, req) = fixture()?;
            let initial = issuer.exchange_code_for_tokens_bound_with_grant_policy(
                req,
                cnf.as_ref(),
                binding.as_ref(),
                true,
                true,
            )?;
            let TokenResponse::Success {
                refresh_token: Some(refresh),
                ..
            } = initial
            else {
                return Err(format!("initial grant: {initial:?}"));
            };
            let response = match entry {
                0 => issuer.refresh_access_token_bound(
                    &refresh,
                    None,
                    cnf.as_ref(),
                    binding.as_ref(),
                )?,
                1 => {
                    issuer
                        .refresh_access_token_bound_async(
                            refresh,
                            None,
                            cnf.clone(),
                            binding.clone(),
                        )
                        .await?
                }
                _ => {
                    let prepared = issuer
                        .token_store
                        .try_get_refresh_token(&refresh)?
                        .ok_or("prepared refresh")?;
                    issuer
                        .refresh_prepared_access_token_bound_async(
                            refresh,
                            prepared,
                            None,
                            None,
                            cnf.clone(),
                            binding.clone(),
                        )
                        .await?
                }
            };
            check(&issuer, response, cnf.as_ref(), binding.as_ref(), kind)?;
        }
    }
    Ok(())
}
