//! Trusted library boundary: an expected key or cnf cannot create possession.
use super::*;
use crate::authcode::types::{CnfClaim, DpopKeyThumbprint, SenderBinding};

fn fixture(bound: bool) -> Result<(TokenIssuer, TokenRequest, String), String> {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(PublicJwtTestKeyManager::new(
        "code-binding",
    )?))
    .with_issuer("https://issuer.example".into())
    .with_jwt_access_tokens_enabled(true);
    let key = URL_SAFE_NO_PAD.encode([71_u8; 32]);
    let mut input = authorization_request("read offline_access", None);
    input.dpop_jkt = bound.then(|| DpopKeyThumbprint::parse(&key)).transpose()?;
    let (code, _) = issuer.issue_authorization_code(input, "sender-user".into())?;
    Ok((issuer, token_request_for_code(code, None), key))
}

async fn exchange_at(
    issuer: &TokenIssuer,
    request: &TokenRequest,
    entry: u8,
    cnf: Option<&CnfClaim>,
    sender: Option<&SenderBinding>,
) -> Result<TokenResponse, String> {
    match entry {
        0 => issuer.exchange_code_for_tokens_bound(request.clone(), cnf, sender),
        1 => issuer.exchange_code_for_tokens_bound_with_refresh_policy(
            request.clone(),
            cnf,
            sender,
            false,
        ),
        2 => issuer.exchange_code_for_tokens_bound_with_grant_policy(
            request.clone(),
            cnf,
            sender,
            true,
            false,
        ),
        _ => {
            issuer
                .exchange_code_for_tokens_bound_with_grant_policy_async(
                    request.clone(),
                    cnf,
                    sender,
                    true,
                    false,
                )
                .await
        }
    }
}

type NegativeCase = (Option<CnfClaim>, Option<SenderBinding>, &'static str);

fn negative_cases(key: &str) -> Result<Vec<NegativeCase>, String> {
    let key = key.to_string();
    let other = URL_SAFE_NO_PAD.encode([72_u8; 32]);
    let fingerprint = "ab".repeat(32);
    let certificate =
        crate::middleware::tls::mtls_fingerprint_to_x5t_s256(&fingerprint).ok_or("certificate")?;
    Ok(vec![
        (None, None, "invalid_dpop_proof"),
        (Some(CnfClaim::Jkt(key.clone())), None, "invalid_dpop_proof"),
        (
            Some(CnfClaim::Jkt(other.clone())),
            Some(SenderBinding::DPoP { jkt: other.clone() }),
            "invalid_grant",
        ),
        (
            Some(CnfClaim::X5tS256(certificate)),
            Some(SenderBinding::Mtls { fingerprint }),
            "invalid_grant",
        ),
        (
            Some(CnfClaim::Jkt(other.clone())),
            Some(SenderBinding::DPoP { jkt: key.clone() }),
            "invalid_grant",
        ),
        (
            None,
            Some(SenderBinding::DPoP { jkt: key.clone() }),
            "invalid_grant",
        ),
    ])
}

#[tokio::test]
async fn code_binding_sync_async_all_bound_apis_preserve_code_on_wrong_or_missing_sender(
) -> TestResult {
    for entry in 0..4 {
        let (issuer, request, key) = fixture(true)?;
        let original = serde_json::to_value(
            issuer
                .code_store
                .try_get_code(request.code.as_deref().ok_or("code")?)?,
        )
        .map_err(|e| e.to_string())?;
        let cases = negative_cases(&key)?;
        for (cnf, sender, expected) in cases {
            let response =
                exchange_at(&issuer, &request, entry, cnf.as_ref(), sender.as_ref()).await?;
            assert!(
                matches!(response,TokenResponse::Error{ref error,..} if error == expected),
                "{response:?}"
            );
            assert_eq!(
                serde_json::to_value(
                    issuer
                        .code_store
                        .try_get_code(request.code.as_deref().ok_or("code")?)?
                )
                .map_err(|e| e.to_string())?,
                original
            );
            let snapshot = issuer.token_store.try_snapshot()?;
            assert!(snapshot.access_tokens.is_empty());
            assert!(snapshot.refresh_tokens.is_empty());
            assert!(snapshot.refresh_grants.is_empty());
            assert!(snapshot.bearer_meta.is_empty());
        }
        let cnf = CnfClaim::Jkt(key.clone());
        let sender = SenderBinding::DPoP { jkt: key };
        let response = exchange_at(&issuer, &request, entry, Some(&cnf), Some(&sender)).await?;
        let TokenResponse::Success {
            access_token,
            token_type,
            refresh_token,
            ..
        } = response
        else {
            return Err(format!("{response:?}"));
        };
        assert_eq!(token_type, "DPoP");
        assert!(issuer
            .code_store
            .try_get_code(request.code.as_deref().ok_or("code")?)?
            .is_none());
        assert_eq!(
            issuer
                .token_store
                .try_verify_access_token(&access_token)?
                .ok_or("access")?
                .cnf,
            Some(cnf)
        );
        assert_eq!(refresh_token.is_some(), entry == 0);
        if let Some(refresh) = refresh_token {
            assert_eq!(
                issuer
                    .token_store
                    .try_get_refresh_token(&refresh)?
                    .ok_or("refresh")?
                    .sender_binding,
                Some(sender)
            );
        }
    }
    Ok(())
}

#[test]
fn code_binding_unbound_convenience_cannot_attest_sender_and_plain_flow_survives() -> TestResult {
    for bound in [false, true] {
        let (issuer, request, key) = fixture(bound)?;
        let response =
            issuer.exchange_code_for_tokens(request.clone(), Some(&CnfClaim::Jkt(key)))?;
        assert!(matches!(response, TokenResponse::Error { .. }));
        assert!(issuer
            .code_store
            .try_get_code(request.code.as_deref().ok_or("code")?)?
            .is_some());
        let response = issuer.exchange_code_for_tokens(request, None)?;
        if bound {
            assert!(
                matches!(response,TokenResponse::Error{ref error,..} if error=="invalid_dpop_proof")
            );
        } else {
            assert!(
                matches!(response,TokenResponse::Success{ref token_type,..} if token_type=="Bearer")
            );
        }
    }
    Ok(())
}
