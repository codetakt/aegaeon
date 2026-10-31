use super::*;

pub(super) async fn unscoped_code(
    issuer: &Arc<TokenIssuer>,
    request: &crate::authcode::types::TokenRequest,
    cnf: &CnfClaim,
    sender: &SenderBinding,
) -> TestResult {
    let (issuer, request, cnf, sender) =
        (issuer.clone(), request.clone(), cnf.clone(), sender.clone());
    let response = tokio::spawn(async move {
        issuer
            .exchange_code_for_tokens_bound_with_grant_policy_async(
                request,
                Some(&cnf),
                Some(&sender),
                true,
                true,
            )
            .await
    })
    .await
    .map_err(|e| e.to_string())??;
    assert!(matches!(response, TokenResponse::Error { ref error, .. } if error == "invalid_grant"));
    Ok(())
}

pub(super) async fn unscoped_refresh(
    issuer: &Arc<TokenIssuer>,
    refresh: &str,
    cnf: &CnfClaim,
    sender: &SenderBinding,
) -> TestResult {
    let (issuer, refresh, cnf, sender) = (
        issuer.clone(),
        refresh.to_owned(),
        cnf.clone(),
        sender.clone(),
    );
    let response = tokio::spawn(async move {
        issuer
            .refresh_access_token_bound_async(refresh, None, Some(cnf), Some(sender))
            .await
    })
    .await
    .map_err(|e| e.to_string())??;
    assert!(matches!(response, TokenResponse::Error { ref error, .. } if error == "invalid_grant"));
    Ok(())
}

pub(super) async fn parent_metadata(
    issuer: &TokenIssuer,
    meta: &crate::authcode::types::BearerTokenMeta,
) -> TestResult {
    let validator = TokenValidator::new(issuer.token_store.clone(), issuer.key_manager.clone());
    validator
        .validate_refresh_parent(meta)
        .map_err(|e| e.to_string())?;
    validator
        .validate_refresh_parent_async(meta)
        .await
        .map_err(|e| e.to_string())?;
    for removed in ["grant", "organization", "epoch"] {
        let mut missing = meta.clone();
        match removed {
            "grant" => missing.exchange_grant = None,
            "organization" => missing.exchange_grant.as_mut().ok_or("grant")?.organization = None,
            _ => {
                let original = missing
                    .exchange_grant
                    .as_mut()
                    .and_then(|g| g.organization.as_mut())
                    .ok_or("original")?;
                original.consent.version = 1;
                original.consent.epoch = None;
            }
        }
        assert!(
            matches!(
                validator.validate_refresh_parent(&missing),
                Err(TokenPolicyError::RefreshParentRevoked)
            ),
            "missing {removed}"
        );
        assert!(
            matches!(
                validator.validate_refresh_parent_async(&missing).await,
                Err(TokenPolicyError::RefreshParentRevoked)
            ),
            "async missing {removed}"
        );
    }
    for field in [
        "environment_id",
        "deployment_id",
        "epoch",
        "primary_id",
        "token_store_id",
    ] {
        let mut wrong = meta.clone();
        let original = wrong
            .exchange_grant
            .as_mut()
            .and_then(|g| g.organization.as_mut())
            .ok_or("original")?;
        let mut record =
            serde_json::to_value(&original.consent.epoch).map_err(|e| e.to_string())?;
        record[field] = serde_json::json!(Uuid::new_v4());
        original.consent.epoch = Some(serde_json::from_value(record).map_err(|e| e.to_string())?);
        assert!(
            matches!(
                validator.validate_refresh_parent(&wrong),
                Err(TokenPolicyError::RefreshParentRevoked)
            ),
            "sync parent {field}"
        );
        assert!(
            matches!(
                validator.validate_refresh_parent_async(&wrong).await,
                Err(TokenPolicyError::RefreshParentRevoked)
            ),
            "async parent {field}"
        );
    }
    let unscoped = meta.clone();
    let observed = tokio::spawn(async move {
        let synchronous = validator.validate_refresh_parent(&unscoped);
        let asynchronous = validator.validate_refresh_parent_async(&unscoped).await;
        matches!(synchronous, Err(TokenPolicyError::RefreshParentRevoked))
            && matches!(asynchronous, Err(TokenPolicyError::RefreshParentRevoked))
    })
    .await
    .map_err(|e| e.to_string())?;
    assert!(observed, "parent readers need actual owner");
    Ok(())
}
