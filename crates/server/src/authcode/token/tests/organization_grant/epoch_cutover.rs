//! Actual witness epoch retirement; primary/token-store restore qualification is separate.
use super::*;
use crate::authcode::types::BearerTokenMeta;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

struct Saved {
    approval: Consent,
    code: String,
    refresh: String,
    metadata: BearerTokenMeta,
    cnf: CnfClaim,
    sender: SenderBinding,
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual witness retirement, issuer and refresh lineage"]
async fn pg_organizations_retired_epoch_never_upgrades_approval_code_or_refresh(
) -> anyhow::Result<()> {
    let mut witness = CallerFixture::new(Uuid::new_v4()).await?;
    let result = Box::pin(exercise(&mut witness)).await;
    let cleanup = witness.finish().await;
    result.and(cleanup)
}

async fn exercise(witness: &mut CallerFixture) -> anyhow::Result<()> {
    let issuer = issuer().map_err(anyhow::Error::msg)?;
    let first = witness.begin().await?;
    let saved = first.store_scope(Box::pin(capture(&issuer))).await??;
    anyhow::ensure!(first.complete().await?.pending == 0);
    witness.retire_epoch().await?;
    let second = witness.begin().await?;
    let checked = second.store_scope(Box::pin(check(&issuer, saved))).await?;
    let completed = second.complete().await;
    checked?;
    anyhow::ensure!(completed?.pending == 0);
    Ok(())
}

async fn capture(issuer: &TokenIssuer) -> anyhow::Result<Saved> {
    let input = input().map_err(anyhow::Error::msg)?;
    let approval = input
        .organization_approval
        .clone()
        .ok_or_else(|| anyhow::anyhow!("approval"))?;
    let code = issuer
        .issue_authorization_code_with_local_profile_async(input)
        .await
        .map_err(anyhow::Error::msg)?
        .0;
    let cnf = CnfClaim::Jkt(approval.dpop_jkt.clone());
    let sender = SenderBinding::DPoP {
        jkt: approval.dpop_jkt.clone(),
    };
    let (access, refresh) = Box::pin(fresh(issuer, &cnf, &sender)).await?;
    let metadata = issuer
        .token_store
        .try_get_bearer_meta_async(access)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("metadata"))?;
    Ok(Saved {
        approval,
        code,
        refresh,
        metadata,
        cnf,
        sender,
    })
}

async fn fresh(
    issuer: &TokenIssuer,
    cnf: &CnfClaim,
    sender: &SenderBinding,
) -> anyhow::Result<(String, String)> {
    let code = issuer
        .issue_authorization_code_with_local_profile_async(input().map_err(anyhow::Error::msg)?)
        .await
        .map_err(anyhow::Error::msg)?
        .0;
    let result = issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            token_request_for_code(code, None),
            Some(cnf),
            Some(sender),
            true,
            true,
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let TokenResponse::Success {
        access_token,
        refresh_token: Some(refresh),
        ..
    } = result
    else {
        anyhow::bail!("fresh current-epoch issuance must work");
    };
    Ok((access_token, refresh))
}

async fn check(issuer: &TokenIssuer, saved: Saved) -> anyhow::Result<()> {
    let mut old = input().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        old.organization_approval
            .as_ref()
            .and_then(|v| v.epoch.as_ref())
            != saved.approval.epoch.as_ref()
    );
    old.req.authorization_details = Some(serde_json::json!([saved.approval.request]));
    old.organization_approval = Some(saved.approval);
    anyhow::ensure!(
        issuer
            .issue_authorization_code_with_local_profile_async(old)
            .await
            .is_err(),
        "retired approval cannot bind a new root"
    );
    let code = issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            token_request_for_code(saved.code.clone(), None),
            Some(&saved.cnf),
            Some(&saved.sender),
            true,
            true,
        )
        .await
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        matches!(code, TokenResponse::Error { ref error, .. } if error == "invalid_grant")
    );
    anyhow::ensure!(
        issuer
            .code_store
            .try_get_code_async(saved.code)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some(),
        "refusal does not rewrite old code"
    );
    let refreshed = issuer
        .refresh_access_token_bound_async(
            saved.refresh,
            None,
            Some(saved.cnf.clone()),
            Some(saved.sender.clone()),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        matches!(refreshed, TokenResponse::Error { ref error, .. } if error == "invalid_grant")
    );
    let validator = TokenValidator::new(issuer.token_store.clone(), issuer.key_manager.clone());
    anyhow::ensure!(matches!(
        validator
            .validate_refresh_parent_async(&saved.metadata)
            .await,
        Err(TokenPolicyError::RefreshParentRevoked)
    ));
    Box::pin(fresh(issuer, &saved.cnf, &saved.sender)).await?;
    Ok(())
}
