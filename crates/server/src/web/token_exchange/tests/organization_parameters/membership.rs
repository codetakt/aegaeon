use super::*;

pub(super) async fn refusals(
    state: &AppState,
    membership: &Membership,
    projection: &crate::application_authorization::inorii::Grant,
) -> TestResult {
    // Each refusal is followed by restored live SQL state and successful use of the same code.
    for mutation in [
        "DELETE FROM authorization_subject_bindings",
        "UPDATE authorization_subject_bindings SET issuer='https://wrong.example'",
        "UPDATE authorization_subject_bindings SET subject='wrong-subject'",
        "UPDATE organization_users SET status='inactive' WHERE organization_id=1",
        "DELETE FROM organization_users WHERE organization_id=1",
        "UPDATE organizations SET deleted_at=now() WHERE id=1",
        "UPDATE organization_users SET role='ORGANIZATION_STAFF' WHERE organization_id=1",
    ] {
        let code = projected_code(state, projection)?;
        let body = code_body(&code)?;
        sqlx::raw_sql(mutation).execute(&membership.pool).await?;
        refused(
            &send(state, format!("{body}&organizationId={ORG_A}"), true).await?,
            "invalid_grant",
        )?;
        check!(state
            .tokens
            .issuer
            .code_store
            .try_get_code(&code)?
            .is_some());
        membership.restore(&state.issuer).await?;
        let (status, issued) = send(state, body, true).await?;
        check!(status == StatusCode::OK);
        output(
            state,
            &issued,
            Some(projection),
            &format!("{}/userinfo", state.issuer),
            SOURCE_SCOPE,
        )?;
    }
    // Missing pool remains an operational failure, not a successful organization fixture.
    let mut unavailable = state.clone();
    unavailable.application_authority = Some(crate::application_authorization::Authority {
        projections: state.db_pool.clone(),
        memberships: None,
    });
    let code = projected_code(state, projection)?;
    let (status, denied) = send(&unavailable, code_body(&code)?, true).await?;
    check!(status == StatusCode::SERVICE_UNAVAILABLE);
    check!(denied.get("access_token").is_none());
    check!(state
        .tokens
        .issuer
        .code_store
        .try_get_code(&code)?
        .is_some());
    let (status, issued) = send(state, code_body(&code)?, true).await?;
    check!(status == StatusCode::OK);
    output(
        state,
        &issued,
        Some(projection),
        &format!("{}/userinfo", state.issuer),
        SOURCE_SCOPE,
    )?;
    Ok(())
}
