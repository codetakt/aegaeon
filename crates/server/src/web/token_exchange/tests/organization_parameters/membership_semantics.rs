use super::*;

async fn redeem(
    state: &AppState,
    projection: &crate::application_authorization::inorii::Grant,
    code: &str,
) -> TestResult {
    let (status, issued) = send(state, code_body(code)?, true).await?;
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

async fn reject_and_retain(state: &AppState, code: &str) -> TestResult {
    refused(&send(state, code_body(code)?, true).await?, "invalid_grant")?;
    check!(state.tokens.issuer.code_store.try_get_code(code)?.is_some());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; owns a unique membership schema"]
async fn membership_null_predicates_and_join_keys_deny_without_consuming_code() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let membership = Membership::create(&pool).await?;
        let result = async {
            let (state, projection) =
                state_with_projection(&pool, &env, &membership, true).await?;
            let nondeleted: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM organizations WHERE id IN (1,2) AND deleted_at IS NULL",
            )
            .fetch_one(&membership.pool)
            .await?;
            check!(nondeleted == 2);
            // NULL deletion markers are the positive, nondeleted baseline.
            redeem(&state, &projection, &projected_code(&state, &projection)?).await?;
            for mutation in [
                "UPDATE authorization_subject_bindings SET issuer=NULL WHERE user_id=7",
                "UPDATE authorization_subject_bindings SET subject=NULL WHERE user_id=7",
                "UPDATE authorization_subject_bindings SET user_id=NULL WHERE user_id=7",
                "UPDATE organization_users SET user_id=NULL WHERE user_id=7 AND organization_id=1",
                "UPDATE organization_users SET organization_id=NULL WHERE user_id=7 AND organization_id=1",
                "UPDATE organizations SET id=NULL WHERE id=1",
                "UPDATE organizations SET public_id=NULL WHERE id=1",
                "UPDATE organization_users SET status=NULL WHERE user_id=7 AND organization_id=1",
            ] {
                let code = projected_code(&state, &projection)?;
                let changed = sqlx::query(mutation).execute(&membership.pool).await?;
                check!(changed.rows_affected() == 1);
                reject_and_retain(&state, &code).await?;
                membership.restore(&state.issuer).await?;
                // Successful reuse of this exact code establishes that rejection did not consume it.
                redeem(&state, &projection, &code).await?;
            }
            Ok(())
        }.await;
        membership.finish(&pool, result).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; owns a unique membership schema"]
async fn membership_null_selected_role_is_unavailable_until_same_code_recovers() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let membership = Membership::create(&pool).await?;
        let result = async {
            let (state, projection) = state_with_projection(&pool, &env, &membership, true).await?;
            let code = projected_code(&state, &projection)?;
            let changed = sqlx::query(
                "UPDATE organization_users SET role=NULL WHERE user_id=7 AND organization_id=1",
            )
            .execute(&membership.pool)
            .await?;
            check!(changed.rows_affected() == 1);
            let (status, denied) = send(&state, code_body(&code)?, true).await?;
            check!(status == StatusCode::SERVICE_UNAVAILABLE);
            check!(denied["error"] == "temporarily_unavailable");
            check!(denied.get("access_token").is_none());
            check!(state
                .tokens
                .issuer
                .code_store
                .try_get_code(&code)?
                .is_some());
            membership.restore(&state.issuer).await?;
            redeem(&state, &projection, &code).await?;
            Ok(())
        }
        .await;
        membership.finish(&pool, result).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; owns a unique membership schema"]
async fn membership_matching_bindings_union_is_required_for_all_roles() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let membership = Membership::create(&pool).await?;
        let result = async {
            let claims = json!({"roles":["USER","SUPER_ADMIN"],"organization_roles":[
                {"organization_id":ORG_A,"roles":["ORGANIZATION_ADMIN","ORGANIZATION_STAFF"]},
                {"organization_id":ORG_B,"roles":["ORGANIZATION_ADMIN","ORGANIZATION_STAFF"]}
            ]});
            let (state, projection) =
                state_with_projection_claims(&pool, &env, &membership, claims).await?;
            membership.restore_complementary_bindings(&state.issuer).await?;
            // Each user supplies one role per organization; only their union supplies all four.
            redeem(&state, &projection, &projected_code(&state, &projection)?).await?;
            for missing_user in [7_i64, 8_i64] {
                let code = projected_code(&state, &projection)?;
                let removed = sqlx::query(
                    "DELETE FROM authorization_subject_bindings WHERE user_id=$1 AND issuer=$2 AND subject='exchange-user'",
                )
                .bind(missing_user)
                .bind(state.issuer.as_str())
                .execute(&membership.pool)
                .await?;
                check!(removed.rows_affected() == 1);
                reject_and_retain(&state, &code).await?;
                membership.restore_complementary_bindings(&state.issuer).await?;
                redeem(&state, &projection, &code).await?;
            }
            Ok(())
        }.await;
        membership.finish(&pool, result).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
