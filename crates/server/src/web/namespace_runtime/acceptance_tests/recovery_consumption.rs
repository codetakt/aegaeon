use super::{
    management_fixture::user,
    support::{fixture, unavailable, unavailable_states, TestResult},
};
use crate::{
    local_credentials::{self, RecoveryTokenPurpose},
    web,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    Form,
};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_recovery_retains_token_and_csrf_then_matching_permit_redeems() -> TestResult {
    for purpose in [
        RecoveryTokenPurpose::Activation,
        RecoveryTokenPurpose::PasswordReset,
    ] {
        let (state, env) = fixture().await?;
        let (id, _) = user(&state, &env).await?;
        if purpose == RecoveryTokenPurpose::Activation {
            sqlx::query("UPDATE aegaeon.end_users SET status='INVITED' WHERE id=$1")
                .bind(id)
                .execute(&state.db_pool)
                .await?;
        }
        let mut tx = state.db_pool.begin().await?;
        let token =
            local_credentials::issue_recovery_token(&mut tx, id, purpose, 600, None, None).await?;
        tx.commit().await?;
        let csrf = state.device.local_auth_csrf_store.try_generate()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={csrf}", web::LOCAL_AUTH_CSRF_COOKIE_NAME).parse()?,
        );
        let form = vec![
            ("csrf_token".into(), csrf.clone()),
            ("token".into(), token.token),
            ("password".into(), "namespace-test-password".into()),
            (
                "password_confirmation".into(),
                "namespace-test-password".into(),
            ),
        ];
        for denied in unavailable_states(&state) {
            let response = match purpose {
                RecoveryTokenPurpose::Activation => {
                    web::local_auth_recovery::local_activate_post(
                        State(denied),
                        headers.clone(),
                        Ok(Form(form.clone())),
                    )
                    .await
                }
                RecoveryTokenPurpose::PasswordReset => {
                    web::local_auth_recovery::local_password_reset_post(
                        State(denied),
                        headers.clone(),
                        Ok(Form(form.clone())),
                    )
                    .await
                }
            };
            unavailable(response).await?;
            let untouched: bool = sqlx::query_scalar("SELECT redeemed_at IS NULL AND revoked_at IS NULL FROM aegaeon.end_user_recovery_tokens WHERE id=$1")
                .bind(uuid::Uuid::parse_str(&token.id)?).fetch_one(&state.db_pool).await?;
            assert!(untouched);
            let credentials: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1",
            )
            .bind(id)
            .fetch_one(&state.db_pool)
            .await?;
            assert_eq!(credentials, 0);
        }
        let response = match purpose {
            RecoveryTokenPurpose::Activation => {
                web::local_auth_recovery::local_activate_post(
                    State(state.clone()),
                    headers,
                    Ok(Form(form)),
                )
                .await
            }
            RecoveryTokenPurpose::PasswordReset => {
                web::local_auth_recovery::local_password_reset_post(
                    State(state.clone()),
                    headers,
                    Ok(Form(form)),
                )
                .await
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::SET_COOKIE]
            .to_str()?
            .contains(web::AUTH_SESSION_COOKIE_NAME));
        assert!(!state.device.local_auth_csrf_store.try_validate(&csrf)?);
        let redeemed: bool = sqlx::query_scalar(
            "SELECT redeemed_at IS NOT NULL FROM aegaeon.end_user_recovery_tokens WHERE id=$1",
        )
        .bind(uuid::Uuid::parse_str(&token.id)?)
        .fetch_one(&state.db_pool)
        .await?;
        assert!(redeemed);
        let credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1 AND status='ACTIVE'")
            .bind(id).fetch_one(&state.db_pool).await?;
        assert_eq!(credentials, 1);
    }
    Ok(())
}
