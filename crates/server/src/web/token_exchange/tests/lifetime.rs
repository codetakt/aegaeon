use super::*;
use std::time::{Duration, SystemTime};

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis; waits for the configured refresh lifetime"]
async fn shared_redis_token_exchange_source_output_and_refresh_expire_online() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
            "exchange-lifetime-{}",
            uuid::Uuid::new_v4()
        ));
        // Allow client authentication and Redis publication time on busy runners.
        // The lineage horizon remains 75 seconds (access + refresh + code TTLs).
        let issuer = crate::authcode::TokenIssuer::try_from_shared_store_env_with_ttls(
            Arc::clone(&state.keys.access_token),
            15,
            45,
            15,
            &namespace,
        )?
        .with_oidc(state.oidc.config.as_deref().cloned())
        .with_issuer(env.issuer_url.clone())
        .with_token_exchange_policy(state.cfg.token_exchange.clone())
        .with_jwt_access_tokens_enabled(true);
        state.tokens.store = Arc::new(issuer.token_store.clone());
        state.tokens.issuer = Arc::new(issuer);
        state.tokens.validator = Arc::new(
            crate::authcode::TokenValidator::with_policy(
                state.tokens.store.as_ref().clone(),
                Arc::clone(&state.keys.access_token),
                state.cfg.security_policy,
            )
            .with_issuer(Some(env.issuer_url.clone()))
            .with_jwt_access_tokens_enabled(true),
        );
        state.validate_subject_namespace().await?;
        let initial = grant(&state).await?;
        let source = initial["access_token"].as_str().ok_or("source")?;
        let meta = state
            .tokens
            .store
            .try_get_bearer_meta(source)?
            .ok_or("source metadata")?;
        let root = meta
            .exchange_grant
            .as_ref()
            .and_then(|g| g.root())
            .ok_or("root")?;
        let (status, output) =
            exchange(&state, source, &[("audience", "internal-api")], true).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "live exchange: {output}; source expires at {:?}, now {:?}",
            meta.expires_at,
            SystemTime::now(),
        );
        let token = output["access_token"].as_str().ok_or("output")?;
        let output_meta = state
            .tokens
            .store
            .try_get_bearer_meta(token)?
            .ok_or("output metadata")?;
        assert!(output_meta.expires_at <= meta.expires_at && meta.expires_at <= root.expires_at);
        tokio::time::sleep(
            meta.expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                + Duration::from_millis(30),
        )
        .await;
        for expired in [source, token] {
            assert!(state
                .tokens
                .store
                .try_verify_access_token(expired)?
                .is_none());
            let (status, body) =
                exchange(&state, expired, &[("audience", "internal-api")], true).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "expired access: {body}");
        }
        let refresh = initial["refresh_token"].as_str().ok_or("refresh")?;
        let (status, fresh) = request(
            &state,
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
            true,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpired root can refresh: {fresh}"
        );
        let next = fresh["refresh_token"].as_str().ok_or("next refresh")?;
        let next_record = state
            .tokens
            .store
            .try_get_refresh_token(next)?
            .ok_or("next record")?;
        assert_eq!(
            next_record.exchange_grant.as_ref().and_then(|g| g.root()),
            Some(root)
        );
        // Rotation retains the earlier refresh deadline. This HTTP case checks
        // that deadline; the independent root guard has a dedicated script test.
        assert!(next_record.expires_at < root.expires_at);
        tokio::time::sleep(
            next_record
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                + Duration::from_millis(30),
        )
        .await;
        let (status, body) = request(
            &state,
            &[("grant_type", "refresh_token"), ("refresh_token", next)],
            true,
        )
        .await?;
        assert!(
            SystemTime::now() < root.expires_at,
            "root must still be live"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "expired refresh: {body}");
        assert!(state.tokens.store.try_get_refresh_token(next)?.is_none());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
