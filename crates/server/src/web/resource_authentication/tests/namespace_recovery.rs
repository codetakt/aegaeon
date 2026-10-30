//! Failure of the validated supplier, distinct from substituting another service.
use super::{fixture::*, policy::accepted};
use crate::web::test_support::TestResult;
use axum::{body::Body, http::StatusCode};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual pool failure and new runtime validation"]
async fn resource_authentication_namespace_pool_failure_preserves_proof_until_recovery(
) -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result: TestResult = async {
        let token = fixture.token("/resource", "read", true, false).await?;
        let proof = signed_proof("GET", "/resource", Some(&token), None)?;
        let auth = format!("DPoP {token}");
        let options = fixture.state.db_pool.connect_options().as_ref().clone();
        fixture.state.db_pool.close().await;
        let before = fixture.replay.attempts();
        let response = request(
            &fixture.state,
            "GET",
            "/resource",
            headers(Some(&auth), Some(&proof), false)?,
            Body::empty(),
        )
        .await?;
        // This failure occurs at runtime admission, before resource authentication.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("www-authenticate"));
        assert!(!response.headers().contains_key("dpop-nonce"));
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "temporarily_unavailable");
        assert_eq!(fixture.replay.attempts(), before);

        // Recovery obtains a fresh capability against the same persistent owner
        // catalog. Reopening storage alone never grants a new namespace permit.
        let reopened = sqlx::postgres::PgPoolOptions::new()
            .connect_with(options)
            .await?;
        let mut recovered =
            crate::web::test_support::test_app_state(reopened.clone(), &fixture.environment)
                .await?;
        recovered.tokens = fixture.state.tokens.clone();
        recovered.keys = fixture.state.keys.clone();
        recovered.dpop = fixture.state.dpop.clone();
        recovered.application_authority =
            Some(Arc::new(crate::application_authorization::Authority {
                projections: recovered.db_pool.clone(),
                memberships: None,
            }));
        assert!(recovered.require_subject_namespace().is_err());
        recovered.validate_subject_namespace().await?;
        assert!(fixture.state.require_subject_namespace().is_err());
        fixture.state = recovered;
        fixture.database.pool = reopened;
        let response = request(
            &fixture.state,
            "GET",
            "/resource",
            headers(Some(&auth), Some(&proof), false)?,
            Body::empty(),
        )
        .await?;
        accepted(response, "/resource").await?;
        assert!(fixture.replay.attempts() > before);
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
