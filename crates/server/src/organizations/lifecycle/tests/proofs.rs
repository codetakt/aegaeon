use super::*;
use crate::organizations::request_work::CapacityClass;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; empty restored state is not initial installation"]
async fn pg_lifecycle_empty_restore_keeps_barrier_without_initial_install_assertion(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.database
        .execute("CREATE SCHEMA aegaeon AUTHORIZATION aegaeon_subject_owner; CREATE TABLE aegaeon.environments(id uuid PRIMARY KEY); ALTER TABLE aegaeon.environments OWNER TO aegaeon_subject_owner")
        .await?;
    let next = Uuid::new_v4();
    f.activate(Some(f.selected.generation()), next).await?;
    let wait:i64=sqlx::query_scalar("SELECT extract(epoch FROM assertions_after-activated_at)::bigint FROM aegaeon_lifecycle.current").fetch_one(&f.database).await?;
    assert_eq!(wait, 5101, "an empty restored application still waits");
    let policy = serde_json::json!({"assertion_window":3600,"request_object_window":3600,"clock_error":300,"initial_install":true});
    assert!(
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4,$5)")
            .bind(f.selected.deployment_id())
            .bind(next)
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .bind(&policy)
            .execute(&f.database)
            .await
            .is_err()
    );
    // Fixture-only reset models first-ever installation; production cannot infer
    // this premise by deleting rows or discovering an empty restored database.
    f.database
        .execute("TRUNCATE aegaeon_lifecycle.current,aegaeon_lifecycle.activations")
        .await?;
    f.activate(None, Uuid::new_v4()).await?;
    let wait:i64=sqlx::query_scalar("SELECT extract(epoch FROM assertions_after-activated_at)::bigint FROM aegaeon_lifecycle.current").fetch_one(&f.database).await?;
    assert_eq!(
        wait, 5101,
        "no predecessor and no Environment still cannot establish first-ever installation"
    );
    f.database
        .execute("TRUNCATE aegaeon_lifecycle.current,aegaeon_lifecycle.activations")
        .await?;
    f.database
        .execute("INSERT INTO aegaeon.environments VALUES(gen_random_uuid())")
        .await?;
    assert!(
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,NULL,$2,$3,$4)")
            .bind(f.selected.deployment_id())
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .bind(&policy)
            .execute(&f.database)
            .await
            .is_err()
    );
    f.database
        .execute("DELETE FROM aegaeon.environments")
        .await?;
    sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,NULL,$2,$3,$4)")
        .bind(f.selected.deployment_id())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(&policy)
        .execute(&f.database)
        .await?;
    let wait:i64=sqlx::query_scalar("SELECT extract(epoch FROM assertions_after-activated_at)::bigint FROM aegaeon_lifecycle.current").fetch_one(&f.database).await?;
    assert_eq!(wait, 0);
    f.finish().await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_proof_policy_is_bounded_durable_and_not_reset_on_restart(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let deadlines: (i64, i64, i64) = sqlx::query_as("SELECT extract(epoch FROM assertions_after-activated_at)::bigint,extract(epoch FROM request_objects_after-activated_at)::bigint,extract(epoch FROM dpop_after-activated_at)::bigint FROM aegaeon_lifecycle.current")
        .fetch_one(&f.database).await?;
    assert_eq!(deadlines, (5101, 5101, 1801));
    for policy in [
        serde_json::json!(null),
        serde_json::json!({}),
        serde_json::json!({"assertion_window":3601,"request_object_window":3600,"clock_error":300}),
        serde_json::json!({"assertion_window":3600,"request_object_window":0,"clock_error":300}),
        serde_json::json!({"assertion_window":3600,"request_object_window":3600,"clock_error":-1}),
        serde_json::json!({"assertion_window":3600,"request_object_window":3600,"clock_error":"300"}),
        serde_json::json!({"assertion_window":3600,"request_object_window":3600,"clock_error":300,"skip":true}),
        serde_json::json!({"assertion_window":3600,"request_object_window":3600,"clock_error":300,"initial_install":"true"}),
    ] {
        assert!(
            sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4,$5)")
                .bind(f.selected.deployment_id())
                .bind(f.selected.generation())
                .bind(Uuid::new_v4())
                .bind(Uuid::new_v4())
                .bind(policy)
                .execute(&f.database)
                .await
                .is_err()
        );
    }
    let make = || {
        Runtime::checked(
            f.selected,
            PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(2)),
            f.endpoint.clone(),
            vec![(Uuid::new_v4(), "https://issuer.example".into())],
            Limits {
                ordinary: 1,
                revocation: 1,
                snapshot: 1,
            },
        )
    };
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(c) FROM aegaeon_lifecycle.current c")
            .fetch_one(&f.database)
            .await?;
    for _ in 0..2 {
        let runtime = make().await?;
        let nonce = runtime
            .start(None, CapacityClass::Ordinary, || async {
                use crate::organizations::lifecycle::proofs::{ensure_allowed, Kind};
                assert!(ensure_allowed(Kind::Assertion).is_err());
                assert!(ensure_allowed(Kind::RequestObject).is_err());
                // Deployment-level work cannot mint an Environment nonce.
                assert!(crate::organizations::lifecycle::proofs::recovery_nonce().is_err());
            })?
            .result()
            .await;
        runtime.close().await;
        nonce?;
    }
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(c) FROM aegaeon_lifecycle.current c")
            .fetch_one(&f.database)
            .await?;
    assert_eq!(before, after);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon_lifecycle.activations")
        .fetch_one(&f.database)
        .await?;
    assert_eq!(
        count, 1,
        "invalid policies and restarts do not create activation receipts"
    );
    f.finish().await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL full-schema runtime supplier"]
async fn pg_lifecycle_recovery_nonce_excludes_old_proofs_and_keeps_single_use(
) -> crate::web::test_support::TestResult {
    use crate::middleware::{dpop::DpopEndpointRole, DpopError, DpopMiddleware};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let f = crate::organizations::repository_tests::Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let previous: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT deployment_id,generation FROM aegaeon_lifecycle.current")
            .fetch_optional(&admin)
            .await?;
    let deployment = previous.map_or_else(Uuid::new_v4, |x| x.0);
    let environment = f.env.environment_id;
    let material = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let key = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&material.pkcs8)?;
    let header = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&material.public_key)}});
    let sign = |nonce: Option<&str>| -> anyhow::Result<String> {
        let claims = serde_json::json!({"htm":"POST","htu":"https://issuer.example/token","iat":crate::util::now_unix_epoch_secs()?,"jti":"recovery-proof","nonce":nonce});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?)
        ))
    };
    let mut predecessor = previous.map(|x| x.1);
    let mut old_nonce = None;
    let mut old_proof = None;
    let result: anyhow::Result<()> = async {
        for _ in 0..2 {
            let selected = Selection::new(deployment, Uuid::new_v4())?;
            sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
                .bind(deployment)
                .bind(predecessor)
                .bind(selected.generation())
                .bind(Uuid::new_v4())
                .execute(&admin)
                .await?;
            let runtime = Runtime::checked(
                selected,
                PgPoolOptions::new()
                    .max_connections(2)
                    .acquire_timeout(Duration::from_secs(2)),
                f.pool.connect_options().as_ref().clone(),
                vec![(environment, f.env.issuer_url.clone())],
                Limits {
                    ordinary: 2,
                    revocation: 1,
                    snapshot: 1,
                },
            )
            .await?;
            let middleware = std::sync::Arc::new(
                DpopMiddleware::from_postgres(
                    runtime.pool().clone(),
                    selected.namespace(environment)?.replay_namespace("dpop"),
                    "https://issuer.example".into(),
                    Duration::from_secs(601),
                )
                .with_native_verifier_for_tests(),
            );
            let verify = |proof: String, role| {
                let middleware = middleware.clone();
                runtime.start(
                    Some(environment),
                    CapacityClass::Ordinary,
                    move || async move {
                        middleware
                            .prepare_components_for(
                                role,
                                &http::Method::POST,
                                &http::Uri::from_static("/token"),
                                &proof,
                                None,
                            )?
                            .finish_async()
                            .await
                    },
                )
            };
            let stage: anyhow::Result<(String, String)> = async {
                let proof = old_proof.clone().unwrap_or(sign(None)?);
                let nonce = match verify(proof, DpopEndpointRole::AuthorizationServer)?
                    .result()
                    .await?
                {
                    Err(DpopError::UseDpopNonce(nonce)) => nonce,
                    other => anyhow::bail!("old proof must challenge, got {other:?}"),
                };
                assert_ne!(old_nonce.as_ref(), Some(&nonce));
                let signed = sign(Some(&nonce))?;
                assert!(matches!(
                    verify(signed.clone(), DpopEndpointRole::ResourceServer)?
                        .result()
                        .await?,
                    Err(DpopError::UseDpopNonce(_))
                ));
                assert!(
                    verify(signed.clone(), DpopEndpointRole::AuthorizationServer)?
                        .result()
                        .await?
                        .is_ok()
                );
                assert!(matches!(
                    verify(signed.clone(), DpopEndpointRole::AuthorizationServer)?
                        .result()
                        .await?,
                    Err(DpopError::Replay)
                ));
                Ok((nonce, signed))
            }
            .await;
            runtime.close().await;
            wait_runtime_release(&admin).await?;
            let (nonce, proof) = stage?;
            old_nonce = Some(nonce);
            old_proof = Some(proof);
            predecessor = Some(selected.generation());
        }
        Ok(())
    }
    .await;
    admin.close().await;
    f.cleanup(result.map_err(Into::into)).await
}
