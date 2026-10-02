use super::{fixture::*, policy::accepted};
use crate::web::test_support::TestResult;
use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderValue, StatusCode},
};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real router token revocation, audience and database errors"]
async fn resource_authentication_storage_and_authority_failures_preserve_envelopes() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        let closed = sqlx::postgres::PgPoolOptions::new()
            .connect_with(fixture.database.pool.connect_options().as_ref().clone())
            .await?;
        closed.close().await;
        for (method, path) in SURFACES {
            for dpop in [false, true] {
                let scheme = if dpop { "DPoP" } else { "Bearer" };
                for refusal in ["revoked", "audience"] {
                    let token = fixture.token(path, "openid read", dpop, false).await?;
                    if refusal == "revoked" {
                        fixture.state.tokens.store.try_revoke_token(&token)?;
                    } else {
                        let mut meta = fixture
                            .state
                            .tokens
                            .store
                            .try_get_bearer_meta(&token)?
                            .ok_or("fixture metadata")?;
                        meta.audience = "https://other.example/resource".into();
                        fixture
                            .state
                            .tokens
                            .store
                            .try_replace_bearer_meta_record(meta)?;
                    }
                    let proof = dpop
                        .then(|| signed_proof(method, path, Some(&token), None))
                        .transpose()?;
                    expect(
                        request(
                            &fixture.state,
                            method,
                            path,
                            headers(
                                Some(&format!("{scheme} {token}")),
                                proof.as_deref(),
                                method == "POST",
                            )?,
                            Body::empty(),
                        )
                        .await?,
                        StatusCode::UNAUTHORIZED,
                        Some(scheme),
                        Some("invalid_token"),
                        false,
                    )
                    .await?;
                }
                if path == "/oauth/upstream/refresh" {
                    continue;
                }
                let token = fixture.token(path, "openid read", dpop, false).await?;
                let mut unavailable = fixture.state.clone();
                let (status, error) = match path {
                    "/userinfo" => {
                        unavailable.oidc.userinfo_endpoint =
                            Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
                                fixture.state.tokens.validator.as_ref().clone(),
                                closed.clone(),
                                fixture.environment.issuer_url.clone(),
                            )));
                        (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
                    }
                    _ => {
                        let mut meta = fixture
                            .state
                            .tokens
                            .store
                            .try_get_bearer_meta(&token)?
                            .ok_or("fixture metadata")?;
                        meta.application_grant = crate::application_authorization::store::capture(
                            &fixture.database.pool,
                            fixture.environment.environment_id,
                            &fixture.environment.issuer_url,
                            "resource-auth-client",
                            "resource-auth-subject",
                        )
                        .await?;
                        assert!(meta.application_grant.is_some());
                        fixture
                            .state
                            .tokens
                            .store
                            .try_replace_bearer_meta_record(meta)?;
                        unavailable.application_authority =
                            Some(crate::application_authorization::Authority {
                                projections: closed.clone(),
                                memberships: None,
                            });
                        (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
                    }
                };
                let auth = format!("{scheme} {token}");
                let proof = dpop
                    .then(|| signed_proof(method, path, Some(&token), None))
                    .transpose()?;
                expect(
                    request(
                        &unavailable,
                        method,
                        path,
                        headers(Some(&auth), proof.as_deref(), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    status,
                    None,
                    Some(error),
                    false,
                )
                .await?;
                let proof = dpop
                    .then(|| signed_proof(method, path, Some(&token), None))
                    .transpose()?;
                accepted(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), proof.as_deref(), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    path,
                )
                .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; direct handler certificate metadata and router ingress distinction"]
async fn resource_authentication_certificate_metadata_and_ingress_remain_distinct() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.state.transport =
        crate::middleware::TransportSecurity::new(crate::config::TransportSecurityConfig {
            require_tls_proxy: true,
            require_proxy_mtls: false,
            trusted_proxies: vec!["127.0.0.1/32".parse()?],
            max_proxy_hops: 1,
            log_forwarded_values: false,
        });
    let result=async {
        for (method,path) in SURFACES {
            for scheme in ["Bearer","DPoP"] {
                let token=fixture.token(path,"openid read",scheme=="DPoP",false).await?;
                let proof=(scheme=="DPoP").then(||signed_proof(method,path,Some(&token),None)).transpose()?;
                let mut hs=headers(Some(&format!("{scheme} {token}")),proof.as_deref(),method=="POST")?;
                hs.insert("x-forwarded-proto",HeaderValue::from_static("https"));
                hs.insert("x-forwarded-client-cert",HeaderValue::from_static("invalid-fingerprint"));
                // The full router refuses invalid certificate metadata at its earlier ingress boundary.
                expect(request(&fixture.state,method,path,hs.clone(),Body::empty()).await?,StatusCode::UNAUTHORIZED,Some("Bearer"),Some("invalid_token"),false).await?;
                let state=State(fixture.state.clone());let remote=ConnectInfo("127.0.0.1:19001".parse()?);let uri=OriginalUri(path.parse()?);
                let response=match (method,path) {
                    (_,"/resource")=>crate::web::resource_endpoint::resource(state,remote,uri,method.parse()?,hs).await,
                    ("POST","/userinfo")=>crate::web::userinfo::userinfo_post(state,remote,uri,hs,Ok(axum::body::Bytes::new())).await,
                    (_,"/userinfo"|"/application/authorization")=>crate::web::userinfo::userinfo_get(state,remote,uri,method.parse()?,hs).await,
                    _=>match crate::web::upstream_refresh_links::authenticate_upstream_refresh_caller(&fixture.state,&path.parse()?,&hs,&fixture.environment.issuer_url).await {Err(response)=>response,Ok(_)=>return Err("invalid certificate metadata accepted".into())},
                };
                expect(response,StatusCode::BAD_REQUEST,Some(scheme),Some("invalid_request"),false).await?;
            }
        }
        Ok::<(),Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; router lookup after native proof and token authentication"]
async fn resource_authentication_upstream_caller_authority_errors_retain_presented_scheme(
) -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        let path = "/oauth/upstream/refresh";
        for scheme in ["Bearer", "DPoP"] {
            let token = fixture
                .token(path, "openid read", scheme == "DPoP", false)
                .await?;
            let mut access = fixture
                .state
                .tokens
                .store
                .try_verify_access_token(&token)?
                .ok_or("fixture access token")?;
            let mut meta = fixture
                .state
                .tokens
                .store
                .try_get_bearer_meta(&token)?
                .ok_or("fixture metadata")?;
            access.client_id = "unregistered-fixture-client".into();
            meta.client_id = access.client_id.clone();
            fixture
                .state
                .tokens
                .store
                .try_replace_access_token_record(access)?;
            fixture
                .state
                .tokens
                .store
                .try_replace_bearer_meta_record(meta)?;
            let proof = (scheme == "DPoP")
                .then(|| signed_proof("POST", path, Some(&token), None))
                .transpose()?;
            let response = request(
                &fixture.state,
                "POST",
                path,
                headers(Some(&format!("{scheme} {token}")), proof.as_deref(), true)?,
                Body::empty(),
            )
            .await?;
            let body = expect(
                response,
                StatusCode::UNAUTHORIZED,
                Some(scheme),
                Some("invalid_token"),
                false,
            )
            .await?;
            assert_eq!(
                body["error_description"],
                "caller client environment is unavailable"
            );
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
