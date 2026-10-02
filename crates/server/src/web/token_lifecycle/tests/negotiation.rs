use super::*;
use crate::kms::{KeyManager, KeyManagerError};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountSigner {
    inner: Arc<dyn KeyManager>,
    calls: AtomicUsize,
}

impl KeyManager for CountSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, KeyManagerError> {
        self.inner.verify(message, signature)
    }
    fn key_id(&self) -> String {
        self.inner.key_id()
    }
    fn jwt_signing_alg(&self) -> &'static str {
        self.inner.jwt_signing_alg()
    }
    fn jwt_signing_public_jwk(&self) -> Option<Value> {
        self.inner.jwt_signing_public_jwk()
    }
    fn rotate(&self) -> Result<(), KeyManagerError> {
        self.inner.rotate()
    }
    fn revoke(&self) -> Result<(), KeyManagerError> {
        self.inner.revoke()
    }
}

async fn request(
    state: &AppState,
    token: &str,
    caller: &str,
    accepts: &[&[u8]],
) -> TestResult<Response> {
    let mut builder = Request::post("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let mut fields = vec![("token", token)];
    if caller == crate::resource_audience::protected_resource(state.issuer.as_str()) {
        fields.extend([("client_id", caller), ("client_secret", SECRET)]);
    } else {
        builder = builder.header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{caller}:{SECRET}"))),
        );
    }
    for value in accepts {
        builder = builder.header(header::ACCEPT, axum::http::HeaderValue::from_bytes(value)?);
    }
    Ok(router(state)
        .oneshot(builder.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?)
}

async fn success(
    response: Response,
    state: &AppState,
    caller: &str,
    jwt: bool,
    active: bool,
) -> TestResult {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        if jwt {
            "application/token-introspection+jwt"
        } else {
            "application/json"
        }
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let body: Value = if jwt {
        verify_response(state, std::str::from_utf8(&bytes)?, caller)?
    } else {
        serde_json::from_slice(&bytes)?
    };
    if active {
        assert_eq!(body["active"], true);
        assert!(body.get("username").is_none());
    } else {
        assert_eq!(body, json!({"active":false}));
    }
    Ok(())
}

async fn error(response: Response, state: &AppState, status: StatusCode) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(
        body,
        json!({"error":"invalid_request","error_description":if status == StatusCode::BAD_REQUEST { "Malformed introspection Accept header" } else { "No acceptable introspection representation" },"iss":state.issuer.as_str()})
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_negotiation_shares_selection_with_recipient_and_output() -> TestResult {
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let (access, refresh, meta) = grant(&fixture.state, false, None);
        let audience = meta.audience.clone();
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        for (accepts, jwt) in [
            (vec![], false),
            (vec![b"application/*".as_slice()], false),
            (
                vec![
                    b"application/*+jwt,app*/json,*/json,application/**".as_slice(),
                    b"application/json".as_slice(),
                ],
                false,
            ),
            (
                vec![b"application/token-introspection+jwt-extra,application/json".as_slice()],
                false,
            ),
            (
                vec![
                    b"application/json;q=0.9,application/token-introspection+jwt;q=0.1".as_slice(),
                ],
                false,
            ),
            (
                vec![b"Application/Token-Introspection+Jwt".as_slice()],
                true,
            ),
            (
                vec![
                    b"application/json;q=0.5".as_slice(),
                    b"application/token-introspection+jwt;q=0.5".as_slice(),
                ],
                true,
            ),
            (
                vec![
                    b"text/plain;note=\"\xff,a\",application/token-introspection+jwt;q=0.5"
                        .as_slice(),
                ],
                true,
            ),
        ] {
            for (token, caller, active) in [
                (&access.token, OWNER, !jwt),
                (&access.token, audience.as_str(), true),
                (&access.token, OTHER, false),
                (&"unknown-token".to_string(), OWNER, false),
            ] {
                success(
                    request(&fixture.state, token, caller, &accepts).await?,
                    &fixture.state,
                    caller,
                    jwt,
                    active,
                )
                .await?;
            }
        }
        update_test_policy(&mut fixture.state, |policy| {
            policy.jwt_introspection_enabled = false
        })
        .await?;
        error(
            request(
                &fixture.state,
                &access.token,
                OWNER,
                &[b"application/token-introspection+jwt"],
            )
            .await?,
            &fixture.state,
            StatusCode::NOT_ACCEPTABLE,
        )
        .await?;
        success(
            request(
                &fixture.state,
                &access.token,
                OWNER,
                &[b"application/token-introspection+jwt,application/json;q=0.001"],
            )
            .await?,
            &fixture.state,
            OWNER,
            false,
            true,
        )
        .await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_negotiation_errors_precede_observation_signing_and_success_metrics(
) -> TestResult {
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let signer = Arc::new(CountSigner {
            inner: fixture
                .state
                .keys
                .jwt_introspection
                .clone()
                .ok_or("signer missing")?,
            calls: AtomicUsize::new(0),
        });
        fixture.state.keys.jwt_introspection = Some(signer.clone());
        // An observed corrupt record always fails before visibility; a positive control below
        // confirms the real Redis observation seam is reached with an acceptable request.
        let broken = "negotiation-storage-sentinel";
        let _: () = fixture
            .connection()?
            .set_ex(fixture.key("access", broken), "{", 300)?;
        let before = super::failures::metrics()?;
        for (accept, status) in [
            (
                b"application/json;q=broken".as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                b"application/json;q=1;Q=0".as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                b"application/json;value=\xff".as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                b"application/json;q=0,*/*".as_slice(),
                StatusCode::NOT_ACCEPTABLE,
            ),
            (
                b"application/token-introspection+jwt;q=0".as_slice(),
                StatusCode::NOT_ACCEPTABLE,
            ),
            (b"".as_slice(), StatusCode::NOT_ACCEPTABLE),
            (b"*/json".as_slice(), StatusCode::NOT_ACCEPTABLE),
        ] {
            error(
                request(&fixture.state, broken, OWNER, &[accept]).await?,
                &fixture.state,
                status,
            )
            .await?;
            assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
            assert_eq!(super::failures::metrics()?, before);
        }
        assert_eq!(
            request(&fixture.state, broken, OWNER, &[b"application/json"])
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(super::failures::metrics()?, before);
        success(
            request(
                &fixture.state,
                "unknown-token",
                OWNER,
                &[b"application/token-introspection+jwt"],
            )
            .await?,
            &fixture.state,
            OWNER,
            true,
            false,
        )
        .await?;
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(super::failures::metrics()?, (before.0, before.1 + 1.0));
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_negotiation_preserves_authentication_and_required_token_precedence(
) -> TestResult {
    let fixture = Fixture::new(true).await?;
    let result = async {
        for (secret, status, code) in [
            (None, StatusCode::BAD_REQUEST, "invalid_client"),
            (Some("wrong"), StatusCode::UNAUTHORIZED, "invalid_client"),
            (Some(SECRET), StatusCode::BAD_REQUEST, "invalid_request"),
        ] {
            let mut builder = Request::post("/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ACCEPT, "application/json;q=malformed");
            if let Some(secret) = secret {
                builder = builder.header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{OWNER}:{secret}"))),
                );
            }
            let before = super::failures::metrics()?;
            let response = router(&fixture.state)
                .oneshot(builder.body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
            if status == StatusCode::UNAUTHORIZED {
                assert_eq!(
                    response.headers()[header::WWW_AUTHENTICATE],
                    "Basic realm=\"token_introspection\", error=\"invalid_client\""
                );
            } else {
                assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
            }
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
            assert_eq!(body["error"], code);
            if secret == Some(SECRET) {
                assert_eq!(body["error_description"], "token parameter required");
            }
            assert_ne!(
                body["error_description"],
                "Malformed introspection Accept header"
            );
            assert_eq!(super::failures::metrics()?, before);
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
