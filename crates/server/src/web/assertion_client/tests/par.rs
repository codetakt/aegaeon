use super::*;

fn request_object(state: &AppState, id: &str) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    let claims = json!({"iss":id,"client_id":id,"aud":state.issuer.as_str(),"iat":now,"exp":now+30,"jti":Uuid::new_v4().to_string(),
        "response_type":"code","redirect_uri":REDIRECT,"scope":"api.read","state":"par-state","code_challenge":CHALLENGE,"code_challenge_method":"S256"});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PEM)?,
    )?)
}
async fn exercise(state: &AppState) -> TestResult {
    let basic = basic();
    for auth in [None, Some(basic.as_str())] {
        let jwt = sign(&claims(state, "/par")?)?;
        let mut pairs = fields("/par", &jwt);
        pairs.retain(|(k, _)| {
            *k != "client_id" && (auth.is_none() || !k.starts_with("client_assertion"))
        });
        let count = par_count(state)?;
        let (status, body) = send(state, "/par", &pairs, auth).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        assert!(body.get("request_uri").is_none());
        assert_eq!(par_count(state)?, count);
        // Missing plain-PAR identification must not consume assertion replay state.
        if auth.is_none() {
            let mut explicit = fields("/par", &jwt);
            explicit.push(("iss", state.issuer.as_str()));
            let (status, body) = send(state, "/par", &explicit, None).await?;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
    }
    Ok(())
}

async fn signed_requests(state: &AppState) -> TestResult {
    let basic = basic();
    for id in [CLIENT, BASIC] {
        let request = request_object(state, id)?;
        let jwt = sign(&claims(state, "/par")?)?;
        let mut pairs = vec![("request", request.as_str())];
        let auth = if id == BASIC {
            Some(basic.as_str())
        } else {
            pairs.extend([
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", jwt.as_str()),
            ]);
            None
        };
        let count = par_count(state)?;
        let (status, body) = send(state, "/par", &pairs, auth).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        assert!(body.get("request_uri").is_none());
        assert_eq!(par_count(state)?, count);
        // Reuse both signed values: rejection must consume neither replay entry.
        pairs.push(("client_id", id));
        let (status, body) = send(state, "/par", &pairs, auth).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let uri = body["request_uri"].as_str().ok_or("request uri")?;
        let stored = state
            .protocol
            .par_store
            .try_consume_request(uri)
            .map_err(|e| format!("{e:?}"))?
            .ok_or("stored request")?;
        assert_eq!(stored.client_id, id);
        assert!(stored.client_authenticated);
        assert!(stored.client_secret.is_none());
        assert_eq!(
            stored
                .request_object_claims
                .ok_or("signed claims")?
                .client_id
                .as_deref(),
            Some(id)
        );
    }
    let other_request = request_object(state, BASIC)?;
    let jwt = sign(&claims(state, "/par")?)?;
    let count = par_count(state)?;
    let (status, body) = send(
        state,
        "/par",
        &[
            ("client_id", CLIENT),
            ("request", &other_request),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &jwt),
        ],
        None,
    )
    .await?;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(par_count(state)?, count);
    assert!(body.get("request_uri").is_none());
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn shared_redis_assertion_subject_par_requires_outer_identity_for_plain_and_signed_requests(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        exercise(&state).await?;
        signed_requests(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
