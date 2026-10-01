use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn request_object_resource(state: &AppState, resource: &str) -> TestResult<String> {
    let jwt = super::par::request_object(state, BASIC)?;
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("payload")?)?)?;
    claims["resource"] = json!(resource);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PEM)?,
    )?)
}
async fn resource_requests(state: &AppState) -> TestResult {
    const RESOURCE: &str = "HTTPS://resource.example:443/a%20b/%2f";
    for resource in [
        RESOURCE.to_string(),
        format!(" {RESOURCE}"),
        format!("{RESOURCE} "),
        format!("{RESOURCE}\t"),
        format!("{RESOURCE}\0"),
        format!("{RESOURCE}\u{00a0}"),
    ] {
        let valid = resource == RESOURCE;
        for source in ["device", "par", "jar"] {
            let request = request_object_resource(state, &resource)?;
            let mut f = fields("/par", "");
            f.retain(|(k, _)| !k.starts_with("client_assertion") && *k != "client_id");
            f.extend([
                ("client_id", BASIC),
                ("iss", state.issuer.as_str()),
                ("resource", resource.as_str()),
            ]);
            let path = match source {
                "device" => {
                    f = vec![("resource", &resource), ("scope", "api.read")];
                    "/device_authorization"
                }
                "jar" => {
                    f = vec![
                        ("request", &request),
                        ("unknown", ""),
                        ("scope", ""),
                        ("client_id", ""),
                    ];
                    if valid {
                        let mut excluded = f.clone();
                        excluded.push(("unknown", "nonempty"));
                        reject(state, "/par", &excluded, Some(&basic())).await?;
                    }
                    "/par"
                }
                _ => "/par",
            };
            let device_before = state.device.code_store.try_active_count()?;
            let par_before = par_count(state)?;
            let (status, body) = send(state, path, &f, Some(&basic())).await?;
            if valid {
                assert_eq!(
                    status,
                    if path == "/par" {
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    },
                    "{source}: {body}"
                );
                if path == "/par" {
                    let stored = state
                        .protocol
                        .par_store
                        .try_consume_request(body["request_uri"].as_str().ok_or("request uri")?)
                        .map_err(|e| format!("{e:?}"))?
                        .ok_or("stored request")?;
                    assert_eq!(stored.resource.as_deref(), Some(RESOURCE));
                } else {
                    assert_eq!(
                        state.device.code_store.try_active_count()?,
                        device_before + 1
                    );
                }
            } else {
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "{source} {resource:?}: {body}"
                );
                assert_eq!(body["error"], "invalid_target", "{source}: {body}");
                assert_eq!(state.device.code_store.try_active_count()?, device_before);
                assert_eq!(par_count(state)?, par_before);
            }
        }
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_forms_resource_spelling_and_whitespace_are_preserved_at_routes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { resource_requests(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
