use super::*;

fn basic_fields(path: &str) -> Vec<(&str, &str)> {
    let mut f = fields(path, "");
    f.retain(|(k, _)| !k.starts_with("client_assertion"));
    if path == "/par" {
        f.iter_mut()
            .filter(|(k, _)| *k == "client_id")
            .for_each(|(_, v)| *v = BASIC);
    }
    f
}
async fn issue(state: &AppState) -> TestResult<String> {
    let (status, body) = send(state, "/token", &basic_fields("/token"), Some(&basic())).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["access_token"]
        .as_str()
        .ok_or("issued access token")?
        .into())
}
async fn successful(state: &AppState, path: &str, suffix: &str) -> TestResult {
    let token = issue(state).await?;
    let mut f = basic_fields(path);
    if path == "/par" {
        f.push(("iss", state.issuer.as_str()));
    }
    if matches!(path, "/revoke" | "/introspect") {
        f.iter_mut()
            .filter(|(k, _)| *k == "token")
            .for_each(|(_, v)| *v = &token);
    }
    let before = state.device.code_store.try_active_count()?;
    let encoded = format!("{}{}", serde_urlencoded::to_string(f)?, suffix);
    let (status, body) = send_raw(state, path, &encoded, Some(&basic())).await?;
    assert_eq!(
        status,
        if path == "/par" {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        "{path} {suffix}: {body}"
    );
    match path {
        "/token" => assert!(state
            .tokens
            .store
            .try_verify_access_token(body["access_token"].as_str().ok_or("access token")?)?
            .is_some()),
        "/device_authorization" => {
            assert_eq!(state.device.code_store.try_active_count()?, before + 1)
        }
        "/introspect" => assert_eq!(body["active"], true),
        "/revoke" => assert!(state
            .tokens
            .store
            .try_verify_access_token(&token)?
            .is_none()),
        "/par" => {
            let stored = state
                .protocol
                .par_store
                .try_consume_request(body["request_uri"].as_str().ok_or("request uri")?)
                .map_err(|e| format!("{e:?}"))?
                .ok_or("stored PAR")?;
            assert!(stored.client_authenticated);
            assert!(stored.client_secret.is_none());
            assert_eq!(stored.client_id, BASIC);
            assert_eq!(stored.max_age, None);
        }
        _ => unreachable!(),
    }
    Ok(())
}
async fn basic_admission(state: &AppState) -> TestResult {
    for path in PATHS {
        for suffix in [
            "",
            "&client_id=&client_secret=&client_assertion_type=&client_assertion=",
            "&client_id&client_secret&client_assertion_type&client_assertion",
            "&%63lient_id=&client_%73ecret=&unknown=&unknown=value",
            "&max_age=&resource=&scope=&token=&grant_type=&device_code=",
        ] {
            successful(state, path, suffix).await?;
        }
        let live = if matches!(path, "/introspect" | "/revoke") {
            Some(issue(state).await?)
        } else {
            None
        };
        let mut base = basic_fields(path);
        if let Some(token) = live.as_deref() {
            base.iter_mut()
                .filter(|(k, _)| *k == "token")
                .for_each(|(_, v)| *v = token);
        }
        let singleton = if path == "/token" {
            "grant_type"
        } else if matches!(path, "/introspect" | "/revoke") {
            "token"
        } else {
            "scope"
        };
        let value = base
            .iter()
            .find(|(k, _)| *k == singleton)
            .ok_or("singleton")?
            .1;
        for extra in [
            format!("&{singleton}={value}"),
            format!(
                "&%{:02X}{}={value}",
                singleton.as_bytes()[0],
                &singleton[1..]
            ),
        ] {
            let encoded = format!("{}{extra}", serde_urlencoded::to_string(&base)?);
            let before = state.device.code_store.try_active_count()?;
            let par_before = par_count(state)?;
            let (status, body) = send_raw(state, path, &encoded, Some(&basic())).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body["error"], "invalid_request");
            assert_eq!(state.device.code_store.try_active_count()?, before);
            assert_eq!(par_count(state)?, par_before);
            if let Some(token) = live.as_deref() {
                assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
            }
            for key in ["access_token", "active", "device_code", "request_uri"] {
                assert!(body.get(key).is_none());
            }
        }
        for value in [" ", "basic-client ", "Basic-client"] {
            let mut f = base.clone();
            f.retain(|(k, _)| *k != "client_id");
            f.push(("client_id", value));
            reject(state, path, &f, Some(&basic())).await?;
        }
        let mut whitespace_secret = base.clone();
        whitespace_secret.push(("client_secret", " "));
        reject(state, path, &whitespace_secret, Some(&basic())).await?;
        let empty_password = format!("Basic {}", STANDARD.encode(format!("{BASIC}:")));
        reject(state, path, &base, Some(&empty_password)).await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_forms_basic_omission_duplicates_and_exact_identity_on_five_routes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { basic_admission(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn assertions(state: &AppState) -> TestResult {
    for path in PATHS {
        let jwt = sign(&claims(state, path)?)?;
        let mut f = fields(path, &jwt);
        if path == "/par" {
            f.push(("iss", state.issuer.as_str()));
        }
        f.extend([
            ("client_id", ""),
            ("client_assertion", ""),
            ("client_assertion_type", ""),
            ("client_secret", ""),
        ]);
        let (status, body) = send(state, path, &f, None).await?;
        assert_eq!(
            status,
            if path == "/par" {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            "{path}: {body}"
        );
        reject(state, path, &f, None).await?; // successful authentication consumed this assertion once
        let mut f = basic_fields(path);
        f.retain(|(k, _)| *k != "client_id");
        f.push(("client_id", PUBLIC));
        for extra in [
            vec![("client_secret", " ")],
            vec![("client_assertion", " ")],
            vec![("client_assertion_type", " ")],
            vec![
                ("client_assertion", "malformed"),
                ("client_assertion_type", ASSERTION_TYPE),
            ],
        ] {
            let mut invalid = f.clone();
            invalid.extend(extra);
            reject(state, path, &invalid, None).await?;
        }
    }
    for empty in [
        vec![],
        vec![("client_assertion", ""), ("client_assertion_type", "")],
    ] {
        let mut f = vec![("client_id", PUBLIC), ("scope", "api.read")];
        f.extend(empty);
        let (status, body) = send(state, "/device_authorization", &f, None).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["device_code"].is_string());
    }
    for (path, required) in [
        ("/token", "grant_type"),
        ("/par", "client_id"),
        ("/introspect", "token"),
        ("/revoke", "token"),
    ] {
        for value in [None, Some("")] {
            let mut f = basic_fields(path);
            f.retain(|(k, _)| *k != required);
            if let Some(value) = value {
                f.push((required, value));
            }
            reject(state, path, &f, Some(&basic())).await?;
        }
    }
    reject(state, "/device_authorization", &[("client_id", "")], None).await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_forms_assertion_omission_public_clients_and_required_fields() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { assertions(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
