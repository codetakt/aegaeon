use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn raw_assertion(payload: &str) -> TestResult<String> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = jsonwebtoken::crypto::sign(
        input.as_bytes(),
        &jsonwebtoken::EncodingKey::from_rsa_pem(PEM)?,
        jsonwebtoken::Algorithm::RS256,
    )?;
    Ok(format!("{input}.{signature}"))
}
async fn invalid_claims(state: &AppState) -> TestResult {
    for path in PATHS {
        for (key, value) in [
            ("sub", Value::Null),
            ("sub", json!(12)),
            ("sub", json!("")),
            ("sub", json!("unknown-client")),
            ("sub", json!(BASIC)),
            ("sub", json!(OTHER)),
            ("iss", json!("wrong-issuer")),
            ("aud", json!("https://other.example/token")),
            ("exp", json!(1)),
            ("iat", json!(i64::MAX)),
            ("nbf", json!(i64::MAX)),
        ] {
            let mut c = claims(state, path)?;
            c[key] = value;
            if key == "sub" && c[key].is_string() {
                c["iss"] = c[key].clone();
            }
            let jwt = sign(&c)?;
            let mut f = fields(path, &jwt);
            if path == "/par" && key == "sub" {
                if let Some(id) = c["sub"].as_str() {
                    f.iter_mut()
                        .filter(|(k, _)| *k == "client_id")
                        .for_each(|(_, v)| *v = id);
                }
            }
            reject(state, path, &f, None).await?;
        }
        for payload in [
            "{}",
            r#"{"sub":"assertion-client","sub":"assertion-client"}"#,
            r#"{"sub":"assertion-client","\u0073ub":"assertion-client"}"#,
            "[]",
            "{",
            r#"{"sub":"assertion-client"} {}"#,
        ] {
            let jwt = raw_assertion(payload)?;
            reject(state, path, &fields(path, &jwt), None).await?;
        }
        for jwt in [
            "",
            "not-jwt",
            "e30.e30",
            "e30.e30.AA.extra",
            "e30.%%%25.AA",
            "e30.e30.",
            "e30.e30.AA=",
            "e30.e30.+/",
        ] {
            reject(state, path, &fields(path, jwt), None).await?;
        }
        let oversized_header = format!("{}.e30.AA", "A".repeat(state.cfg.jose_header_max_len + 1));
        reject(state, path, &fields(path, &oversized_header), None).await?;
        let oversized_assertion =
            "A".repeat(super::super::router::SERVER_REQUEST_BODY_LIMIT_BYTES + 1);
        reject(state, path, &fields(path, &oversized_assertion), None).await?;
        let valid = sign(&claims(state, path)?)?;
        let mut parts: Vec<_> = valid.split('.').map(str::to_string).collect();
        parts[2] = URL_SAFE_NO_PAD.encode([0_u8; 256]);
        reject(state, path, &fields(path, &parts.join(".")), None).await?;
        let wrong_alg = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims(state, path)?,
            &jsonwebtoken::EncodingKey::from_secret(b"test"),
        )?;
        reject(state, path, &fields(path, &wrong_alg), None).await?;
        for id in [
            BASIC,
            " assertion-client",
            "assertion-client ",
            "Assertion-client",
            "",
        ] {
            let mut f = fields(path, &valid);
            f.retain(|(k, _)| *k != "client_id");
            f.push(("client_id", id));
            reject(state, path, &f, None).await?;
        }
        // Neither an incomplete pair nor an empty pair can become method `none`.
        for missing in ["client_assertion", "client_assertion_type"] {
            let mut f = fields(path, "");
            f.retain(|(k, _)| *k != missing && *k != "client_id");
            f.push(("client_id", PUBLIC));
            reject(state, path, &f, None).await?;
        }
        let mut f = fields(path, &valid);
        f.iter_mut()
            .filter(|(k, _)| *k == "client_assertion_type")
            .for_each(|(_, v)| *v = "unsupported");
        reject(state, path, &f, None).await?;
        let mut f = fields(path, &valid);
        f.push(("client_secret", SECRET));
        reject(state, path, &f, None).await?;
        reject(state, path, &fields(path, &valid), Some(&basic())).await?;
        let mut f = fields(path, &valid);
        f.push(("client_assertion", &valid));
        reject(state, path, &f, None).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn shared_redis_assertion_subject_rejects_invalid_signed_claims_and_malformed_credentials(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        invalid_claims(&state).await?;
        update_test_policy(&mut state, |p| p.private_key_jwt_enabled = false).await?;
        for path in PATHS {
            let jwt = sign(&claims(&state, path)?)?;
            reject(&state, path, &fields(path, &jwt), None).await?;
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[test]
#[ignore = "requires PostgreSQL and Redis; isolated environment-policy process"]
fn shared_redis_assertion_subject_parser_backend_failure_is_server_error() -> TestResult {
    const CHILD: &str = "AEGAEON_TEST_ASSERTION_BACKEND_CHILD";
    const BACKEND: &str = "AEGAEON_RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD";
    let test = concat!(
        module_path!(),
        "::shared_redis_assertion_subject_parser_backend_failure_is_server_error"
    )
    .split_once("::")
    .ok_or("test module lacks crate prefix")?
    .1;
    if let Some(marker) = std::env::var_os(CHILD) {
        assert_eq!(marker, test, "unexpected backend child marker");
        assert_eq!(std::env::var(BACKEND)?, "unsupported-test-backend");
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(backend_failure());
    }
    // Set the override only for the new process, before its runtime or threads.
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            test,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env(CHILD, test)
        .env(BACKEND, "unsupported-test-backend")
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && stdout.contains(&format!("test {test} ... ok")),
        "backend child failed or did not run exactly one test: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    Ok(())
}

async fn backend_failure() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        for path in PATHS {
            let jwt = sign(&claims(&state, path)?)?;
            let (status, body) = send(&state, path, &fields(path, &jwt), None).await?;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{path}: {body}");
            assert_eq!(body["error"], "server_error");
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
