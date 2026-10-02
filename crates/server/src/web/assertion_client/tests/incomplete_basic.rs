//! Application HeaderMap admission; these tests do not establish wire normalization.
mod boundaries;
mod effects;
use super::client_auth_errors::{borrowed, password_fields, successful_response};
use super::*;

fn incomplete_headers() -> Vec<String> {
    vec![
        "Basic".into(),
        "bAsIc".into(),
        "Basic ".into(),
        "Basic\t".into(),
        " \tBaSiC \t ".into(),
        "Basic not-base64".into(),
        format!("Basic {}", STANDARD.encode([0xff, b':', b'x'])),
        format!("Basic {}", STANDARD.encode("missing-colon")),
        format!("{} ", basic()),
    ]
}

fn stored_values(state: &AppState) -> TestResult<std::collections::BTreeMap<String, Vec<u8>>> {
    let mut connection =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("aegaeon:{{runtime:{}:*", state.environment_id))
        .query(&mut connection)?;
    keys.into_iter()
        .map(|key| {
            let value = redis::cmd("DUMP").arg(&key).query(&mut connection)?;
            Ok((key, value))
        })
        .collect()
}

async fn refusal_matrix(state: &AppState) -> TestResult {
    for path in PATHS {
        for auth in incomplete_headers() {
            let before = stored_values(state)?;
            for client in [BASIC, PUBLIC] {
                let mut f = password_fields(path, client);
                // Effective omission and grant assertion do not create client methods.
                f.extend([
                    ("client_secret".into(), "".into()),
                    ("client_assertion".into(), "".into()),
                    ("client_assertion_type".into(), "".into()),
                ]);
                if path == "/token" {
                    f.push(("assertion".into(), "grant-assertion".into()));
                }
                reject(state, path, &borrowed(&f), Some(&auth)).await?;
            }
            for secret in [SECRET, " "] {
                let mut f = password_fields(path, POST);
                f.push(("client_secret".into(), secret.into()));
                reject_request(state, path, &borrowed(&f), Some(&auth)).await?;
            }
            assert!(
                before == stored_values(state)?,
                "early refusal changed stored values"
            );
            for with_post in [false, true] {
                let jwt = sign(&claims(state, path)?)?;
                let mut f = fields(path, &jwt);
                if with_post {
                    f.push(("client_secret", SECRET));
                }
                let before = stored_values(state)?;
                reject(state, path, &f, Some(&auth)).await?;
                assert!(
                    before == stored_values(state)?,
                    "mixture changed stored values"
                );
                successful_response(state, path, &fields(path, &jwt), None).await?;
                reject(state, path, &fields(path, &jwt), None).await?;
            }
        }
    }
    Ok(())
}

async fn controls(state: &AppState) -> TestResult {
    let payload = STANDARD.encode(format!("{BASIC}:{SECRET}"));
    for path in PATHS {
        for auth in [basic(), format!(" \tbAsIc\t {payload}")] {
            successful_response(
                state,
                path,
                &borrowed(&password_fields(path, BASIC)),
                Some(&auth),
            )
            .await?;
        }
        let mut post = password_fields(path, POST);
        post.push(("client_secret".into(), SECRET.into()));
        successful_response(state, path, &borrowed(&post), None).await?;
        // Non-Basic values retain the prior endpoint policy; no new classification.
        for auth in ["Basicx value", "Basic:value", "", " ", "Bearer value"] {
            if path == "/par" {
                reject(state, path, &borrowed(&post), Some(auth)).await?;
            } else {
                successful_response(state, path, &borrowed(&post), Some(auth)).await?;
            }
        }
        if path != "/token" {
            successful_response(state, path, &borrowed(&password_fields(path, PUBLIC)), None)
                .await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn incomplete_basic_on_five_routes_rejects_before_fallback_and_preserves_replay() -> TestResult
{
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        refusal_matrix(&state).await?;
        controls(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[test]
fn basic_attempt_recognition_keeps_public_payload_presence_contract() {
    use crate::client_registry::ClientRegistry;
    for header in ["Basic", "bAsIc", "Basic ", " \tBasic\t "] {
        assert!(ClientRegistry::basic_auth_attempted(header));
        assert!(!ClientRegistry::basic_auth_present(header));
        assert!(ClientRegistry::decode_basic_auth_credentials(header).is_none());
    }
    for header in ["", " ", "\t", "Basicx value", "Basic:value", "Bearer value"] {
        assert!(!ClientRegistry::basic_auth_attempted(header));
        assert!(!ClientRegistry::basic_auth_present(header));
    }
    assert!(ClientRegistry::basic_auth_present("Basic not-base64"));
}
