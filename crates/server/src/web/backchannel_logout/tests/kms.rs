use super::*;
use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD;
use std::sync::Mutex;

const KEY_ID: &str = "fixture-rsa-signing-key";
const PUBLIC_PEM: &str = include_str!("../../../../tests/fixtures/rsa2048-public.pem");

#[derive(Clone, Default)]
struct KmsFixture {
    requests: Arc<Mutex<Vec<Value>>>,
    omit_signature: bool,
}

async fn kms_request(
    State(state): State<KmsFixture>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    assert_eq!(headers["content-type"], "application/x-amz-json-1.1");
    let body: Value = serde_json::from_slice(&body).expect("AWS JSON request");
    assert_eq!(body["KeyId"], KEY_ID);
    match headers["x-amz-target"].to_str().expect("target") {
        "TrentService.GetPublicKey" => Json(json!({
            "PublicKey":STANDARD.encode(pem::parse(PUBLIC_PEM).expect("public PEM").contents()),
            "KeySpec":"RSA_2048", "KeyUsage":"SIGN_VERIFY", "SigningAlgorithms":["RSASSA_PKCS1_V1_5_SHA_256"]
        })),
        "TrentService.Sign" => {
            assert_eq!(body["MessageType"], "RAW");
            assert_eq!(body["SigningAlgorithm"], "RSASSA_PKCS1_V1_5_SHA_256");
            let input = STANDARD
                .decode(body["Message"].as_str().expect("message"))
                .expect("base64 message");
            state.requests.lock().expect("requests").push(body);
            if state.omit_signature {
                return Json(json!({}));
            }
            let key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes())
                .expect("private PEM");
            let signature =
                jsonwebtoken::crypto::sign(&input, &key, jsonwebtoken::Algorithm::RS256)
                    .expect("local signature");
            Json(
                json!({"Signature":STANDARD.encode(URL_SAFE_NO_PAD.decode(signature).expect("signature bytes"))}),
            )
        }
        _ => panic!("unexpected KMS operation"),
    }
}

async fn fixture_key(state: KmsFixture) -> TestResult<(OidcSigningKey, FixtureTask)> {
    let app = Router::new()
        .route("/", post(kms_request))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let task = FixtureTask(tokio::spawn(async move {
        axum::serve(listener, app).await.expect("KMS fixture");
    }));
    // Explicit fake credentials and endpoint: never consult an ambient AWS provider.
    let sdk = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            "fixture",
            "fixture",
            None,
            None,
            "local-test",
        ))
        .endpoint_url(endpoint)
        .retry_config(aws_sdk_kms::config::retry::RetryConfig::disabled())
        .timeout_config(
            aws_sdk_kms::config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(5))
                .build(),
        )
        .build();
    let key = OidcSigningKey::from_test_kms_client(
        aws_sdk_kms::Client::from_conf(sdk),
        KEY_ID.to_string(),
        KID.to_string(),
    )
    .await?;
    Ok((key, task))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_profile_kms_sdk_sign_input_and_local_signature_parity() -> TestResult {
    let state = KmsFixture::default();
    let (key, _fixture) = fixture_key(state.clone()).await?;
    let cfg = config(key);
    let local = local_key()?;
    for sub in [None, Some("subject")] {
        let sync = build_backchannel_logout_token(&cfg, "client", "session", sub, "logout-event")
            .map_err(anyhow::Error::msg)?;
        let asynchronous =
            build_backchannel_logout_token_async(&cfg, "client", "session", sub, "logout-event")
                .await
                .map_err(anyhow::Error::msg)?;
        for token in [sync, asynchronous] {
            let claims = verify_logout(&cfg.signing_key, &token, "client", sub)?;
            assert_eq!(token, local.sign_logout_token(&claims)?);
            let request = state
                .requests
                .lock()
                .expect("requests")
                .iter()
                .find(|request| {
                    let input = STANDARD
                        .decode(request["Message"].as_str().expect("message"))
                        .expect("base64");
                    token.starts_with(&format!("{}.", String::from_utf8(input).expect("UTF-8")))
                })
                .cloned();
            assert!(
                request.is_some(),
                "actual SDK request must contain signed header and payload"
            );
        }
    }
    let id = crate::oidc::IdTokenBuilder::try_new(
        ISSUER.to_string(),
        "subject".to_string(),
        "client".to_string(),
    )
    .map_err(anyhow::Error::msg)?
    .nonce("login-nonce".to_string())
    .build();
    for token in [
        cfg.signing_key.sign_rs256_jwt(&id.claims)?,
        cfg.signing_key.sign_rs256_jwt_async(&id.claims).await?,
    ] {
        assert_eq!(
            verify_token(&cfg.signing_key, &token, "JWT")?,
            serde_json::to_value(&id.claims)?
        );
        assert_eq!(token, local.sign_rs256_jwt(&id.claims)?);
    }
    assert_eq!(state.requests.lock().expect("requests").len(), 6);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_profile_kms_missing_signature_fails_closed() -> TestResult {
    let state = KmsFixture {
        omit_signature: true,
        ..KmsFixture::default()
    };
    let (key, _fixture) = fixture_key(state.clone()).await?;
    let cfg = config(key);
    assert!(
        build_backchannel_logout_token(&cfg, "client", "session", None, "logout-event").is_err()
    );
    assert!(
        build_backchannel_logout_token_async(&cfg, "client", "session", None, "logout-event")
            .await
            .is_err()
    );
    assert_eq!(state.requests.lock().expect("requests").len(), 2);
    Ok(())
}
