use super::*;
use redis::Commands;
use simple_asn1::{to_der, ASN1Block, BigInt, BigUint};
type RsaFixture = (Value, Vec<u8>, Vec<u8>);

fn rsa_fixture() -> Result<RsaFixture, Box<dyn std::error::Error>> {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/vectors/rfc7520-subset.json"
    ))?;
    let case = fixtures["test_cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["title"] == "JWE RSA-OAEP and AES GCM")
        .expect("RSA private fixture")
        .clone();
    let key = &case["input"]["key"];
    let mut integers = vec![ASN1Block::Integer(0, BigInt::from(0))];
    for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        integers.push(ASN1Block::Integer(
            0,
            BigInt::from(BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD.decode(key[field].as_str().expect("key component"))?,
            )),
        ));
    }
    let pkcs1 = to_der(&ASN1Block::Sequence(0, integers))?;
    let pkcs8 = to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from(0)),
            ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1)),
                    ASN1Block::Null(0),
                ],
            ),
            ASN1Block::OctetString(0, pkcs1.clone()),
        ],
    ))?;
    Ok((case, pkcs1, pkcs8))
}

struct EnvelopeFixture {
    key: Vec<u8>,
    encrypted_key: Vec<u8>,
    cek: Vec<u8>,
}
impl EnvelopeFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (case, _, key) = rsa_fixture()?;
        let encrypted_key = URL_SAFE_NO_PAD.decode(
            case["output"]["encrypted_key"]
                .as_str()
                .ok_or("encrypted key")?,
        )?;
        let cek = aegaeon_crypto::jwe::rsa_oaep_unwrap(&key, &encrypted_key)?;
        Ok(Self {
            key,
            encrypted_key,
            cek,
        })
    }
    fn seal(&self, header: &str, plaintext: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let protected = URL_SAFE_NO_PAD.encode(header);
        let iv = aegaeon_crypto::rand::random_array::<12>();
        let sealed =
            aegaeon_crypto::jwe::encrypt_a256gcm(&self.cek, &iv, plaintext, protected.as_bytes())?;
        let (cipher, tag) = sealed.split_at(sealed.len() - 16);
        Ok(format!(
            "{protected}.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&self.encrypted_key),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(cipher),
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }
}

async fn configure_encryption(state: &mut AppState, fixture: &EnvelopeFixture) -> TestResult {
    crate::web::test_support::seed_request_object_encryption_key(
        state,
        "request-encryption-test",
        &fixture.key,
    )
    .await?;
    shared_protocol_stores(state)?;
    Ok(())
}

fn assert_no_grant_records(state: &AppState) -> TestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let mut conn = redis::Client::open(url)?.get_connection()?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    for (surface, version) in [("par", "v1"), ("authcode", "v2"), ("token-store", "v3")] {
        let prefix = namespace.redis_atomic_group_prefix(
            crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            surface,
            version,
        );
        let count = conn.scan_match::<_, String>(format!("{prefix}:*"))?.count();
        assert_eq!(count, 0, "refusal must not create {surface} records");
    }
    Ok(())
}

async fn assert_no_browser_grant(state: &AppState) -> TestResult {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(count, 0, "refusal must not initiate browser consent");
    assert_no_grant_records(state)
}

async fn refuse(state: &AppState, sid: &str, token: &str, par: bool) -> TestResult {
    let (status, body) = if par {
        send(
            state,
            sid,
            "/par",
            Some(vec![("client_id", CLIENT), ("request", token)]),
            None,
        )
        .await?
    } else {
        let uri = format!(
            "/authorize?{}",
            serde_urlencoded::to_string([("client_id", CLIENT), ("request", token)])?
        );
        send(state, sid, &uri, None, None).await?
    };
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "encrypted Request Object must fail safely"
    );
    let response: Value = serde_json::from_str(&body)?;
    assert!(response["error"].is_string());
    for field in ["code", "request_uri", "access_token", "refresh_token"] {
        assert!(response.get(field).is_none());
    }
    assert_no_browser_grant(state).await
}

async fn valid_encrypted_requests(par: bool) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result=async {
        let (mut state,sid)=fixture(&pool,&env).await?;
        let encryption=EnvelopeFixture::new()?;
        configure_encryption(&mut state,&encryption).await?;
        for cty in ["JWT","jwt","jWt","application/jwt","APPLICATION/JWT","Application/JwT"] {
            let inner=signed_request(&state,"approve")?;
            let header=format!(r#"{{ "alg":"RSA-OAEP","enc":"A256GCM","cty":"{cty}","extension":{{"ignored":[false,null]}},"\u2603":7 }}"#);
            let token=encryption.seal(&header,inner.as_bytes())?;
            let uri=authorization_uri(&state,&sid,&token,if par {"par-approve"} else {"jar-approve"}).await?;
            let (status,body)=send(&state,&sid,&uri,None,None).await?;
            assert_eq!(status,StatusCode::OK,"encrypted request must reach consent");
            let (status,body)=send(&state,&sid,"/auth/consent",Some(vec![("transaction",transaction(&body)?),("decision","approve")]),Some(state.issuer.as_str())).await?;
            assert_eq!(status,StatusCode::OK,"consent approval must issue code");
            let tokens=redeem(&state,&sid,&body).await?;
            assert!(tokens["access_token"].is_string());
            assert!(tokens["id_token"].is_string());
            assert!(tokens["refresh_token"].is_string());
        }
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn encrypted_request_object_headers_authorize_redeems_code() -> TestResult {
    valid_encrypted_requests(false).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn encrypted_request_object_headers_par_redeems_code() -> TestResult {
    valid_encrypted_requests(true).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn encrypted_request_object_headers_refuse_without_grant_effects() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        let encryption = EnvelopeFixture::new()?;
        configure_encryption(&mut state, &encryption).await?;
        for par in [false, true] {
            for header in [
                r#"{"enc":"A256GCM","cty":"JWT"}"#,
                r#"{"alg":"rsa-oaep","enc":"A256GCM","cty":"JWT"}"#,
                r#"{"alg":"RSA-OAEP","cty":"JWT"}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":null}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":7}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":""}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"text/plain"}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT "}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"application/jwt; charset=utf-8"}"#,
                r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT","\u0063ty":"JWT"}"#,
            ] {
                let inner = signed_request(&state, "approve")?;
                refuse(
                    &state,
                    &sid,
                    &encryption.seal(header, inner.as_bytes())?,
                    par,
                )
                .await?;
            }
            let header = r#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT"}"#;
            for mode in ["bad-signature", "wrong-client", "wrong-audience", "expired"] {
                let inner = signed_request(&state, mode)?;
                refuse(
                    &state,
                    &sid,
                    &encryption.seal(header, inner.as_bytes())?,
                    par,
                )
                .await?;
            }
            for inner in [b"not a JWT".as_slice(), b"a.b.c.d.e", b"\xff"] {
                refuse(&state, &sid, &encryption.seal(header, inner)?, par).await?;
            }
            for part in [3, 4] {
                let inner = signed_request(&state, "approve")?;
                let token = encryption.seal(header, inner.as_bytes())?;
                let mut segments: Vec<String> = token.split('.').map(str::to_owned).collect();
                let mut bytes = URL_SAFE_NO_PAD.decode(&segments[part])?;
                bytes[0] ^= 1;
                segments[part] = URL_SAFE_NO_PAD.encode(bytes);
                refuse(&state, &sid, &segments.join("."), par).await?;
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
