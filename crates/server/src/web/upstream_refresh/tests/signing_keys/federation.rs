use super::*;

pub(super) async fn bind(flow: &Flow, f: &Fixture, metadata_keys: Value) -> ResultTest {
    let now = i64::try_from(crate::web::now_epoch_secs()?)?;
    let anchor = "https://anchor.example";
    let leaf = &flow.request.issuer;
    let anchor_keys = serde_json::to_value(f.signing_key.jwks())?;
    let leaf_keys = serde_json::to_value(flow.new_key.jwks())?;
    let metadata = json!({"openid_provider":{"issuer":leaf,"authorization_endpoint":flow.discovery.authorization_endpoint,"token_endpoint":flow.discovery.token_endpoint,"jwks_uri":flow.discovery.jwks_uri,"jwks":metadata_keys}});
    let leaf_claims = json!({"iss":leaf,"sub":leaf,"iat":now-30,"exp":now+3600,"jwks":leaf_keys,"authority_hints":[anchor],"metadata":metadata});
    let sub_claims = json!({"iss":anchor,"sub":leaf,"iat":now-30,"exp":now+3600,"jwks":leaf_keys});
    let anchor_claims = json!({
        "iss": anchor,
        "sub": anchor,
        "iat": now - 30,
        "exp": now + 3600,
        "jwks": anchor_keys,
        "metadata": {"federation_entity": {
            "federation_fetch_endpoint": "https://anchor.example/fetch",
            "federation_list_endpoint": "https://anchor.example/list",
        }},
    });
    let sign = |key: &crate::oidc::OidcSigningKey, claims: &Value| -> ResultTest<String> {
        Ok(jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::RS256,
                kid: Some(key.kid().into()),
                typ: Some("entity-statement+jwt".into()),
                ..Default::default()
            },
            claims,
            key.local_encoding_key().ok_or("federation fixture key")?,
        )?)
    };
    let chain = json!([
        sign(&flow.new_key, &leaf_claims)?,
        sign(&f.signing_key, &sub_claims)?,
        sign(&f.signing_key, &anchor_claims)?
    ]);
    flow.state
        .federation
        .trust_anchors
        .upsert(f.env.environment_id, anchor, &anchor_keys, None)
        .await?;
    flow.state
        .federation
        .chain_cache
        .upsert(f.env.environment_id, leaf, anchor, &chain, now + 3600)
        .await?;
    Ok(())
}
