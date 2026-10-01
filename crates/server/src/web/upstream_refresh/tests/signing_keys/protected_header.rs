use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn protected_header_pg_upstream_callback_refuses_before_unknown_kid_retrieval() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims=f.claims()?;
            f.store_callback(&f.callback(&claims,Some("private-refresh"))?).await.map_err(error)?;
            let flow=Flow::new(f).await?;
            let stored=f.stored().await?;
            for extra in [r#""crit":null"#,r#""crit":[]"#,r#""b64":true"#,r#""b64":false,"crit":["b64"]"#,r#""cty":null"#,r#""extension":1,"\u0065xtension":2"#] {
                let header=format!("{{\"alg\":\"RS256\",\"kid\":\"new-key\",{extra}}}");
                let input=format!("{}.{}",URL_SAFE_NO_PAD.encode(header),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?));
                let signature=jsonwebtoken::crypto::sign(input.as_bytes(),flow.new_key.local_encoding_key().ok_or("key")?,jsonwebtoken::Algorithm::RS256)?;
                flow.token(format!("{input}.{signature}"));
                assert_eq!(flow.callback().await?.status(),StatusCode::BAD_GATEWAY);
                assert_eq!(flow.keys.hits(),0,"rejected processing must not fetch keys");
                flow.assert_no_effects(f,&stored,0).await?;
            }
            let header=json!({"alg":"RS256","kid":"new-key","extension":{"nested":[null,true]},"拡張":5,"jku":flow.tokens.url}).to_string();
            let input=format!("{}.{}",URL_SAFE_NO_PAD.encode(header),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?));
            let signature=jsonwebtoken::crypto::sign(input.as_bytes(),flow.new_key.local_encoding_key().ok_or("key")?,jsonwebtoken::Algorithm::RS256)?;
            flow.token(format!("{input}.{signature}"));
            assert_eq!(flow.callback().await?.status(),StatusCode::FOUND);
            assert_eq!(flow.keys.hits(),1,"only configured JWKS endpoint supplies the unfamiliar key");
            assert_eq!(flow.tokens.hits(),7,"ignored jku must not add a fetch");
            Ok(())
        })
    })
}
