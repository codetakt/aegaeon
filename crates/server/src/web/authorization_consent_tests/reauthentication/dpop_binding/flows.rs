use super::*;

pub(super) async fn run(state: &AppState, sid: &str, post: bool, login: bool) -> TestResult {
    let key = Key::new(state)?;
    for source in [
        "plain",
        "jar",
        "par-parameter",
        "par-header",
        "par-both",
        "par-jar-header",
        "par-jar-claim",
        "par-jar-both",
    ] {
        let prompt = login.then_some("login consent");
        let pairs = match source {
            "plain" => {
                let mut pairs = fields(state, prompt)?;
                pairs.push(("dpop_jkt".into(), key.jkt.clone()));
                if login {
                    pairs.push(("max_age".into(), "0".into()));
                }
                pairs
            }
            "jar" => vec![
                ("client_id".into(), CLIENT.into()),
                (
                    "request".into(),
                    signed(state, Some(json!(key.jkt)), prompt)?,
                ),
                // An invalid outer thumbprint cannot replace the signed key.
                ("dpop_jkt".into(), "ignored-outer-thumbprint".into()),
            ],
            mode => par::push(state, sid, mode, &key, prompt).await?,
        };
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = authorize(&mut browser, state, &pairs, post).await?;
        let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
        redeem_bound(state, &code, &key).await?;
    }
    Ok(())
}

pub(super) async fn unbound(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    // Signed absence ignores an outer key. Plain absence preserves optional token binding.
    for post in [false, true] {
        for jar in [false, true] {
            for proof_at_token in [false, true] {
                let mut pairs = if jar {
                    vec![
                        ("client_id".into(), CLIENT.into()),
                        ("request".into(), signed(state, None, None)?),
                    ]
                } else {
                    fields(state, None)?
                };
                if jar {
                    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
                }
                let mut browser = Browser::default();
                browser
                    .cookies
                    .insert("aegaeon_auth_session".into(), sid.into());
                let page = authorize(&mut browser, state, &pairs, post).await?;
                let code = finish(&mut browser, state, page, None).await?;
                let proof = proof_at_token
                    .then(|| key.proof(state, "/token", json!({})))
                    .transpose()?;
                let (status, body) = token(state, &code, proof.as_deref()).await?;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert_eq!(
                    body["token_type"],
                    if proof_at_token { "DPoP" } else { "Bearer" }
                );
            }
        }
    }
    Ok(())
}
