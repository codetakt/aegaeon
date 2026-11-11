//! Encoded grant limits filter browser choices without changing API discovery.
use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_picker_skips_unrepresentable_resolved_grants_and_advances(
) -> TestResult {
    let long = "x".repeat(256);
    let escaped = "\"".repeat(128);
    let f = Fixture::with_identifier(&long).await?;
    let mut state = configured_discovery(&f).await?;
    request_objects::shared_request_stores(&mut state).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let privileges: Vec<_> = (0..123).map(|i| format!("{i:03}{}", "p".repeat(125))).collect();
        let audience = format!("{}/organizations", state.issuer);
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET privileges=$1,version=version+1 WHERE environment_id=$2 AND domain_id=$3 AND role_key='reader'")
            .bind(json!(privileges)).bind(state.environment_id).bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=(SELECT jsonb_agg(CASE WHEN value->>'audience'=$1 THEN jsonb_set(value,'{privileges}',$2) ELSE value END) FROM jsonb_array_elements(targets)),revision=revision+1 WHERE environment_id=$3 AND client_identifier=$4")
            .bind(&audience).bind(json!(privileges)).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        let base = f.organization.id.as_u128();
        assert!(base < u128::MAX - 2);
        roleless::add_membership(&f, uuid::Uuid::from_u128(base + 1), &escaped, json!(["reader"])).await?;
        roleless::add_membership(&f, uuid::Uuid::from_u128(base + 2), "z", json!(["reader"])).await?;
        let details = json!([{"type":TYPE,"locations":[audience],"privileges":privileges,"selection":"interactive"}]);
        let selector = crate::organizations::selection::SelectionRequest::parse(&details)
            .map_err(|_| "near-limit selector must remain valid")?;
        let available = privileges.iter().cloned().collect();
        // The later short identifier remains selectable at the unchanged 16 KiB bound.
        let accepted = selector.resolve("z", &available).map_err(|_| "short identifier must fit")?;
        assert!(crate::organizations::consent::GrantRequest::parse(&accepted).is_ok());
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let parent = discovery_parent(&state, &key, &sid).await?;
        let token = parent["access_token"].as_str().ok_or("discovery token")?;
        let query = serde_urlencoded::to_string([("audience", &audience)])?;
        let (status, api) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::OK, "{api}");
        assert_eq!(api, json!({"organizations":[{"identifier":long},{"identifier":escaped},{"identifier":"z"}],"next_cursor":null}));

        let original = selector_uri(&state, &key)?;
        let mut fields: Vec<(String, String)> = serde_urlencoded::from_str(original.split_once('?').ok_or("query")?.1)?;
        fields.iter_mut().find(|(key, _)| key == "authorization_details").ok_or("details")?.1 = details.to_string();
        // PAR transports the near-limit selector without exceeding the separate
        // direct authorization query bound. The selector/grant limits stay intact.
        let refs: Vec<_> = fields.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        let (status, pushed) = request_objects::par(&state, &key, &refs).await?;
        assert_eq!(status, StatusCode::CREATED, "{pushed}");
        let uri = format!("/authorize?{}", serde_urlencoded::to_string([
            ("client_id", OWNER), ("request_uri", pushed["request_uri"].as_str().ok_or("PAR reference")?)
        ])?);
        let (status, mut html) = page(&state, &sid, &uri, None).await?;
        assert_eq!(status, StatusCode::OK, "{html}");
        for _ in 0..2 {
            assert!(html.contains("No eligible organizations on this page."), "{html}");
            assert!(html.contains("Next page") && !html.contains("select:0"));
            let (status, next) = page(&state, &sid, "/auth/consent", Some(&[("transaction", transaction(&html)?), ("decision", "next")])).await?;
            assert_eq!(status, StatusCode::OK, "{next}");
            html = next;
        }
        assert!(html.contains("value=\"select:0\">z</button>") && !html.contains("Next page"), "{html}");
        let (status, consent) = page(&state, &sid, "/auth/consent", Some(&[("transaction", transaction(&html)?), ("decision", "select:0")])).await?;
        assert_eq!(status, StatusCode::OK, "{consent}");
        assert!(consent.contains("Organization access"));
        assert!(code(&consent, &state.issuer).is_err(), "selection is not approval");
        let (status, approved) = page(&state, &sid, "/auth/consent", Some(&[("transaction", transaction(&consent)?), ("decision", "approve")])).await?;
        assert_eq!(status, StatusCode::OK, "{approved}");
        let parent = redeem(&state, &key, &code(&approved, &state.issuer)?).await?;
        assert_eq!(parent["authorization_details"], accepted);
        assert!(serde_json::to_vec(&parent["authorization_details"])?.len() <= 16 * 1024);
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
