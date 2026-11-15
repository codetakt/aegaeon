use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_encoded_audience_continues_page() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let prefix = "https://api.example.test/";
        let audience = format!("{prefix}{}{}", "/".repeat(970), "a".repeat(2048 - prefix.len() - 970));
        assert_eq!(audience.len(), 2048);
        crate::util::validate_resource_indicator(&audience)?;
        sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management,membership_discovery) VALUES($1,$2,$3,false,false)")
            .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(&audience).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2 AND client_identifier=$3")
            .bind(json!([{"audience":audience,"privileges":[PRIVILEGE]}])).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        for i in 0..26 {
            let id = uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,$4,'active')")
                .bind(id).bind(state.environment_id).bind(f.organization.scope.domain_id).bind(format!("encoded-page-{i:02}")).execute(&f.pool).await?;
            sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,gen_random_uuid(),'active','[\"reader\"]')")
                .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(id).bind(f.users[1]).execute(&f.pool).await?;
        }
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let token = discovery_parent(&state, &key, &sid).await?;
        let token = token["access_token"].as_str().ok_or("discovery token")?;
        let query = serde_urlencoded::to_string([("audience", audience.as_str())])?;
        assert!(query.len() <= 4096);
        let (status, first) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::OK, "{first}");
        let first_rows = first["organizations"].as_array().ok_or("first page")?;
        assert_eq!(first_rows.len(), 25);
        let cursor = first["next_cursor"].as_str().ok_or("cursor")?;
        let continued = serde_urlencoded::to_string([("audience", audience.as_str()), ("cursor", cursor)])?;
        assert!(continued.len() > 4096, "must cross the old raw-query bound");
        let (status, last) = memberships(&state, &key, token, &continued).await?;
        assert_eq!(status, StatusCode::OK, "{last}");
        let last_rows = last["organizations"].as_array().ok_or("last page")?;
        assert_eq!(last_rows.len(), 2);
        assert!(last["next_cursor"].is_null());
        let identifiers: std::collections::BTreeSet<_> = first_rows.iter().chain(last_rows).map(|row| row["identifier"].as_str().unwrap()).collect();
        assert_eq!(identifiers.len(), 27);
        let wrong = serde_urlencoded::to_string([("audience", format!("{audience}a")), ("cursor", cursor.to_owned())])?;
        assert_eq!(memberships(&state, &key, token, &wrong).await?.0, StatusCode::BAD_REQUEST);
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
