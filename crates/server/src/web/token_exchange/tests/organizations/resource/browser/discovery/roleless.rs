//! Roleless memberships remain valid and must not hide eligible organizations.
use super::*;

async fn clear_roles(f: &Fixture, organization: uuid::Uuid) -> TestResult {
    sqlx::query("UPDATE aegaeon.organization_memberships SET roles='[]',revision=revision+1,grant_generation=grant_generation+1 WHERE environment_id=$1 AND organization_id=$2 AND end_user_id=$3")
        .bind(f.organization.scope.environment_id).bind(organization).bind(f.users[1])
        .execute(&f.pool).await?;
    Ok(())
}

pub(super) async fn add_membership(
    f: &Fixture,
    id: uuid::Uuid,
    name: &str,
    roles: Value,
) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,$4,'active')")
        .bind(id).bind(f.organization.scope.environment_id).bind(f.organization.scope.domain_id)
        .bind(name).execute(&f.pool).await?;
    sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,gen_random_uuid(),'active',$5)")
        .bind(f.organization.scope.environment_id).bind(f.organization.scope.domain_id)
        .bind(id).bind(f.users[1]).bind(roles).execute(&f.pool).await?;
    Ok(())
}

pub(super) fn continued_query(state: &AppState, first: &Value) -> TestResult<String> {
    Ok(serde_urlencoded::to_string([
        ("audience", format!("{}/organizations", state.issuer)),
        (
            "cursor",
            first["next_cursor"]
                .as_str()
                .ok_or("cursor after roleless page")?
                .to_owned(),
        ),
    ])?)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_roleless_pages_preserve_eligible_selection(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            // The first bounded scan is entirely roleless. The second contains both
            // a roleless membership and the eligible one at the last UUID key.
            // Derive distinct keys from this fixture's random organization, so
            // retained rows from earlier runs cannot collide with a fixed UUID.
            clear_roles(&f, f.organization.id).await?;
            let base = f.organization.id.as_u128();
            assert!(base > 25 && base < u128::MAX);
            let eligible = uuid::Uuid::from_u128(base + 1);
            for index in 0..25_u128 {
                add_membership(
                    &f,
                    uuid::Uuid::from_u128(base - index - 1),
                    &format!("roleless-{index}"),
                    json!([]),
                )
                .await?;
            }
            add_membership(&f, eligible, "eligible-last", json!(["reader"])).await?;
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
            let parent = discovery_parent(&state, &key, &sid).await?;
            let token = parent["access_token"].as_str().ok_or("discovery token")?;
            let query = serde_urlencoded::to_string([(
                "audience",
                format!("{}/organizations", state.issuer),
            )])?;
            let (status, first) = memberships(&state, &key, token, &query).await?;
            assert_eq!(status, StatusCode::OK, "{first}");
            assert_eq!(first["organizations"], json!([]));
            let (status, last) =
                memberships(&state, &key, token, &continued_query(&state, &first)?).await?;
            assert_eq!(status, StatusCode::OK, "{last}");
            assert_eq!(
                last,
                json!({"organizations":[{"identifier":"eligible-last"}],"next_cursor":null})
            );

            let uri = selector_uri(&state, &key)?;
            let (status, first) = page(&state, &sid, &uri, None).await?;
            assert_eq!(status, StatusCode::OK, "{first}");
            assert!(first.contains("No eligible organizations on this page."));
            assert!(first.contains("Next page") && !first.contains("select:0"));
            let next = [("transaction", transaction(&first)?), ("decision", "next")];
            let (status, last) = page(&state, &sid, "/auth/consent", Some(&next)).await?;
            assert_eq!(status, StatusCode::OK, "{last}");
            assert!(last.contains("eligible-last") && !last.contains("Next page"));
            let select = [
                ("transaction", transaction(&last)?),
                ("decision", "select:0"),
            ];
            let (status, consent) = page(&state, &sid, "/auth/consent", Some(&select)).await?;
            assert_eq!(status, StatusCode::OK, "{consent}");
            assert!(consent.contains("Organization access") && consent.contains("eligible-last"));
            assert!(
                code(&consent, &state.issuer).is_err(),
                "selection still requires approval"
            );
            let approval = [
                ("transaction", transaction(&consent)?),
                ("decision", "approve"),
            ];
            let (status, approved) = page(&state, &sid, "/auth/consent", Some(&approval)).await?;
            assert_eq!(status, StatusCode::OK, "{approved}");
            let token_response = redeem(&state, &key, &code(&approved, &state.issuer)?).await?;
            assert_eq!(
                token_response["authorization_details"][0]["organizations"][0]["identifier"],
                "eligible-last"
            );

            // With the last eligible membership made roleless, both surfaces still
            // terminate successfully after advancing through the empty first page.
            clear_roles(&f, eligible).await?;
            let (status, first) = memberships(&state, &key, token, &query).await?;
            assert_eq!(status, StatusCode::OK, "{first}");
            assert_eq!(first["organizations"], json!([]));
            let (status, last) =
                memberships(&state, &key, token, &continued_query(&state, &first)?).await?;
            assert_eq!(status, StatusCode::OK, "{last}");
            assert_eq!(last, json!({"organizations":[],"next_cursor":null}));
            let (status, first) = page(&state, &sid, &uri, None).await?;
            assert_eq!(status, StatusCode::OK, "{first}");
            let next = [("transaction", transaction(&first)?), ("decision", "next")];
            let (status, last) = page(&state, &sid, "/auth/consent", Some(&next)).await?;
            assert_eq!(status, StatusCode::OK, "{last}");
            assert!(last.contains("No eligible organizations on this page."));
            assert!(!last.contains("Next page") && !last.contains("select:0"));
            Ok(())
        }),
    )
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
