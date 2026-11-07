//! Valid role unions outside the grant bound must not hide other memberships.
use super::*;

async fn roles(f: &Fixture, organization: uuid::Uuid, values: Value) -> TestResult {
    sqlx::query("UPDATE aegaeon.organization_memberships SET roles=$1,revision=revision+1,grant_generation=grant_generation+1 WHERE environment_id=$2 AND organization_id=$3 AND end_user_id=$4")
        .bind(values).bind(f.organization.scope.environment_id).bind(organization).bind(f.users[1])
        .execute(&f.pool).await?;
    Ok(())
}

async fn oversized(f: &Fixture) -> TestResult {
    for (name, prefix) in [("large-a", "a"), ("large-b", "b")] {
        let mut privileges: Vec<_> = (0..129)
            .map(|i| format!("{prefix}.privilege.{i}"))
            .collect();
        if name == "large-a" {
            privileges[0] = PRIVILEGE.into();
        }
        sqlx::query("INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,privileges,manages_members,assignable_roles) VALUES($1,$2,$3,$4,false,'[]')")
            .bind(f.organization.scope.environment_id).bind(f.organization.scope.domain_id)
            .bind(name).bind(json!(privileges)).execute(&f.pool).await?;
    }
    roles(f, f.organization.id, json!(["large-a", "large-b"])).await?;
    let base = f.organization.id.as_u128();
    assert!(base > 25 && base < u128::MAX);
    for index in 0..25_u128 {
        roleless::add_membership(
            f,
            uuid::Uuid::from_u128(base - index - 1),
            &format!("oversized-{index}"),
            json!(["large-a", "large-b"]),
        )
        .await?;
    }
    roleless::add_membership(
        f,
        uuid::Uuid::from_u128(base + 1),
        "eligible-last",
        json!(["reader"]),
    )
    .await
}

async fn picker(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    sid: &str,
) -> TestResult {
    let (status, first) = page(state, sid, &selector_uri(state, key)?, None).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(
        first.contains("No eligible organizations on this page.") && first.contains("Next page")
    );
    let next = [("transaction", transaction(&first)?), ("decision", "next")];
    let (status, last) = page(state, sid, "/auth/consent", Some(&next)).await?;
    assert_eq!(status, StatusCode::OK, "{last}");
    assert!(last.contains("eligible-last") && !last.contains("Next page"));
    let select = [
        ("transaction", transaction(&last)?),
        ("decision", "select:0"),
    ];
    let (status, consent) = page(state, sid, "/auth/consent", Some(&select)).await?;
    assert_eq!(status, StatusCode::OK, "{consent}");
    assert!(consent.contains("Organization access") && consent.contains("eligible-last"));
    assert!(
        code(&consent, &state.issuer).is_err(),
        "selection still requires approval"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_oversized_union_pages_and_invalid_roles() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        oversized(&f).await?;
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let parent = discovery_parent(&state, &key, &sid).await?;
        let token = parent["access_token"].as_str().ok_or("discovery token")?;
        let query = serde_urlencoded::to_string([("audience", format!("{}/organizations", state.issuer))])?;
        let (status, first) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["organizations"], json!([]));
        let next = roleless::continued_query(&state, &first)?;
        let (status, last) = memberships(&state, &key, token, &next).await?;
        assert_eq!(status, StatusCode::OK, "{last}");
        assert_eq!(last, json!({"organizations":[{"identifier":"eligible-last"}],"next_cursor":null}));
        picker(&state, &key, &sid).await?;

        // This unknown key sorts AFTER both valid oversized roles: all referenced
        // definitions must be validated before the oversized-union skip applies.
        roles(&f, f.organization.id, json!(["large-a", "large-b", "zz-undefined"])).await?;
        assert_eq!(memberships(&state, &key, token, &next).await?.0, StatusCode::BAD_REQUEST);
        roles(&f, f.organization.id, json!(["large-a", "large-b"])).await?;

        // The same two individually valid roles become representable at exactly
        // 256 unique privileges. Request intersection must not reduce the bound.
        let smaller: Vec<_> = (0..127).map(|i| format!("b.privilege.{i}")).collect();
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET privileges=$1,version=version+1 WHERE environment_id=$2 AND domain_id=$3 AND role_key='large-b'")
            .bind(json!(smaller)).bind(state.environment_id).bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        let (status, first) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["organizations"].as_array().ok_or("organizations")?.len(), 25);
        let (status, last) = memberships(&state, &key, token, &roleless::continued_query(&state, &first)?).await?;
        assert_eq!(status, StatusCode::OK, "{last}");
        assert_eq!(last["organizations"].as_array().ok_or("organizations")?.len(), 2);
        assert!(last["next_cursor"].is_null());
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
