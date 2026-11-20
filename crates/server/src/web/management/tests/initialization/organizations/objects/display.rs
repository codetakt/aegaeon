use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and authenticated management HTTP"]
async fn pg_organizations_display_revisions_and_scoped_writers() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = exercise(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn exercise(pool: &sqlx::PgPool) -> ManagementTestResult {
    let h = Harness::new(pool).await?;
    let domain = h
        .collection
        .strip_suffix("/organizations")
        .ok_or("domain URI")?;
    let (org, authority_tag) = representation(
        h.app
            .clone()
            .oneshot(h.create("external-school", "create"))
            .await?,
        StatusCode::OK,
    )
    .await?;
    let org_uri = format!(
        "{}/{}",
        h.collection,
        org["id"].as_str().ok_or("organization")?
    );
    let org_display = format!("{org_uri}/display");
    let policy = format!("{domain}/role-policy");
    let role_display = format!("{policy}/display");
    let get = async |uri: &str| {
        representation(h.app.clone().oneshot(h.read(uri)).await?, StatusCode::OK).await
    };
    let send = async |uri: &str, method: Method, body: Value, key: &str, tag: &str| {
        h.app
            .clone()
            .oneshot(mutation(uri, method, body, &h.cookie, key, Some(tag)))
            .await
    };
    let (_, empty_tag) = get(&policy).await?;
    let roles = json!([{"key":"admin","privileges":["read"],"managesMembers":false,"assignableRoles":[]},{"key":"reader","privileges":["read"],"managesMembers":false,"assignableRoles":[]}]);
    let before = representation(
        send(
            &policy,
            Method::PUT,
            json!({"roles":roles,"reason":"define"}),
            "define",
            &empty_tag,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let (empty, initial_roles) = get(&role_display).await?;
    assert_eq!(empty["labels"], json!({}));
    assert_eq!(empty["revision"], 0);
    let (empty, initial_org) = get(&org_display).await?;
    assert!(empty["displayName"].is_null());
    assert_eq!(empty["revision"], 0);
    let set = async |name: Value, key: &str, tag: &str| {
        send(
            &org_display,
            Method::PUT,
            json!({"displayName":name,"reason":"rename"}),
            key,
            tag,
        )
        .await
    };
    let patch = async |labels: Value, key: &str, tag: &str| {
        send(
            &role_display,
            Method::PATCH,
            json!({"labels":labels,"reason":"set labels"}),
            key,
            tag,
        )
        .await
    };
    assert_eq!(
        send(
            &org_display,
            Method::PUT,
            json!({"reason":"missing name"}),
            "missing",
            &initial_org
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    let (left, right) = tokio::join!(
        set(json!("School"), "left", &initial_org),
        set(json!("学校"), "right", &initial_org)
    );
    let mut outcomes = [left?.status(), right?.status()];
    outcomes.sort();
    assert_eq!(outcomes, [StatusCode::OK, StatusCode::PRECONDITION_FAILED]);
    let (_, org_tag) = get(&org_display).await?;
    let (cleared, new_tag) =
        representation(set(Value::Null, "clear", &org_tag).await?, StatusCode::OK).await?;
    assert_eq!(cleared["revision"], 2);
    assert!(cleared["displayName"].is_null());
    assert_eq!(
        representation(set(Value::Null, "no-op", &new_tag).await?, StatusCode::OK).await?,
        (cleared, new_tag)
    );
    assert_eq!(get(&org_uri).await?, (org, authority_tag));
    let first = representation(
        patch(
            json!({"admin":"管理者","reader":"閲覧者"}),
            "labels",
            &initial_roles,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first.0["revision"], 1);
    assert_eq!(
        representation(
            patch(
                json!({"admin":"管理者","reader":"閲覧者"}),
                "labels",
                &initial_roles
            )
            .await?,
            StatusCode::OK
        )
        .await?,
        first
    );
    assert_eq!(
        patch(
            json!({"admin":null,"unknown":"invalid"}),
            "partial",
            &first.1
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(get(&role_display).await?, first);
    let (cleared, tag) = representation(
        patch(json!({"admin":null}), "clear-role", &first.1).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(cleared["labels"], json!({"reader":"閲覧者"}));
    let (restored, _) = representation(
        patch(json!({"admin":"管理者"}), "restore", &tag).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(restored["revision"], 3);
    let revisions:Vec<i64>=sqlx::query_scalar("SELECT display_revision FROM aegaeon.organization_role_definitions WHERE domain_id=$1 ORDER BY role_key").bind(h.domain).fetch_all(pool).await?;
    assert_eq!(revisions, [3, 1]);
    assert_eq!(get(&policy).await?, before);
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\"]' WHERE domain_id=$1").bind(h.domain).execute(pool).await?;
    assert_eq!(
        h.app.clone().oneshot(h.read(&role_display)).await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        patch(
            json!({"admin":"管理者","reader":"閲覧者"}),
            "labels",
            &initial_roles
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    get(&org_display).await?;
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\"]' WHERE domain_id=$1").bind(h.domain).execute(pool).await?;
    get(&role_display).await?;
    assert_eq!(
        h.app.clone().oneshot(h.read(&org_display)).await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        set(Value::Null, "clear", &org_tag).await?.status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
