use super::*;

async fn human(
    pool: &sqlx::PgPool,
    h: &Harness,
    email: &str,
) -> Result<(Uuid, String), Box<dyn std::error::Error>> {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status)
        SELECT $1,$2,password_hash,'HUMAN','ACTIVE' FROM aegaeon.administrators WHERE id=$3",
    )
    .bind(user)
    .bind(email)
    .bind(h.administrator)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role)
        SELECT team_id,$1,'ADMINISTRATOR' FROM aegaeon.team_memberships WHERE administrator_id=$2",
    )
    .bind(user)
    .bind(h.administrator)
    .execute(pool)
    .await?;
    let response = h
        .app
        .clone()
        .oneshot(request(
            "/api/v1/authentication/sessions",
            json!({"email":email,"password":input().owner_password}),
            "",
            "https://admin.aegaeon.test",
            true,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("aegaeon_admin_session="))
        .and_then(|v| v.split(';').next())
        .ok_or("missing management session")?;
    Ok((user, cookie.into()))
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and authenticated management HTTP"]
async fn pg_organizations_display_separates_provision_configure_and_business_administration(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = separate_writers(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn separate_writers(pool: &sqlx::PgPool) -> ManagementTestResult {
    let h = Harness::new(pool).await?;
    let (configure, configure_cookie) = human(pool, &h, "configure@example.test").await?;
    let (business, business_cookie) = human(pool, &h, "business@example.test").await?;
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\"]',revision=revision+1
        WHERE domain_id=$1 AND administrator_id=$2")
        .bind(h.domain).bind(h.administrator).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities)
        VALUES($1,$2,$3,$4,true,'[\"configure\"]')")
        .bind(Uuid::new_v4()).bind(h.environment).bind(h.domain).bind(configure).execute(pool).await?;

    let domain = h
        .collection
        .strip_suffix("/organizations")
        .ok_or("domain path")?;
    let role_policy = format!("{domain}/role-policy");
    let role_display = format!("{role_policy}/display");
    let read = async |path: &str, cookie: &str| {
        let request = Request::builder()
            .uri(path)
            .header("cookie", cookie)
            .body(Body::empty())?;
        representation(h.app.clone().oneshot(request).await?, StatusCode::OK).await
    };
    let write =
        async |path: &str, method: Method, body: Value, cookie: &str, key: &str, tag: &str| {
            h.app
                .clone()
                .oneshot(mutation(path, method, body, cookie, key, Some(tag)))
                .await
        };
    let (_, start) = read(&role_policy, &configure_cookie).await?;
    let roles = json!({"roles":[{"key":"admin","privileges":["organization.members.manage"],"managesMembers":true,"assignableRoles":["admin"]}],"reason":"define business administrator"});
    let (_, policy_tag) = representation(
        write(
            &role_policy,
            Method::PUT,
            roles,
            &configure_cookie,
            "policy",
            &start,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let (org, _) = representation(
        h.app.clone().oneshot(h.create("school", "create")).await?,
        StatusCode::OK,
    )
    .await?;
    let id = Uuid::parse_str(org["id"].as_str().ok_or("organization ID")?)?;
    let path = format!("{}/{id}", h.collection);
    let org_display = format!("{path}/display");
    let (_, org_tag) = read(&org_display, &h.cookie).await?;
    let (_, roles_tag) = read(&role_display, &configure_cookie).await?;
    let name = json!({"displayName":"School","reason":"set name"});
    let label = json!({"labels":{"admin":"Administrator"},"reason":"set label"});
    assert_eq!(
        write(
            &org_display,
            Method::PUT,
            name.clone(),
            &configure_cookie,
            "denied-name",
            &org_tag
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        write(
            &role_display,
            Method::PATCH,
            label.clone(),
            &h.cookie,
            "denied-label",
            &roles_tag
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    let members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    assert_eq!(members, 0);
    let (display, saved_tag) = representation(
        write(&org_display, Method::PUT, name, &h.cookie, "name", &org_tag).await?,
        StatusCode::OK,
    )
    .await?;
    let (labels, saved_roles) = representation(
        write(
            &role_display,
            Method::PATCH,
            label,
            &configure_cookie,
            "label",
            &roles_tag,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(display["displayName"], "School");
    assert_eq!(labels["labels"]["admin"], "Administrator");
    assert_eq!(read(&role_policy, &configure_cookie).await?.1, policy_tag);
    let authority: (i64, i64) = sqlx::query_as(
        "SELECT revision, grant_generation FROM aegaeon.application_organizations WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    assert_eq!(authority, (1, 1));

    // Supply the same UUID to both principal namespaces. Even an authenticated
    // human Team administrator with an active member-management role in this
    // organization has no display authority until granted it in the domain.
    sqlx::query(
        "INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')",
    )
    .bind(business)
    .bind(h.environment)
    .bind("business@example.test")
    .execute(pool)
    .await?;
    sqlx::query("UPDATE aegaeon.application_organizations SET state='active',revision=revision+1,grant_generation=grant_generation+1 WHERE id=$1")
        .bind(id).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles)
        VALUES($1,$2,$3,$4,$5,'active','[\"admin\"]')")
        .bind(h.environment).bind(h.domain).bind(id).bind(business).bind(Uuid::new_v4()).execute(pool).await?;
    let rename = json!({"displayName":"Different","reason":"rename"});
    let relabel = json!({"labels":{"admin":"Different"},"reason":"relabel"});
    assert_eq!(
        write(
            &org_display,
            Method::PUT,
            rename,
            &business_cookie,
            "business-name",
            &saved_tag
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        write(
            &role_display,
            Method::PATCH,
            relabel,
            &business_cookie,
            "business-label",
            &saved_roles
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(read(&org_display, &h.cookie).await?, (display, saved_tag));
    assert_eq!(
        read(&role_display, &configure_cookie).await?,
        (labels, saved_roles)
    );
    Ok(())
}
