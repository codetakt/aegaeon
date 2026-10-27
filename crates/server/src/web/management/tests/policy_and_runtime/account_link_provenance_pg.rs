struct BindingFixture {
    pool: sqlx::PgPool,
    env: RuntimeKeyTestEnvironment,
    app: axum::Router,
    sid: String,
    outsider_sid: String,
    connection: Uuid,
    users: [Uuid; 2],
}
impl BindingFixture {
    async fn new() -> Result<Self, Box<dyn StdError>> {
        let pool = membership_test_pool().await?;
        let env = setup_runtime_key_test_environment(&pool).await?;
        let connection=sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,'binding-test','binding-test','https://upstream.example','client','none','ACTIVE') RETURNING id").bind(env.environment_id).bind(env.configuration_version_id).fetch_one(&pool).await?;
        let mut users = [Uuid::nil(); 2];
        for user in &mut users {
            *user=sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,$2,'ACTIVE') RETURNING id").bind(env.environment_id).bind(Uuid::new_v4().to_string()).fetch_one(&pool).await?;
        }
        let mgmt = test_management_state();
        let now = crate::util::now_unix_epoch_secs()?;
        let sid = mgmt
            .sessions
            .create(env.administrator_id, now)
            .ok_or("session")?;
        let outsider_sid = mgmt
            .sessions
            .create(env.non_member_administrator_id, now)
            .ok_or("outsider session")?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        Ok(Self {
            pool,
            env,
            app,
            sid,
            outsider_sid,
            connection,
            users,
        })
    }
    async fn post(
        &self,
        path: &str,
        value: serde_json::Value,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn StdError>> {
        self.post_as(path, value, &self.sid).await
    }
    async fn post_as(
        &self,
        path: &str,
        value: serde_json::Value,
        sid: &str,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn StdError>> {
        let response = self
            .app
            .clone()
            .oneshot(membership_http_request(
                Method::POST,
                &self.env,
                path,
                sid,
                value,
            )?)
            .await?;
        Ok((response.status(), response_json(response).await?))
    }
    async fn legacy(&self, sub: &str) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar("INSERT INTO aegaeon.account_links(environment_id,connection_id,upstream_issuer,upstream_sub_hash,end_user_id,upstream_refresh_token_encrypted,upstream_refresh_token_connection_id,upstream_refresh_token_generation) VALUES($1,$2,'https://upstream.example',$3,$4,decode('012345abcd','hex'),$2,7) RETURNING id").bind(self.env.environment_id).bind(self.connection).bind(crate::upstream::upstream_subject_link_hash("https://upstream.example",sub)).bind(self.users[0]).fetch_one(&self.pool).await
    }
    async fn binding(&self, id: Uuid) -> Result<serde_json::Value, sqlx::Error> {
        sqlx::query_scalar("SELECT to_jsonb(al) FROM aegaeon.account_links al WHERE id=$1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }
    async fn cleanup(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM aegaeon.account_links WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM aegaeon.team_memberships WHERE team_id=$1 AND administrator_id=$2",
        )
        .bind(self.env.team_id)
        .bind(self.env.non_member_administrator_id)
        .execute(&self.pool)
        .await?;
        cleanup_configuration_members(&self.pool, &self.env).await
    }
}
fn assert_binding_summary(value: &serde_json::Value, provenance: &str, revision: i64) {
    assert_eq!(value["bindingProvenance"], provenance);
    assert_eq!(value["bindingRevision"], revision);
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_management_create_single_bulk_and_conflict_moves() -> TestResult {
    let f = BindingFixture::new().await?;
    let (status,created)=f.post("accountLinks",serde_json::json!({"connectionId":f.connection,"upstreamSubject":"new","endUserId":f.users[0]})).await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_binding_summary(&created, "administrator_confirmed", 1);
    let legacy = f.legacy("legacy").await?;
    let before = f.binding(legacy).await?;
    assert_eq!(before["binding_provenance"], "legacy_unreviewed");
    assert_eq!(before["binding_revision"], 1);
    let (status, moved) = f
        .post(
            &format!("accountLinks/{legacy}/relink"),
            serde_json::json!({"endUserId":f.users[1],"upstreamRefreshTokenHandling":"retain"}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_binding_summary(&moved, "administrator_confirmed", 2);
    let after = f.binding(legacy).await?;
    assert_eq!(
        after["upstream_refresh_token_encrypted"],
        before["upstream_refresh_token_encrypted"]
    );
    assert_eq!(after["upstream_refresh_token_generation"], 7);
    let created_id = created["id"].as_str().ok_or("created id")?;
    let (status,bulk)=f.post("accountLinks/bulkRelink",serde_json::json!({"accountLinkIds":[legacy.to_string(),created_id.to_string()],"endUserId":f.users[0],"upstreamRefreshTokenHandling":"clear"})).await?;
    assert_eq!(status, StatusCode::OK, "{bulk}");
    let after = f.binding(legacy).await?;
    assert_eq!(after["binding_revision"], 3);
    assert!(after["upstream_refresh_token_encrypted"].is_null());
    assert_eq!(
        f.binding(Uuid::parse_str(created_id)?).await?["binding_revision"],
        1,
        "bulk no-op must not advance"
    );
    let (status,resolved)=f.post("accountLinks/resolveConflict",serde_json::json!({"connectionId":f.connection,"upstreamSubject":"legacy","endUserId":f.users[1],"lowConfidenceHandling":"allow_low_confidence"})).await?;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_binding_summary(&resolved, "administrator_confirmed", 4);
    f.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_read_preview_and_noop_never_attest_legacy() -> TestResult {
    let f = BindingFixture::new().await?;
    let id = f.legacy("legacy").await?;
    let before = f.binding(id).await?;
    let response = f
        .app
        .clone()
        .oneshot(membership_http_request(
            Method::GET,
            &f.env,
            "accountLinks",
            &f.sid,
            serde_json::Value::Null,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let rows = response_json(response).await?;
    assert_binding_summary(&rows["accountLinks"][0], "legacy_unreviewed", 1);
    for (path, body) in [
        (
            "accountLinks/conflictPreview".to_string(),
            serde_json::json!({"connectionId":f.connection,"upstreamSubject":"legacy"}),
        ),
        (
            format!("accountLinks/{id}/relink"),
            serde_json::json!({"endUserId":f.users[0]}),
        ),
        (
            "accountLinks/bulkRelink".to_string(),
            serde_json::json!({"accountLinkIds":[id],"endUserId":f.users[0]}),
        ),
        (
            "accountLinks/resolveConflict".to_string(),
            serde_json::json!({"connectionId":f.connection,"upstreamSubject":"legacy","endUserId":f.users[0]}),
        ),
    ] {
        let (status, value) = f.post(&path, body).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(f.binding(id).await?, before);
    }
    f.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_denied_role_environment_and_overflow_leave_binding_unchanged() -> TestResult {
    let f = BindingFixture::new().await?;
    let other = BindingFixture::new().await?;
    let id = f.legacy("legacy").await?;
    let before = f.binding(id).await?;
    let path = format!("accountLinks/{id}/relink");
    let (status, _) = f
        .post_as(
            &path,
            serde_json::json!({"endUserId":f.users[1],"upstreamRefreshTokenHandling":"clear"}),
            &f.outsider_sid,
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(f.binding(id).await?, before);
    sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES($1,$2,'READONLY')").bind(f.env.team_id).bind(f.env.non_member_administrator_id).execute(&f.pool).await?;
    let (status, _) = f
        .post_as(
            &path,
            serde_json::json!({"endUserId":f.users[1],"upstreamRefreshTokenHandling":"clear"}),
            &f.outsider_sid,
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(f.binding(id).await?, before);
    let (status, _) = f
        .post(
            &path,
            serde_json::json!({"endUserId":other.users[1],"upstreamRefreshTokenHandling":"clear"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(f.binding(id).await?, before);
    sqlx::query(
        "UPDATE aegaeon.account_links SET binding_revision=9223372036854775807 WHERE id=$1",
    )
    .bind(id)
    .execute(&f.pool)
    .await?;
    let before = f.binding(id).await?;
    for (path, body) in [
        (
            path,
            serde_json::json!({"endUserId":f.users[1],"upstreamRefreshTokenHandling":"clear"}),
        ),
        (
            "accountLinks/bulkRelink".into(),
            serde_json::json!({"accountLinkIds":[id],"endUserId":f.users[1],"upstreamRefreshTokenHandling":"clear"}),
        ),
        (
            "accountLinks/resolveConflict".into(),
            serde_json::json!({"connectionId":f.connection,"upstreamSubject":"legacy","endUserId":f.users[1],"lowConfidenceHandling":"allow_low_confidence","upstreamRefreshTokenHandling":"clear"}),
        ),
    ] {
        let (status, value) = f.post(&path, body).await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{value}");
        assert_eq!(
            f.binding(id).await?,
            before,
            "overflow must roll back owner, provenance and credentials"
        );
    }
    other.cleanup().await?;
    f.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_audit_failure_rolls_back_owner_revision_and_credentials() -> TestResult {
    let f = BindingFixture::new().await?;
    let id = f.legacy("legacy").await?;
    let before = f.binding(id).await?;
    let constraint = format!("binding_audit_failure_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("ALTER TABLE aegaeon.audit_events ADD CONSTRAINT {constraint} CHECK (environment_id <> '{}'::uuid) NOT VALID",f.env.environment_id)).execute(&f.pool).await?;
    let result = f
        .post(
            &format!("accountLinks/{id}/relink"),
            serde_json::json!({"endUserId":f.users[1],"upstreamRefreshTokenHandling":"clear"}),
        )
        .await;
    sqlx::query(&format!(
        "ALTER TABLE aegaeon.audit_events DROP CONSTRAINT {constraint}"
    ))
    .execute(&f.pool)
    .await?;
    let (status, value) = result?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{value}");
    assert_eq!(f.binding(id).await?, before);
    f.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_configuration_save_and_activation_refuse_legacy_reuse() -> TestResult {
    let f = BindingFixture::new().await?;
    let mut document: serde_json::Value = sqlx::query_scalar(
        "SELECT configuration_document FROM aegaeon.configuration_versions WHERE id=$1",
    )
    .bind(f.env.configuration_version_id)
    .fetch_one(&f.pool)
    .await?;
    document["federation"] = serde_json::json!({"upstreamIssuer":"https://upstream.example","clientId":"client","redirectUri":"https://auth.example.com/callback","jitProvisioning":{"enabled":true,"collisionPolicy":"reuse_existing_email"}});
    let issuer_url = format!("https://{}", f.env.issuer_host);
    assert!(
        crate::web::management::configuration_documents::validate_configuration_version_document(
            &document,
            &f.env.issuer_host,
            &issuer_url,
            "legacy-save"
        )
        .is_err()
    );
    assert!(parse_activated_environment_configuration(
        document.clone(),
        &f.env.issuer_host,
        &issuer_url,
        "legacy-activation"
    )
    .is_err());
    document["federation"]["jitProvisioning"]["enabled"] = serde_json::json!(false);
    assert!(
        crate::web::management::configuration_documents::validate_configuration_version_document(
            &document,
            &f.env.issuer_host,
            &issuer_url,
            "disabled-save"
        )
        .is_ok()
    );
    assert!(parse_activated_environment_configuration(
        document,
        &f.env.issuer_host,
        &issuer_url,
        "disabled-activation"
    )
    .is_ok());
    f.cleanup().await?;
    Ok(())
}
