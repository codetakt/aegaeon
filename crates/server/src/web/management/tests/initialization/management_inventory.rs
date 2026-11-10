//! Mounted HTTP and dedicated SQL bootstrap, each in an owned disposable DB.
use super::*;
use serde_json::{json, Value};

struct Fixture {
    control: PgPool,
    pool: PgPool,
    admin: PgPool,
    bootstrap: PgPool,
    name: String,
    installation: Uuid,
}

impl Fixture {
    async fn new() -> ManagementTestResultOf<Self> {
        let (control, pool, name) = database_with_management().await?;
        let admin = crate::web::test_support::test_admin_pool(&pool).await?;
        let directory = std::env::var("AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY")?;
        let supplier: Value = serde_json::from_slice(&std::fs::read(
            std::path::Path::new(&directory).join("suppliers.json"),
        )?)?;
        let options: sqlx::postgres::PgConnectOptions = supplier["urls"]["bootstrap"]
            .as_str()
            .ok_or("bootstrap fixture supplier missing")?
            .parse()?;
        let bootstrap = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options.database(&name))
            .await?;
        let installation = sqlx::query_scalar("SELECT id FROM management_authority.installation")
            .fetch_one(&admin)
            .await?;
        Ok(Self {
            control,
            pool,
            admin,
            bootstrap,
            name,
            installation,
        })
    }

    async fn finish(self, result: ManagementTestResult) -> ManagementTestResult {
        finish(
            result,
            database_cleanup::cleanup_pools(
                self.control,
                vec![self.pool, self.admin, self.bootstrap],
                &self.name,
            )
            .await,
        )
    }

    async fn principal(&self, kind: &str) -> ManagementTestResultOf<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind) VALUES($1,$2,'NeverReturnCredentialMaterial',$3::aegaeon.administrator_kind)")
            .bind(id).bind(format!("inventory-{id}@example.invalid")).bind(kind)
            .execute(&self.pool).await?;
        Ok(id)
    }

    fn grant_request(&self, principal: Uuid, kind: &str, selector: Value) -> Value {
        json!({
            "installation_id": self.installation, "operation_id": Uuid::new_v4(),
            "grant_id": Uuid::new_v4(), "principal_id": principal, "principal_kind": kind,
            "adopt_installation": true, "use_selector": selector,
            "use_actions": {"policy":"enumerated", "registry_version":1,
                "actions":["inventory.teams.read", "inventory.tenants.read",
                    "inventory.environments.read", "inventory.users.read", "inventory.organizations.read"]},
            "conditions": {}, "valid_from":"2026-01-01T00:00:00Z", "permanent":true,
        })
    }

    fn selector(&self, mode: &str) -> Value {
        json!({"id":Uuid::new_v4(), "mode":mode, "anchor_kind":"installation", "anchor_id":self.installation})
    }

    async fn bootstrap(&self, request: &Value) -> Result<Value, sqlx::Error> {
        bootstrap(&self.bootstrap, request).await
    }

    async fn human_app(&self, principal: Uuid) -> ManagementTestResultOf<(Router, String, PgPool)> {
        let mut management = test_management_state();
        let namespace = crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        management.sessions = std::sync::Arc::new(ManagementSessionStore::from_postgres(
            &management.cfg,
            self.pool.clone(),
            &namespace,
        )?);
        let session = management
            .sessions
            .try_create_async(principal, crate::util::now_unix_epoch_secs()?)
            .await
            .map_err(std::io::Error::other)?
            .ok_or("session capacity")?;
        let state = test_app_state(self.pool.clone(), management)?;
        let runtime = state.db_pool.clone();
        Ok((
            crate::web::build_router(state),
            format!("aegaeon_admin_session={session}"),
            runtime,
        ))
    }
}

type ManagementTestResultOf<T> = Result<T, Box<dyn std::error::Error>>;

async fn bootstrap(pool: &PgPool, request: &Value) -> Result<Value, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *transaction)
        .await?;
    let value = sqlx::query_scalar("SELECT management_authority.bootstrap_v1($1)")
        .bind(request)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(value)
}

async fn inventory(
    app: &Router,
    installation: Uuid,
    grant: Uuid,
    kind: &str,
    credential: (&str, &str),
    query: &str,
) -> ManagementTestResultOf<(StatusCode, Value)> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/installations/{installation}/inventory/{kind}?grantId={grant}{query}"
                ))
                .header(credential.0, credential.1)
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    assert_no_store_and_request_id(&response);
    let bytes = body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let value: Value = serde_json::from_slice(&bytes)?;
    assert!(!String::from_utf8_lossy(&bytes).contains("NeverReturnCredentialMaterial"));
    Ok((status, value))
}

fn grant_id(request: &Value) -> ManagementTestResultOf<Uuid> {
    Ok(request["grant_id"].as_str().ok_or("grant id")?.parse()?)
}

fn ids(page: &Value) -> Vec<&str> {
    page["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .map(|item| item["id"].as_str().expect("object id"))
        .collect()
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_http_bootstrap_replay_and_current_credentials(
) -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        let env = setup_runtime_key_test_environment(&f.pool).await?;
        let user = Uuid::new_v4();
        let domain = Uuid::new_v4();
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,'inventory-subject','ACTIVE')")
            .bind(user).bind(env.environment_id).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name,enabled) VALUES($1,$2,'inventory domain',true)")
            .bind(domain).bind(env.environment_id).execute(&f.admin).await?;
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,'inventory/学校','active')")
            .bind(organization).bind(env.environment_id).bind(domain).execute(&f.admin).await?;
        let viewer = f.principal("HUMAN").await?;
        let (app, cookie, runtime) = f.human_app(viewer).await?;
        let request = f.grant_request(viewer, "HUMAN", f.selector("current_and_future_descendants"));
        let grant = grant_id(&request)?;
        assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::FORBIDDEN);
        let denied = bootstrap(&f.pool, &request).await.expect_err("ordinary runtime bootstrap");
        assert_eq!(denied.as_database_error().and_then(|error|error.code()).as_deref(), Some("42501"));
        let first = f.bootstrap(&request).await?;
        assert_eq!(f.bootstrap(&request).await?, first);
        let mut changed = request.clone(); changed["label"] = json!("different operation");
        assert_eq!(f.bootstrap(&changed).await.expect_err("receipt rebinding").as_database_error().and_then(|error|error.code()).as_deref(), Some("23505"));
        let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_authority.grants),(SELECT count(*) FROM management_authority.operation_receipts),(SELECT count(*) FROM management_authority.audit_events)")
            .fetch_one(&f.admin).await?;
        assert_eq!(counts,(1,1,1));
        let members: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.team_memberships WHERE administrator_id=$1")
            .bind(viewer).fetch_one(&f.pool).await?;
        assert_eq!(members,0);
        for (kind, expected) in [("teams",env.team_id), ("tenants",env.tenant_id), ("environments",env.environment_id), ("users",user), ("organizations",organization)] {
            let (status, page) = inventory(&app, f.installation, grant, kind, ("cookie", &cookie), "").await?;
            assert_eq!(status, StatusCode::OK, "{kind}: {page}");
            assert_eq!(ids(&page), vec![expected.to_string().as_str()]);
        }
        // A Team owner has no global grant, even when selecting another principal's grant.
        let (owner_app, owner_cookie, owner_runtime) = f.human_app(env.administrator_id).await?;
        assert_eq!(inventory(&owner_app, f.installation, grant, "teams", ("cookie", &owner_cookie), "").await?.0, StatusCode::FORBIDDEN);
        drop(owner_app); database_cleanup::close_pool(&owner_runtime).await?;
        for query in ["&limit=0", "&limit=201", "&unknown=1"] {
            assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), query).await?.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(inventory(&app, Uuid::new_v4(), grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::FORBIDDEN);
        let serving = f.pool.connect_options().get_username().to_owned();
        let revoke: String = sqlx::query_scalar("SELECT format('REVOKE EXECUTE ON FUNCTION management_authority.inventory_v1(jsonb) FROM %I', $1::text)")
            .bind(&serving).fetch_one(&f.admin).await?;
        sqlx::query(&revoke).execute(&f.admin).await?;
        assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::INTERNAL_SERVER_ERROR);
        let restore: String = sqlx::query_scalar("SELECT format('GRANT EXECUTE ON FUNCTION management_authority.inventory_v1(jsonb) TO %I', $1::text)")
            .bind(&serving).fetch_one(&f.admin).await?;
        sqlx::query(&restore).execute(&f.admin).await?;
        assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::OK);
        sqlx::query("DELETE FROM aegaeon.runtime_management_sessions WHERE administrator_id=$1").bind(viewer).execute(&f.admin).await?;
        assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::UNAUTHORIZED);
        f.pool.close().await;
        assert_eq!(inventory(&app, f.installation, grant, "teams", ("cookie", &cookie), "").await?.0, StatusCode::SERVICE_UNAVAILABLE);
        drop(app); database_cleanup::close_pool(&runtime).await?;
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_http_selectors_and_authorized_keyset() -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        let first = setup_runtime_key_test_environment(&f.pool).await?;
        let second = setup_runtime_key_test_environment(&f.pool).await?;
        let viewer = f.principal("HUMAN").await?;
        let (app, cookie, runtime) = f.human_app(viewer).await?;
        let current = f.grant_request(viewer,"HUMAN",f.selector("current_descendants"));
        let future = f.grant_request(viewer,"HUMAN",f.selector("current_and_future_descendants"));
        let exact = f.grant_request(viewer,"HUMAN",json!({"id":Uuid::new_v4(),"mode":"exact","anchor_kind":"team","anchor_id":first.team_id}));
        for request in [&current,&future,&exact] { f.bootstrap(request).await?; }
        let new_team = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.teams(id,name) VALUES($1,'Later')").bind(new_team).execute(&f.pool).await?;
        let (_, old) = inventory(&app,f.installation,grant_id(&current)?,"teams",("cookie",&cookie),"").await?;
        assert_eq!(ids(&old).len(),2); assert!(!ids(&old).contains(&new_team.to_string().as_str()));
        let (_, later) = inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),"").await?;
        assert_eq!(ids(&later).len(),3);
        let (_, selected) = inventory(&app,f.installation,grant_id(&exact)?,"teams",("cookie",&cookie),"").await?;
        assert_eq!(ids(&selected),vec![first.team_id.to_string().as_str()]);
        let (_, page) = inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),"&limit=1").await?;
        // Invalid UTF-8 and a JSON null escape both fail before cursor MAC validation.
        for malformed in ["ff", "7b2278223a225c7530303030227d"] {
            let invalid_encoding = format!("&limit=1&cursor={malformed}.{}", "0".repeat(64));
            let (status, refusal) = inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),&invalid_encoding).await?;
            assert_eq!(status,StatusCode::BAD_REQUEST);
            assert_eq!(refusal["errorCode"],"invalid_request");
        }
        let cursor = page["pageInfo"]["endCursor"].as_str().ok_or("cursor")?;
        let (_, next) = inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),&format!("&limit=1&cursor={cursor}")).await?;
        assert_ne!(ids(&page),ids(&next));
        assert_eq!(inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),&format!("&limit=2&cursor={cursor}")).await?.0,StatusCode::BAD_REQUEST);
        sqlx::query("UPDATE management_authority.grants SET revision=revision+1,label='description' WHERE id=$1")
            .bind(grant_id(&future)?).execute(&f.admin).await?;
        assert_eq!(inventory(&app,f.installation,grant_id(&future)?,"teams",("cookie",&cookie),&format!("&limit=1&cursor={cursor}")).await?.0,StatusCode::BAD_REQUEST);
        // Current ancestry removes moved resources even when a snapshot includes them.
        let scoped = f.grant_request(viewer,"HUMAN",json!({"id":Uuid::new_v4(),"mode":"current_descendants","anchor_kind":"team","anchor_id":first.team_id}));
        f.bootstrap(&scoped).await?;
        let (_, before) = inventory(&app,f.installation,grant_id(&scoped)?,"tenants",("cookie",&cookie),"").await?;
        assert_eq!(ids(&before),vec![first.tenant_id.to_string().as_str()]);
        sqlx::query("UPDATE aegaeon.tenants SET team_id=$1 WHERE id=$2").bind(second.team_id).bind(first.tenant_id).execute(&f.pool).await?;
        let (_, after) = inventory(&app,f.installation,grant_id(&scoped)?,"tenants",("cookie",&cookie),"").await?;
        assert!(ids(&after).is_empty());
        drop(app); database_cleanup::close_pool(&runtime).await?;
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_http_service_credential_ceiling_and_revoke() -> ManagementTestResult
{
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        let first = setup_runtime_key_test_environment(&f.pool).await?;
        setup_runtime_key_test_environment(&f.pool).await?;
        let principal = f.principal("SERVICE").await?;
        let request = f.grant_request(principal,"SERVICE",f.selector("current_and_future_descendants"));
        f.bootstrap(&request).await?;
        let prefix = format!("aeg_{}", &Uuid::new_v4().simple().to_string()[..8]);
        let secret = format!("{prefix}_{}",Uuid::new_v4().simple());
        let key: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.api_keys(team_id,service_administrator_id,name,key_prefix,key_hash) VALUES($1,$2,'inventory',$3,$4) RETURNING id")
            .bind(first.team_id).bind(principal).bind(prefix).bind(aegaeon_crypto::hash::sha256_digest(secret.as_bytes()).as_slice()).fetch_one(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.api_key_capabilities(api_key_id,capability) VALUES($1,'AUDIT_READ')").bind(key).execute(&f.pool).await?;
        let state = test_app_state(f.pool.clone(),test_management_state())?;
        let runtime = state.db_pool.clone();
        let app = crate::web::build_router(state);
        let bearer = format!("Bearer {secret}");
        assert_eq!(inventory(&app,f.installation,grant_id(&request)?,"teams",("authorization",&bearer),"").await?.0,StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.api_key_capabilities SET capability='READ' WHERE api_key_id=$1").bind(key).execute(&f.pool).await?;
        let (status,page) = inventory(&app,f.installation,grant_id(&request)?,"teams",("authorization",&bearer),"").await?;
        assert_eq!(status,StatusCode::OK); assert_eq!(ids(&page),vec![first.team_id.to_string().as_str()]);
        sqlx::query("UPDATE aegaeon.api_keys SET status='REVOKED',revoked_at=now(),revoked_by_administrator_id=$2 WHERE id=$1")
            .bind(key).bind(first.administrator_id).execute(&f.pool).await?;
        assert_eq!(inventory(&app,f.installation,grant_id(&request)?,"teams",("authorization",&bearer),"").await?.0,StatusCode::UNAUTHORIZED);
        drop(app); database_cleanup::close_pool(&runtime).await?;
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_http_live_ancestor_revocation() -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        setup_runtime_key_test_environment(&f.pool).await?;
        let principal = f.principal("HUMAN").await?;
        let mut root = f.grant_request(principal,"HUMAN",f.selector("current_and_future_descendants"));
        root["delegation_selector"] = f.selector("current_and_future_descendants");
        root["delegation_actions"] = root["use_actions"].clone();
        f.bootstrap(&root).await?;
        let mut parent = grant_id(&root)?;
        for _ in 0..2 {
            let child = Uuid::new_v4();
            // Administrative fixture insertion exercises the production trigger;
            // ordinary issuance still requires the final-transaction work in #316.
            sqlx::query("INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent) SELECT $1,installation_id,principal_id,principal_kind,id,delegation_epoch,delegation_selector_id,delegation_action_policy,delegation_actions,delegation_selector_id,delegation_action_policy,delegation_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent FROM management_authority.grants WHERE id=$2")
                .bind(child).bind(parent).execute(&f.admin).await?;
            parent = child;
        }
        let (app,cookie,runtime) = f.human_app(principal).await?;
        assert_eq!(inventory(&app,f.installation,parent,"teams",("cookie",&cookie),"").await?.0,StatusCode::OK);
        sqlx::query("UPDATE management_authority.grants SET revoked_at=now(),revision=revision+1,delegation_epoch=delegation_epoch+1 WHERE id=$1")
            .bind(grant_id(&root)?).execute(&f.admin).await?;
        assert_eq!(inventory(&app,f.installation,parent,"teams",("cookie",&cookie),"").await?.0,StatusCode::FORBIDDEN);
        let replacement = f.grant_request(principal,"HUMAN",f.selector("current_and_future_descendants"));
        f.bootstrap(&replacement).await?;
        assert_eq!(inventory(&app,f.installation,grant_id(&replacement)?,"teams",("cookie",&cookie),"").await?.0,StatusCode::OK);
        assert_eq!(inventory(&app,f.installation,parent,"teams",("cookie",&cookie),"").await?.0,StatusCode::FORBIDDEN);
        drop(app); database_cleanup::close_pool(&runtime).await?;
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_bootstrap_concurrent_receipt_is_atomic() -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        let principal = f.principal("HUMAN").await?;
        let request = f.grant_request(principal, "HUMAN", f.selector("current_and_future_descendants"));
        let mut barrier = f.admin.begin().await?;
        sqlx::query("SELECT id FROM management_authority.installation FOR UPDATE")
            .execute(&mut *barrier).await?;
        let submit = || {
            let pool = f.bootstrap.clone();
            let request = request.clone();
            tokio::spawn(async move { bootstrap(&pool, &request).await })
        };
        let first = submit();
        let second = submit();
        let login = f.bootstrap.connect_options().get_username().to_owned();
        let observed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT management_authority.bootstrap_v1%'")
                    .bind(&login).fetch_one(&f.admin).await?;
                if waiting == 2 { return Ok::<(),sqlx::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await;
        // Release and join both owned calls even if the observation timed out.
        barrier.rollback().await?;
        let (first, second) = tokio::join!(first, second);
        let first = first?;
        let second = second?;
        observed??;
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()),1);
        let failure = first.as_ref().err().or_else(||second.as_ref().err()).ok_or("missing serialized loser")?;
        assert_eq!(failure.as_database_error().and_then(|error|error.code()).as_deref(),Some("40001"));
        let original = first.as_ref().ok().or_else(||second.as_ref().ok()).ok_or("missing winner")?;
        assert_eq!(&f.bootstrap(&request).await?, original);
        let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_authority.grants),(SELECT count(*) FROM management_authority.operation_receipts),(SELECT count(*) FROM management_authority.audit_events)")
            .fetch_one(&f.admin).await?;
        assert_eq!(counts,(1,1,1));
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; verifies extension placement and missing supplier refusal"]
async fn pg_management_inventory_pgcrypto_placement_and_shadowing() -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        setup_runtime_key_test_environment(&f.pool).await?;
        setup_runtime_key_test_environment(&f.pool).await?;
        let viewer = f.principal("HUMAN").await?;
        let (app, cookie, runtime) = f.human_app(viewer).await?;
        let grant = f.grant_request(
            viewer,
            "HUMAN",
            f.selector("current_and_future_descendants"),
        );
        f.bootstrap(&grant).await?;
        sqlx::raw_sql(
            r#"
            CREATE SCHEMA "inventory-crypto";
            ALTER EXTENSION pgcrypto SET SCHEMA "inventory-crypto";
            GRANT USAGE ON SCHEMA "inventory-crypto" TO aegaeon_management_authority_owner;
            CREATE FUNCTION aegaeon.hmac(bytea,bytea,text) RETURNS bytea LANGUAGE SQL
              AS $$ SELECT pg_catalog.decode(pg_catalog.repeat('00',32),'hex') $$;
        "#,
        )
        .execute(&f.admin)
        .await?;
        let (status, page) = inventory(
            &app,
            f.installation,
            grant_id(&grant)?,
            "teams",
            ("cookie", &cookie),
            "&limit=1",
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        let cursor = page["pageInfo"]["endCursor"].as_str().ok_or("cursor")?;
        let (status, next) = inventory(
            &app,
            f.installation,
            grant_id(&grant)?,
            "teams",
            ("cookie", &cookie),
            &format!("&limit=1&cursor={cursor}"),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(ids(&page), ids(&next));
        // The old namespace shadow would accept this all-zero MAC. The real
        // extension function must remain selected for both generation and reads.
        let forged = format!(
            "{}.{}",
            cursor.split_once('.').ok_or("cursor delimiter")?.0,
            "00".repeat(32)
        );
        assert_eq!(
            inventory(
                &app,
                f.installation,
                grant_id(&grant)?,
                "teams",
                ("cookie", &cookie),
                &format!("&limit=1&cursor={forged}")
            )
            .await?
            .0,
            StatusCode::BAD_REQUEST
        );
        sqlx::query("DROP EXTENSION pgcrypto")
            .execute(&f.admin)
            .await?;
        let (status, refusal) = inventory(
            &app,
            f.installation,
            grant_id(&grant)?,
            "teams",
            ("cookie", &cookie),
            "&limit=1",
        )
        .await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(refusal.get("items").is_none());
        drop(app);
        database_cleanup::close_pool(&runtime).await?;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL, dedicated bootstrap credential and owned child database"]
async fn pg_management_inventory_oversized_name_keeps_lookahead_and_next_page(
) -> ManagementTestResult {
    let f = Fixture::new().await?;
    let result: ManagementTestResult = async {
        let viewer = f.principal("HUMAN").await?;
        let (app, cookie, runtime) = f.human_app(viewer).await?;
        let result: ManagementTestResult = async {
            let grant_request = f.grant_request(
                viewer,
                "HUMAN",
                f.selector("current_and_future_descendants"),
            );
            let grant = grant_id(&grant_request)?;
            f.bootstrap(&grant_request).await?;
            let long_name = "é".repeat(513);
            let ordinary_name = "A \t\nB";
            let mut created = Vec::new();
            for name in [long_name.as_str(), ordinary_name] {
                let response = app
                    .clone()
                    .oneshot(request(
                        "/api/v1/teams",
                        json!({"name":name}),
                        &cookie,
                        "https://admin.aegaeon.test",
                        true,
                    ))
                    .await?;
                assert_eq!(response.status(), StatusCode::CREATED);
                let value: Value = serde_json::from_slice(
                    &body::to_bytes(response.into_body(), 64 * 1024).await?,
                )?;
                assert_eq!(value["name"], name);
                created.push(
                    value["id"]
                        .as_str()
                        .ok_or("created team id")?
                        .parse::<Uuid>()?,
                );
            }
            created.sort();
            // Arrange UUID ordering through the existing update API, so the long
            // authorized row is deterministically the first page's lookahead.
            for (id, name) in [
                (created[0], ordinary_name),
                (created[1], long_name.as_str()),
            ] {
                let mut update = request(
                    &format!("/api/v1/teams/{id}"),
                    json!({"name":name}),
                    &cookie,
                    "https://admin.aegaeon.test",
                    true,
                );
                *update.method_mut() = Method::PATCH;
                let response = app.clone().oneshot(update).await?;
                assert_eq!(response.status(), StatusCode::OK);
                let value: Value = serde_json::from_slice(
                    &body::to_bytes(response.into_body(), 64 * 1024).await?,
                )?;
                assert_eq!(value["name"], name);
            }
            let (status, first) = inventory(
                &app,
                f.installation,
                grant,
                "teams",
                ("cookie", &cookie),
                "&limit=1",
            )
            .await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(ids(&first), vec![created[0].to_string()]);
            assert_eq!(first["items"][0]["name"], ordinary_name);
            assert_eq!(first["pageInfo"]["hasNextPage"], true);
            let cursor = first["pageInfo"]["endCursor"]
                .as_str()
                .ok_or("next cursor")?;
            let (status, second) = inventory(
                &app,
                f.installation,
                grant,
                "teams",
                ("cookie", &cookie),
                &format!("&limit=1&cursor={cursor}"),
            )
            .await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(ids(&second), vec![created[1].to_string()]);
            assert!(second["items"][0].as_object().unwrap().contains_key("name"));
            assert_eq!(second["items"][0]["name"], Value::Null);
            assert_eq!(second["pageInfo"]["hasNextPage"], false);
            assert_eq!(second["pageInfo"]["endCursor"], Value::Null);
            let stored: String = sqlx::query_scalar("SELECT name FROM aegaeon.teams WHERE id=$1")
                .bind(created[1])
                .fetch_one(&f.pool)
                .await?;
            assert_eq!(stored, long_name);
            Ok(())
        }
        .await;
        drop(app);
        runtime.close().await;
        result
    }
    .await;
    f.finish(result).await
}
