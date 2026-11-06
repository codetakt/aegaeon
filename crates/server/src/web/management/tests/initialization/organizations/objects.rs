use super::*;
mod audit;
mod audit_delivery;
mod boundaries;
mod delivery;
mod identity_policy;
mod invitations;
mod recovery;
mod role_policy;
mod role_policy_bounds;
mod snapshot;
mod support_policy;

struct Harness {
    app: axum::Router,
    cookie: String,
    collection: String,
    domain: Uuid,
    environment: Uuid,
    administrator: Uuid,
}

impl Harness {
    async fn new(pool: &sqlx::PgPool) -> Result<Self, Box<dyn std::error::Error>> {
        let initialized = initialize_management(pool, &input()).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = Arc::new(
            crate::web::management::ManagementConfig::try_from_env_with_database(pool).await?,
        );
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let login = app
            .clone()
            .oneshot(request(
                "/api/v1/authentication/sessions",
                json!({"email":input().owner_email,"password":input().owner_password}),
                "",
                "https://admin.aegaeon.test",
                true,
            ))
            .await?;
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let cookie = login
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("aegaeon_admin_session="))
            .ok_or("session")?
            .split(';')
            .next()
            .ok_or("cookie")?
            .to_owned();
        let base = format!(
            "/api/v1/teams/{}/environments/{}/organization-domains",
            initialized.team_id, initialized.environment_id
        );
        let (domain, tag) = representation(
            app.clone()
                .oneshot(mutation(
                    &format!("{base}/default"),
                    Method::POST,
                    json!({"reason":"initialize"}),
                    &cookie,
                    "bootstrap",
                    None,
                ))
                .await?,
            StatusCode::OK,
        )
        .await?;
        let id = Uuid::parse_str(domain["id"].as_str().ok_or("id")?)?;
        let path = format!("{base}/{id}");
        let collection = format!("{path}/organizations");
        let (_,tag) = representation(app.clone().oneshot(mutation(&format!("{path}/targets"),Method::POST,json!({"audience":"urn:example:provisioning","management":false,"reason":"target"}),&cookie,"target",Some(&tag))).await?,StatusCode::OK).await?;
        // Registered-client supply is a fixture; domain bootstrap, policy and
        // enablement use their mounted authenticated APIs.
        let registration = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT $1,id,active_configuration_version_id,'provisioning-fixture','organization fixture','CONFIDENTIAL',ARRAY['https://client.example/cb'],ARRAY['authorization_code','urn:ietf:params:oauth:grant-type:token-exchange'],ARRAY['openid'],'client_secret_basic',true FROM aegaeon.environments WHERE id=$2")
            .bind(registration).bind(initialized.environment_id).execute(pool).await?;
        representation(app.clone().oneshot(mutation(&format!("{path}/clients"),Method::POST,json!({"clientRegistrationId":registration,"active":true,"targets":[{"audience":"urn:example:provisioning","privileges":["read"]}],"reason":"client"}),&cookie,"client",Some(&tag))).await?,StatusCode::OK).await?;
        let (_, tag) = representation(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(&path)
                        .header("cookie", &cookie)
                        .body(Body::empty())?,
                )
                .await?,
            StatusCode::OK,
        )
        .await?;
        representation(
            app.clone()
                .oneshot(mutation(
                    &format!("{path}/enable"),
                    Method::POST,
                    json!({"reason":"enable"}),
                    &cookie,
                    "enable",
                    Some(&tag),
                ))
                .await?,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(
            app.clone()
                .oneshot(mutation(
                    &collection,
                    Method::POST,
                    json!({"externalId":"unauthorized","reason":"create"}),
                    &cookie,
                    "unauthorized",
                    None
                ))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(&collection)
                        .header("cookie", &cookie)
                        .body(Body::empty())?
                )
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        let grant = domain["operator"]["id"].as_str().ok_or("grant")?;
        representation(app.clone().oneshot(mutation(&format!("{path}/operators/{grant}"),Method::PATCH,json!({"active":true,"capabilities":["configure","provision","reconcile"],"reason":"explicit operator capabilities"}),&cookie,"grant",Some(&format!("\"{grant}.1\"")))).await?,StatusCode::OK).await?;
        Ok(Self {
            app,
            cookie,
            collection,
            domain: id,
            environment: initialized.environment_id,
            administrator: initialized.administrator_id,
        })
    }

    fn create(&self, external: &str, key: &str) -> Request<Body> {
        mutation(
            &self.collection,
            Method::POST,
            json!({"externalId":external,"reason":"provision"}),
            &self.cookie,
            key,
            None,
        )
    }

    fn read(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("cookie", &self.cookie)
            .body(Body::empty())
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_provisioning_reconciles_exact_ids_and_rechecks_replay_authority(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let external = "urn:学校/É?external=1";
        let (a, b) = tokio::join!(
            h.app.clone().oneshot(h.create(external, "same")),
            h.app.clone().oneshot(h.create(external, "same"))
        );
        let (created, tag) = representation(a?, StatusCode::OK).await?;
        assert_eq!(
            representation(b?, StatusCode::OK).await?,
            (created.clone(), tag.clone())
        );
        assert_eq!(created["externalId"], external);
        assert_eq!(created["state"], "provisioning");
        assert!(created.get("grantGeneration").is_none());
        let id = created["id"].as_str().ok_or("id")?.to_owned();
        Uuid::parse_str(&id)?;
        let item = format!("{}/{id}", h.collection);
        assert_eq!(
            representation(h.app.clone().oneshot(h.read(&item)).await?, StatusCode::OK).await?,
            (created.clone(), tag.clone())
        );
        assert_eq!(
            h.app
                .clone()
                .oneshot(h.create("different", "same"))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        for (i, value) in ["School", "school", "É", "E\u{301}"]
            .into_iter()
            .enumerate()
        {
            let (row, _) = representation(
                h.app
                    .clone()
                    .oneshot(h.create(value, &format!("distinct-{i}")))
                    .await?,
                StatusCode::OK,
            )
            .await?;
            assert_eq!(row["externalId"], value);
        }
        let mut uri = format!("{}?pageSize=2", h.collection);
        let mut ids = std::collections::BTreeSet::new();
        let mut cursor = None;
        loop {
            let response = h.app.clone().oneshot(h.read(&uri)).await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let value: Value =
                serde_json::from_slice(&body::to_bytes(response.into_body(), 65_536).await?)?;
            for row in value["organizations"].as_array().ok_or("organizations")? {
                assert!(ids.insert(row["id"].as_str().ok_or("id")?.to_owned()));
            }
            if let Some(next) = value["pageInfo"]["nextPageToken"].as_str() {
                cursor = Some(next.to_owned());
                uri = format!("{}?pageSize=2&pageToken={next}", h.collection);
            } else {
                break;
            }
        }
        assert_eq!(ids.len(), 5);
        let foreign = Uuid::new_v4();
        for uri in [
            format!("{}/{foreign}", h.collection),
            item.replace(&h.domain.to_string(), &foreign.to_string()),
        ] {
            assert_eq!(
                h.app.clone().oneshot(h.read(&uri)).await?.status(),
                StatusCode::FORBIDDEN
            );
        }
        let domain = h.collection.strip_suffix("/organizations").ok_or("path")?;
        assert_eq!(
            h.app
                .clone()
                .oneshot(h.read(&format!(
                    "{domain}/operators?pageToken={}",
                    cursor.ok_or("cursor")?
                )))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let delete = format!("{item}/delete");
        assert_eq!(
            h.app
                .clone()
                .oneshot(mutation(
                    &delete,
                    Method::POST,
                    json!({"reason":"retire"}),
                    &h.cookie,
                    "stale",
                    Some(&format!("\"{id}.2\""))
                ))
                .await?
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
        // A refused mutation still owns the restrictive lease until rollback
        // and pool cleanup finish. Wait for observed cleanup before retrying.
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let (deleted, _) = representation(
            h.app
                .clone()
                .oneshot(mutation(
                    &delete,
                    Method::POST,
                    json!({"reason":"retire"}),
                    &h.cookie,
                    "delete",
                    Some(&tag),
                ))
                .await?,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(deleted["state"], "deleted");
        assert_eq!(
            h.app
                .clone()
                .oneshot(h.create(external, "reuse"))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let retained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1",
        )
        .bind(Uuid::parse_str(&id)?)
        .fetch_one(&pool)
        .await?;
        assert_eq!(retained, 2);
        sqlx::query(
            "UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1",
        )
        .bind(h.domain)
        .execute(&pool)
        .await?;
        assert_eq!(
            h.app
                .clone()
                .oneshot(h.create(external, "same"))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            h.app.clone().oneshot(h.read(&item)).await?.status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_provisioning_retains_deletion_at_receipt_capacity(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let (created,tag) = representation(h.app.clone().oneshot(h.create("retained","first")).await?,StatusCode::OK).await?;
        let id = created["id"].as_str().ok_or("id")?.to_owned();
        // Manufacture a retained ordinary budget boundary, not historical audit evidence.
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,operation,idempotency_key,request_digest,result,client_registration_id) SELECT $1,$2,$3,'operator','management-console','create','capacity-'||i,decode(repeat('00',32),'hex'),'{}'::jsonb,'00000000-0000-0000-0000-000000000000'::uuid FROM generate_series(1,9999) i")
            .bind(h.environment).bind(h.domain).bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.create("blocked","capacity")).await?.status(),StatusCode::CONFLICT);
        assert_eq!(representation(h.app.clone().oneshot(h.create("retained","first")).await?,StatusCode::OK).await?,(created,tag.clone()));
        let held = tokio::time::timeout(std::time::Duration::from_secs(3),async {
            loop {
                if let Ok(held) = (0..4).map(|_|crate::organizations::request_work::Admission::try_acquire()).collect::<Result<Vec<_>,_>>() {break held;}
                tokio::task::yield_now().await;
            }
        }).await?;
        assert_eq!(h.app.clone().oneshot(h.create("blocked-again","ordinary")).await?.status(),StatusCode::SERVICE_UNAVAILABLE);
        let path = format!("{}/{id}/delete",h.collection);
        let (deleted,_) = representation(h.app.clone().oneshot(mutation(&path,Method::POST,json!({"reason":"restrict"}),&h.cookie,"restrict",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(deleted["state"],"deleted");
        drop(held);
        let counts:(i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND operation IN ('create','set_state')), (SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$2), (SELECT count(*) FROM aegaeon.organization_authority_outbox o JOIN aegaeon.organization_authority_events e ON e.id=o.event_id WHERE e.organization_id=$2)").bind(h.domain).bind(Uuid::parse_str(&id)?).fetch_one(&pool).await?;
        assert_eq!(counts,(10001,2,2));
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
