use super::*;
use crate::lti::{store, LtiError};
use axum::{response::Response, Router};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    app: Router,
    pool: PgPool,
    session: String,
    uri: String,
    environment: Uuid,
    registration: Uuid,
    configuration: Value,
    previous: Value,
}

impl Fixture {
    async fn new(pool: &PgPool) -> Result<Self> {
        let initialized = initialize_management(pool, &input()).await?;
        let mut management = test_management_state();
        management.cfg = std::sync::Arc::new(
            crate::web::management::ManagementConfig::try_from_env_with_database(pool).await?,
        );
        let app = crate::web::build_router(test_app_state(pool.clone(), management)?);
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
        let session = login
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("aegaeon_admin_session="))
            .and_then(|value| value.split(';').next())
            .ok_or("admin session")?
            .to_string();
        sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,'tool','Example Tool','PUBLIC',ARRAY['https://tool.example/launch'],ARRAY['authorization_code'],ARRAY['openid'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
            .bind(initialized.environment_id).execute(pool).await?;
        let configuration = json!({
            "schemaVersion":1,"name":"Example Tool","status":"active",
            "initiateLoginUri":"https://tool.example/login",
            "redirectUris":["https://tool.example/launch"],
            "deployments":[{"id":"deployment-1","status":"active",
                "producers":["producer"],"allowedRoles":[],
                "resourceLinks":[{"id":"resource-1","status":"retired",
                    "targetLinkUri":"https://tool.example/resource",
                    "context":{"id":"context-1","types":[]}}]}]
        });
        let mut fixture = Self {
            app,
            pool: pool.clone(),
            session,
            uri: format!(
                "/api/v1/teams/{}/environments/{}/lti/registrations",
                initialized.team_id, initialized.environment_id
            ),
            environment: initialized.environment_id,
            registration: Uuid::nil(),
            configuration,
            previous: Value::Null,
        };
        let response = fixture
            .send(
                Method::PUT,
                "",
                fixture.payload(0, fixture.configuration.clone()),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let saved: Value =
            serde_json::from_slice(&body::to_bytes(response.into_body(), 262144).await?)?;
        fixture.registration = Uuid::parse_str(saved["id"].as_str().ok_or("registration id")?)?;
        fixture.previous = saved["configuration"].clone();
        fixture.previous["initiateLoginUri"] = json!("https:tool.example/login");
        fixture.previous["redirectUris"] = json!(["https:/tool.example/launch"]);
        fixture.previous["deployments"][0]["resourceLinks"][0]["targetLinkUri"] =
            json!("HTTPS:tool.example/resource");
        // Model a revision saved by the previous validator. Insert history without
        // disabling immutability, changing an existing document or bypassing roles.
        fixture.append_previous(2, &fixture.previous).await?;
        Ok(fixture)
    }

    fn payload(&self, revision: i64, configuration: Value) -> Value {
        json!({"clientId":"tool","baseRevision":revision,"configuration":configuration})
    }

    async fn send(&self, method: Method, suffix: &str, payload: Value) -> Result<Response> {
        let mut req = request(
            &format!("{}{suffix}", self.uri),
            payload,
            &self.session,
            "https://admin.aegaeon.test",
            true,
        );
        *req.method_mut() = method;
        Ok(self.app.clone().oneshot(req).await?)
    }

    async fn append_previous(&self, revision: i64, document: &Value) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO aegaeon.lti_registration_revisions(registration_id,revision,document,author_id) SELECT registration_id,$2,$3,author_id FROM aegaeon.lti_registration_revisions WHERE registration_id=$1 AND revision=1")
            .bind(self.registration).bind(revision).bind(document).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE aegaeon.lti_registrations SET revision=$2,active_revision=$2 WHERE id=$1",
        )
        .bind(self.registration)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn active_is_valid(&self) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let result = store::load(&mut tx, self.environment, "tool", true).await;
        tx.rollback().await?;
        match result {
            Ok(Some(_)) => Ok(true),
            Err(LtiError::Invalid) => Ok(false),
            other => Err(format!("unexpected active read: {other:?}").into()),
        }
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_lti_management_repairs_legacy_destinations_without_activating_them(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult = async {
        let fixture = Fixture::new(&pool).await?;
        assert!(!fixture.active_is_valid().await?);
        assert_eq!(fixture.send(Method::GET,"?clientId=tool",Value::Null).await?.status(),StatusCode::BAD_REQUEST);
        assert_eq!(fixture.send(Method::POST,"/activate",json!({"clientId":"tool","revision":2})).await?.status(),StatusCode::BAD_REQUEST);
        let response = fixture.send(Method::PUT,"",fixture.payload(2,fixture.configuration.clone())).await?;
        let status = response.status();
        let bytes = body::to_bytes(response.into_body(),262144).await?;
        assert_eq!(status,StatusCode::OK,"{}",String::from_utf8_lossy(&bytes));
        let saved:Value = serde_json::from_slice(&bytes)?;
        assert_eq!(saved["id"],fixture.registration.to_string());
        assert_eq!(saved["revision"],3);
        assert_eq!(saved["activeRevision"],2);
        assert_eq!(saved["configuration"]["initiateLoginUri"],fixture.configuration["initiateLoginUri"]);
        assert!(!fixture.active_is_valid().await?);
        assert_eq!(fixture.send(Method::POST,"/activate",json!({"clientId":"tool","revision":3})).await?.status(),StatusCode::OK);
        assert!(fixture.active_is_valid().await?);
        let old:Value=sqlx::query_scalar("SELECT document FROM aegaeon.lti_registration_revisions WHERE registration_id=$1 AND revision=2")
            .bind(fixture.registration).fetch_one(&pool).await?;
        assert_eq!(old,fixture.previous);
        assert!(sqlx::query("UPDATE aegaeon.lti_registration_revisions SET document=$2 WHERE registration_id=$1 AND revision=2")
            .bind(fixture.registration).bind(&fixture.configuration).execute(&pool).await.is_err());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.lti_registration_revisions WHERE registration_id=$1")
            .bind(fixture.registration).fetch_one(&pool).await?;
        assert_eq!(count,3);
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type LIKE 'management.lti.%'")
            .bind(fixture.environment).fetch_one(&pool).await?;
        assert_eq!(events,3);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_lti_management_repair_preserves_validation_identity_and_retirement(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult = async {
        let fixture = Fixture::new(&pool).await?;
        let mut changed_context=fixture.configuration.clone();
        changed_context["deployments"][0]["resourceLinks"][0]["context"]["id"]=json!("another-context");
        let mut removed=fixture.configuration.clone();removed["deployments"]=json!([]);
        let mut revived=fixture.configuration.clone();revived["deployments"][0]["resourceLinks"][0]["status"]=json!("active");
        for (base,config,expected) in [
            (2,fixture.previous.clone(),StatusCode::BAD_REQUEST),
            (1,fixture.configuration.clone(),StatusCode::CONFLICT),
            (2,changed_context,StatusCode::CONFLICT),
            (2,removed,StatusCode::CONFLICT),
            (2,revived,StatusCode::CONFLICT),
        ] {
            assert_eq!(fixture.send(Method::PUT,"",fixture.payload(base,config)).await?.status(),expected);
        }
        for (cookie,csrf,expected) in [("",true,StatusCode::UNAUTHORIZED),(fixture.session.as_str(),false,StatusCode::FORBIDDEN)] {
            let mut req=request(&fixture.uri,fixture.payload(2,fixture.configuration.clone()),cookie,"https://admin.aegaeon.test",csrf);
            *req.method_mut()=Method::PUT;
            assert_eq!(fixture.app.clone().oneshot(req).await?.status(),expected);
        }
        let foreign=fixture.uri.replace(&fixture.environment.to_string(),&Uuid::new_v4().to_string());
        let mut req=request(&foreign,fixture.payload(2,fixture.configuration.clone()),&fixture.session,"https://admin.aegaeon.test",true);
        *req.method_mut()=Method::PUT;
        assert_eq!(fixture.app.clone().oneshot(req).await?.status(),StatusCode::NOT_FOUND);
        let revision:i64=sqlx::query_scalar("SELECT revision FROM aegaeon.lti_registrations WHERE id=$1")
            .bind(fixture.registration).fetch_one(&pool).await?;
        assert_eq!(revision,2);
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type LIKE 'management.lti.%'")
            .bind(fixture.environment).fetch_one(&pool).await?;
        assert_eq!(events,1);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_lti_management_repair_rejects_undecodable_history() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let fixture = Fixture::new(&pool).await?;
        let mut malformed = fixture.previous.clone();
        malformed
            .as_object_mut()
            .ok_or("configuration object")?
            .remove("name");
        fixture.append_previous(3, &malformed).await?;
        assert_eq!(
            fixture
                .send(
                    Method::PUT,
                    "",
                    fixture.payload(3, fixture.configuration.clone())
                )
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM aegaeon.lti_registrations WHERE id=$1")
                .bind(fixture.registration)
                .fetch_one(&pool)
                .await?;
        assert_eq!(revision, 3);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
