//! Browser CSRF -> native request -> real TLS -> credential change and login.
use super::*;
use crate::organizations::invitations::transport::fixture::Fixture as Transport;
use std::time::Duration;
mod refusals;
const PASSWORD: &str = "enrollment-private-password-v1";

async fn enable(f: &RecipientFixture) -> TestResult {
    delivery::configure(f).await?;
    sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=$2 WHERE id=$1")
        .bind(f.state.environment_id)
        .bind(json!({"registration":true,"passwordRecovery":true,"subjectFormat":"uuid"}))
        .execute(&f.base.pool)
        .await?;
    Ok(())
}

async fn form(f: &RecipientFixture) -> TestResult<(String, String)> {
    let mut request = Request::get(f.path("identity")).body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(f.state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .ok_or("cookie")?
        .to_owned();
    let body = String::from_utf8(to_bytes(response.into_body(), 16384).await?.to_vec())?;
    let token = body
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("csrf")?
        .to_owned();
    assert!(!body.contains(&f.capability));
    Ok((cookie, token))
}

async fn post(
    f: &RecipientFixture,
    mut fields: Vec<(&str, String)>,
    csrf: Option<(String, String)>,
) -> TestResult<(StatusCode, Value)> {
    let (cookie, token) = match csrf {
        Some(value) => value,
        None => form(f).await?,
    };
    fields.push(("csrf_token", token));
    let origin = url::Url::parse(&f.state.issuer)?
        .origin()
        .ascii_serialization();
    let mut request = Request::post(f.path("identity"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ORIGIN, origin)
        .header(header::COOKIE, cookie)
        .header("x-request-id", "identity-browser-request")
        .body(Body::from(serde_urlencoded::to_string(fields)?))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(f.state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    let value = serde_json::from_slice(&to_bytes(response.into_body(), 16384).await?)?;
    Ok((status, value))
}

async fn request(
    f: &RecipientFixture,
    purpose: &str,
    login: &str,
    key: &str,
) -> TestResult<(StatusCode, Value)> {
    post(
        f,
        vec![
            ("action", "request".into()),
            ("purpose", purpose.into()),
            ("invitation_capability", f.capability.clone()),
            ("login_identifier", login.into()),
            ("request_key", key.into()),
        ],
        None,
    )
    .await
}
fn completion(id: Uuid, proof: &str, password: &str) -> Vec<(&'static str, String)> {
    vec![
        ("action", "complete".into()),
        ("request_id", id.to_string()),
        ("proof", proof.into()),
        ("password", password.into()),
        ("password_confirmation", password.into()),
    ]
}
async fn delivered(f: &RecipientFixture, id: Uuid, transport: &Transport) -> TestResult<Value> {
    let result = f
        .state
        .deliver_organization_invitation(crate::web::OrganizationDeliveryRequest {
            domain_id: f.organization.scope.domain_id,
            invitation_id: f.invitation,
            challenge_id: None,
            identity_request_id: Some(id),
            credential: delivery::credential(),
        })
        .await?;
    assert_eq!(result.outcome, "acknowledged");
    Ok(transport
        .received
        .lock()
        .unwrap()
        .last()
        .ok_or("envelope")?
        .clone())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_registration_tls_replay_and_case_exact_address(
) -> TestResult {
    let f = setup::new().await?;
    let result = async {
        assert_ne!(request(&f,"registration","","disabled").await?.0,StatusCode::OK);
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let (status,value) = request(&f,"registration","","new").await?;
        assert_eq!(status,StatusCode::OK,"{value}");
        let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        assert_eq!(request(&f,"registration","","new").await?.1["requestId"],id.to_string());
        let envelope = delivered(&f,id,&transport).await?;
        assert_eq!(envelope["template"],"organization_identity_registration");
        assert_eq!(envelope["recipient"],"Invitee@example.test");
        let proof = envelope["capability"].as_str().ok_or("proof")?;
        assert_ne!(post(&f,completion(id,&f.capability,PASSWORD),None).await?.0,StatusCode::OK);
        let csrf = form(&f).await?;
        let (first,second) = tokio::join!(post(&f,completion(id,proof,PASSWORD),Some(csrf.clone())),post(&f,completion(id,proof,PASSWORD),None));
        let (status,value) = first?;assert_eq!(second?.0,StatusCode::OK);
        assert_eq!(status,StatusCode::OK,"{value}");
        let subject = value["subject"].as_str().ok_or("subject")?;
        let user = Uuid::parse_str(subject)?;
        assert_eq!(post(&f,completion(id,proof,PASSWORD),None).await?.0,StatusCode::OK);
        assert_eq!(post(&f,completion(id,proof,"different-private-password"),None).await?.0,StatusCode::CONFLICT);
        assert_eq!(post(&f,completion(id,proof,PASSWORD),Some(csrf)).await?.0,StatusCode::FORBIDDEN);
        let (email,verified,address):(String,bool,String) = sqlx::query_as("SELECT u.email,p.email_verified,p.verified_delivery_address FROM aegaeon.end_users u JOIN aegaeon.end_user_profiles p ON p.end_user_id=u.id WHERE u.id=$1")
            .bind(user).fetch_one(&f.base.pool).await?;
        assert_eq!(email,"invitee@example.test");assert!(!verified);assert_eq!(address,"Invitee@example.test");
        assert!(crate::local_credentials::authenticate_local_user(&f.base.pool,&f.state.issuer,subject,PASSWORD).await?.is_some());
        let memberships: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1 AND end_user_id=$2")
            .bind(f.organization.id).bind(user).fetch_one(&f.base.pool).await?;
        assert_eq!(memberships,0);
        let (request_id,completed):(String,Value) = sqlx::query_as("SELECT request_id,data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.identity_completed'")
            .bind(f.organization.id).fetch_one(&f.base.pool).await?;
        assert_eq!(request_id,"identity-browser-request");
        assert_eq!(completed["authorityBasis"]["executor"]["kind"],"recipient_identity_proof");
        assert_eq!(completed["authorityBasis"]["executor"]["userId"],user.to_string());
        assert_eq!(completed["before"]["state"],"pending");
        assert_eq!(completed["after"]["state"],"completed");
        let events: Vec<String> = sqlx::query_scalar("SELECT data::text FROM aegaeon.organization_authority_events WHERE organization_id=$1")
            .bind(f.organization.id).fetch_all(&f.base.pool).await?;
        assert_eq!(events.iter().filter(|v|v.contains("identity_revision")).count(),1);
        for event in events { for secret in [PASSWORD,proof,&f.capability,"Invitee@example.test"] { assert!(!event.contains(secret)); } }
        crate::organizations::repository_tests::import::validate_fixture_source(&f.base).await?;
        drop(transport);
        Ok(())
    }.await;
    fixture::finish(&f.state).await?;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_recovery_invalidates_siblings_and_no_implicit_link(
) -> TestResult {
    let f = setup::new().await?;
    let result = async {
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let user = f.base.users[0];
        sqlx::query("UPDATE aegaeon.end_users SET email='invitee@example.test' WHERE id=$1").bind(user).execute(&f.base.pool).await?;
        sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,email_verified,verified_delivery_address) VALUES ($1,false,'Invitee@example.test') ON CONFLICT(end_user_id) DO UPDATE SET verified_delivery_address='Invitee@example.test'").bind(user).execute(&f.base.pool).await?;
        sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES ($1,$2) ON CONFLICT(end_user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash")
            .bind(user).bind(crate::local_credentials::hash_password("previous-private-password")?).execute(&f.base.pool).await?;
        let subject: String = sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE id=$1").bind(user).fetch_one(&f.base.pool).await?;
        let mut proofs = Vec::new();
        for key in ["first","second"] {
            let (status,value) = request(&f,"password_recovery",&subject,key).await?;assert_eq!(status,StatusCode::OK,"{value}");
            let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
            let envelope = delivered(&f,id,&transport).await?;
            assert_eq!(envelope["template"],"organization_identity_recovery");
            proofs.push((id,envelope["capability"].as_str().ok_or("proof")?.to_owned()));
        }
        assert_eq!(post(&f,completion(proofs[0].0,&proofs[0].1,PASSWORD),None).await?.0,StatusCode::OK);
        assert_ne!(post(&f,completion(proofs[1].0,&proofs[1].1,"a-different-new-password"),None).await?.0,StatusCode::OK);
        assert!(crate::local_credentials::authenticate_local_user(&f.base.pool,&f.state.issuer,&subject,PASSWORD).await?.is_some());
        assert!(crate::local_credentials::authenticate_local_user(&f.base.pool,&f.state.issuer,&subject,"previous-private-password").await?.is_none());
        // A registration proof never attaches an existing login alias.
        let value = request(&f,"registration","","existing").await?.1;
        let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        let envelope = delivered(&f,id,&transport).await?;
        assert_eq!(post(&f,completion(id,envelope["capability"].as_str().ok_or("proof")?,PASSWORD),None).await?.0,StatusCode::CONFLICT);
        // Restoring the same policy cannot restore the completed or pending request.
        sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=NULL WHERE id=$1").bind(f.state.environment_id).execute(&f.base.pool).await?;
        sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=$2 WHERE id=$1").bind(f.state.environment_id).bind(json!({"registration":true,"passwordRecovery":true,"subjectFormat":"uuid"})).execute(&f.base.pool).await?;
        assert_ne!(post(&f,completion(proofs[0].0,&proofs[0].1,PASSWORD),None).await?.0,StatusCode::OK);
        crate::organizations::repository_tests::import::validate_fixture_source(&f.base).await?;
        drop(transport);Ok(())
    }.await;
    fixture::finish(&f.state).await?;
    f.base.cleanup(result).await
}
