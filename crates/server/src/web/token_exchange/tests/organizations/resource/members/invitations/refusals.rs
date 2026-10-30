use super::*;

const BODY: &str =
    r#"{"recipient":"Member@example.test","roles":["reader"],"reason":"invite a member"}"#;
const CANCEL: &str = r#"{"reason":"cancel pending invitation"}"#;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_delegated_invitation_boundaries_races_and_reserved_revocation(
) -> TestResult {
    use crate::organizations::request_work::{Admission, MAX_REQUESTS};
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let result = async {
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET assignable_roles='[\"reader\"]',version=version+1 WHERE environment_id=$1 AND role_key='reader'").bind(state.environment_id).execute(&f.pool).await?;
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (root, token) = issue(&f, &state, &key, MANAGE).await?;
        let client = MemberClient { state: &state, key: &key, read: token.clone(), write: token.clone(), list: String::new() };
        let path = format!("/organizations/{}/invitations", f.organization.id);
        let tag = VersionTag::new(f.organization.id, f.organization.revision).map_err(|_| "version")?.header_value();
        let stale = VersionTag::new(f.organization.id, f.organization.revision+1).map_err(|_| "version")?.header_value();
        assert_eq!(client.request(Method::POST,&path,&token,Some(&stale),Some("stale"),BODY).await?.0,StatusCode::PRECONDITION_FAILED);
        for body in [
            r#"{"recipient":"Member@example.test","roles":["reader","reader"],"reason":"duplicate"}"#,
            r#"{"recipient":"Member@example.test","roles":["reader"],"reason":"unknown","bypass":true}"#,
            r#"{"recipient":"Member@example.test","roles":["reader"],"reason":"first","reason":"duplicate"}"#,
        ] {
            assert_eq!(client.request(Method::POST,&path,&token,Some(&tag),Some("invalid"),body).await?.0,StatusCode::BAD_REQUEST);
        }
        let stronger = BODY.replace("reader", "admin");
        assert_eq!(client.request(Method::POST,&path,&token,Some(&tag),Some("escalate"),&stronger).await?.0,StatusCode::FORBIDDEN);
        let (_, read) = issue(&f,&state,&key,READ).await?;
        assert_eq!(client.request(Method::POST,&path,&read,Some(&tag),Some("read-only"),BODY).await?.0,StatusCode::FORBIDDEN);
        let foreign=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,'foreign-invitation','active')").bind(foreign).bind(state.environment_id).bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        let foreign_tag=VersionTag::new(foreign,1).map_err(|_| "version")?.header_value();
        assert_eq!(client.request(Method::POST,&format!("/organizations/{foreign}/invitations"),&token,Some(&foreign_tag),Some("foreign"),BODY).await?.0,StatusCode::FORBIDDEN);
        let (a,b)=tokio::join!(
            client.request(Method::POST,&path,&token,Some(&tag),Some("same"),BODY),
            client.request(Method::POST,&path,&token,Some(&tag),Some("same"),BODY)
        );
        let (a,b)=(a?,b?);assert_eq!(a.0,StatusCode::OK,"{}",a.1);assert_eq!(a,b);
        let id=a.1["id"].as_str().ok_or("id")?;
        let item=format!("{path}/{id}");
        let etag=a.2.as_deref().ok_or("etag")?;
        assert_eq!(client.request(Method::GET,&item,&token,None,None,"").await?,a);
        assert_eq!(client.request(Method::HEAD,&item,&token,None,None,"").await?.0,StatusCode::OK);
        assert_eq!(client.request(Method::GET,&format!("/organizations/{foreign}/invitations/{id}"),&token,None,None,"").await?.0,StatusCode::FORBIDDEN);
        assert_eq!(client.request(Method::POST,&path,&token,Some(&tag),Some("same"),&BODY.replace("Member@","Other@")).await?.0,StatusCode::CONFLICT);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitations WHERE environment_id=$1").bind(state.environment_id).fetch_one(&f.pool).await?;assert_eq!(count,1);
        let revoke=format!("{item}/revoke");
        let (a,b)=tokio::join!(
            client.request(Method::POST,&revoke,&token,Some(etag),Some("cancel-a"),CANCEL),
            client.request(Method::POST,&revoke,&token,Some(etag),Some("cancel-b"),CANCEL)
        );
        let (a,b)=(a?,b?);
        // The single cancellation admission may refuse the concurrent request
        // before it reaches the serialized compare-and-swap.
        assert!([a.0,b.0].contains(&StatusCode::OK));
        let (winner,winning_key,loser)=if a.0==StatusCode::OK {(a,"cancel-a",b)} else {(b,"cancel-b",a)};
        assert!([StatusCode::SERVICE_UNAVAILABLE,StatusCode::PRECONDITION_FAILED].contains(&loser.0));
        assert_eq!(client.request(Method::POST,&revoke,&token,Some(etag),Some(winning_key),CANCEL).await?,winner);
        assert_eq!(client.request(Method::POST,&revoke,&token,Some(etag),Some("late"),CANCEL).await?.0,StatusCode::PRECONDITION_FAILED);
        let pending=client.request(Method::POST,&path,&token,Some(&tag),Some("pending"),BODY).await?;
        assert_eq!(pending.0,StatusCode::OK);
        let pending_path=format!("{path}/{}",pending.1["id"].as_str().ok_or("pending")?);
        let (_,fresh)=issue(&f,&state,&key,MANAGE).await?;
        state.tokens.store.try_revoke_token(root["refresh_token"].as_str().ok_or("root")?)?;
        assert_eq!(client.request(Method::GET,&pending_path,&token,None,None,"").await?.0,StatusCode::UNAUTHORIZED);
        assert_eq!(client.request(Method::GET,&pending_path,&fresh,None,None,"").await?.0,StatusCode::OK);
        Admission::drain_for_test().await?;
        let holds=(0..MAX_REQUESTS).map(|_|Admission::try_acquire()).collect::<Result<Vec<_>,_>>()?;
        assert_eq!(client.request(Method::GET,&pending_path,&fresh,None,None,"").await?.0,StatusCode::SERVICE_UNAVAILABLE);
        let cancelled=client.request(Method::POST,&format!("{pending_path}/revoke"),&fresh,pending.2.as_deref(),Some("reserved"),CANCEL).await?;
        assert_eq!(cancelled.0,StatusCode::OK,"{}",cancelled.1);
        assert_eq!(cancelled.1["state"],"revoked");
        drop(holds);
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1").bind(f.users[1]).execute(&f.pool).await?;
        assert_eq!(client.request(Method::POST,&format!("{pending_path}/revoke"),&fresh,pending.2.as_deref(),Some("reserved"),CANCEL).await?.0,StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
