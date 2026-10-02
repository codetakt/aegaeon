use super::*;
use crate::dcr_persistence::test_database::Database;
use crate::web::test_support::{setup_test_environment, TestEnvironment, TestResult};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

const MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/migrations/20261002120000_client_dpop_minimum.sql"
));
const REPAIR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/client-dpop-minimum-repair.sql"
));
const INPUT: &str = "CREATE TEMP TABLE client_dpop_minimum_repair_input(schema_version integer, environment_id uuid, client_id uuid, expected_row_sha256 text, dpop_bound_access_tokens text, operator_reference text)";

async fn seed(pool: &PgPool, env: &TestEnvironment, status: &str) -> TestResult<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,$2,'upgrade fixture','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none',$3::aegaeon.client_status FROM aegaeon.environments WHERE id=$1 RETURNING id")
        .bind(env.environment_id).bind(Uuid::new_v4().to_string()).bind(status).fetch_one(pool).await?)
}

async fn digest(conn: &mut PgConnection, id: Uuid) -> TestResult<String> {
    sqlx::query("SET TIME ZONE 'UTC'")
        .execute(&mut *conn)
        .await?;
    Ok(sqlx::query_scalar("SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(c)::text,'UTF8')),'hex') FROM aegaeon.clients c WHERE id=$1").bind(id).fetch_one(conn).await?)
}

async fn input(
    conn: &mut PgConnection,
    env: Uuid,
    id: Uuid,
    expected: &str,
    choice: &str,
) -> TestResult {
    sqlx::query("TRUNCATE pg_temp.client_dpop_minimum_repair_input")
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO pg_temp.client_dpop_minimum_repair_input VALUES(1,$1,$2,$3,$4,'change-123')",
    )
    .bind(env)
    .bind(id)
    .bind(expected)
    .bind(choice)
    .execute(conn)
    .await?;
    Ok(())
}

async fn snapshot(pool: &PgPool) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM aegaeon.audit_events a))").fetch_one(pool).await?)
}

async fn refused(conn: &mut PgConnection) -> TestResult {
    assert!(sqlx::raw_sql(REPAIR).execute(&mut *conn).await.is_err());
    sqlx::query("ROLLBACK").execute(conn).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; exact predecessor migration and all-retained cutover"]
async fn pg_client_dpop_upgrade_and_atomic_offline_resolution() -> TestResult {
    let db = Database::client_dpop_predecessor().await?;
    let result=async {
        let env=setup_test_environment(&db.pool).await?;
        let active=seed(&db.pool,&env,"ACTIVE").await?;
        let deleted=seed(&db.pool,&env,"DELETED").await?;
        let other=setup_test_environment(&db.pool).await?;
        let deleted_environment_client=seed(&db.pool,&other,"ACTIVE").await?;
        sqlx::query("UPDATE aegaeon.environments SET status='DELETED' WHERE id=$1").bind(other.environment_id).execute(&db.pool).await?;
        let historical=seed(&db.pool,&env,"ACTIVE").await?;
        let version:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.configuration_versions(environment_id,version_number,configuration_hash,status,configuration_document) VALUES($1,2,'historical','DRAFT','{}') RETURNING id").bind(env.environment_id).fetch_one(&db.pool).await?;
        sqlx::query("UPDATE aegaeon.clients SET configuration_version_id=$1 WHERE id=$2").bind(version).bind(historical).execute(&db.pool).await?;

        sqlx::raw_sql(MIGRATION).execute(&db.pool).await?;
        assert!(preflight_client_dpop_minimum(&db.pool).await.is_err());
        let pending:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.clients WHERE dpop_bound_access_tokens IS NULL").fetch_one(&db.pool).await?;
        assert_eq!(pending,4);
        let new=seed(&db.pool,&env,"ACTIVE").await?;
        let default:bool=sqlx::query_scalar("SELECT dpop_bound_access_tokens FROM aegaeon.clients WHERE id=$1").bind(new).fetch_one(&db.pool).await?;
        assert!(!default);
        assert!(sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT environment_id,configuration_version_id,$2,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,NULL FROM aegaeon.clients WHERE id=$1").bind(new).bind(Uuid::new_v4().to_string()).execute(&db.pool).await.is_err(), "explicit NULL inserts must fail");
        assert!(sqlx::query("UPDATE aegaeon.clients SET dpop_bound_access_tokens=NULL WHERE id=$1").bind(new).execute(&db.pool).await.is_err());
        sqlx::query("UPDATE aegaeon.clients SET name=name WHERE id=$1").bind(active).execute(&db.pool).await?;
        let mut conn=db.pool.acquire().await?;
        sqlx::query(INPUT).execute(&mut *conn).await?;
        let expected=digest(&mut conn,active).await?;
        input(&mut conn,env.environment_id,active,&expected,"true").await?;
        let before=snapshot(&db.pool).await?;
        sqlx::raw_sql(REPAIR).execute(&mut *conn).await?;
        assert_eq!(snapshot(&db.pool).await?,before,"distributed review form rolls back");
        sqlx::raw_sql("CREATE FUNCTION aegaeon.fail_dpop_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; CREATE TRIGGER fail_dpop_audit BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.fail_dpop_audit()").execute(&db.pool).await?;
        refused(&mut conn).await?;
        assert_eq!(snapshot(&db.pool).await?,before);
        sqlx::raw_sql("DROP TRIGGER fail_dpop_audit ON aegaeon.audit_events; DROP FUNCTION aegaeon.fail_dpop_audit()").execute(&db.pool).await?;
        let commit=REPAIR.strip_suffix("ROLLBACK;\n").ok_or("final rollback")?.to_owned()+"COMMIT;\n";
        sqlx::raw_sql(&commit).execute(&mut *conn).await?;
        let after=snapshot(&db.pool).await?;
        let mut expected_clients=before["clients"].clone();
        for row in expected_clients.as_array_mut().ok_or("clients")? { if row["id"]==active.to_string() { row["dpop_bound_access_tokens"]=true.into(); } }
        assert_eq!(after["clients"],expected_clients,"only selected column changes");
        let audit=sqlx::query("SELECT event_type,actor_type,actor_id,current_user::text AS role,session_user::text AS session_role,occurred_at <= clock_timestamp() AND occurred_at > clock_timestamp() - interval '5 minutes' AS recent,request_id,ip_address::text AS ip,user_agent,mfa,trace_id,data FROM aegaeon.audit_events WHERE event_type='maintenance.clientDpopMinimum.resolved.v1'").fetch_one(&db.pool).await?;
        assert_eq!(audit.get::<String,_>("actor_type"),"database_role");
        assert_eq!(audit.get::<String,_>("actor_id"),audit.get::<String,_>("role"));
        assert!(audit.get::<String,_>("request_id").starts_with("maintenance:"));
        for name in ["ip","user_agent","trace_id"] { assert!(audit.get::<Option<String>,_>(name).is_none()); }
        assert!(audit.get::<Option<bool>,_>("mfa").is_none());
        let data:Value=audit.get("data");assert_eq!(data["expected_row_sha256"],expected);assert_eq!(data["dpop_bound_access_tokens"],true);assert_eq!(data["team_id"],env.team_id.to_string());
        assert_eq!(data["session_user"],audit.get::<String,_>("session_role"));assert!(audit.get::<bool,_>("recent"));
        assert_eq!(data["schema_version"],1);assert_eq!(data["environment_id"],env.environment_id.to_string());assert_eq!(data["tenant_id"],env.tenant_id.to_string());assert_eq!(data["client_id"],active.to_string());assert_eq!(data["operator_reference"],"change-123");
        Uuid::parse_str(audit.get::<String,_>("request_id").strip_prefix("maintenance:").ok_or("maintenance prefix")?)?;

        refused(&mut conn).await?;
        assert_eq!(snapshot(&db.pool).await?,after);
        assert!(preflight_client_dpop_minimum(&db.pool).await.is_err(),"deleted retained client blocks startup");
        let expected=digest(&mut conn,deleted).await?;
        input(&mut conn,env.environment_id,deleted,&expected,"false").await?;
        sqlx::raw_sql(&commit).execute(&mut *conn).await?;

        for (environment,id) in [(env.environment_id,historical),(other.environment_id,deleted_environment_client)] {
            assert!(preflight_client_dpop_minimum(&db.pool).await.is_err());
            let expected=digest(&mut conn,id).await?;
            input(&mut conn,environment,id,&expected,"false").await?;
            sqlx::raw_sql(&commit).execute(&mut *conn).await?;
        }
        preflight_client_dpop_minimum(&db.pool).await?;
        drop(conn);
        Ok(())
    }.await;
    db.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; strict typed repair refusals"]
async fn pg_client_dpop_repair_rejects_invalid_duplicate_and_stale_input() -> TestResult {
    let db = Database::client_dpop_predecessor().await?;
    let result=async {
        let env=setup_test_environment(&db.pool).await?;
        let id=seed(&db.pool,&env,"ACTIVE").await?;
        sqlx::raw_sql(MIGRATION).execute(&db.pool).await?;
        let mut conn=db.pool.acquire().await?;
        assert!(sqlx::raw_sql(REPAIR).execute(&mut *conn).await.is_err());
        sqlx::query("ROLLBACK").execute(&mut *conn).await?;
        sqlx::query(INPUT).execute(&mut *conn).await?;
        let expected=digest(&mut conn,id).await?;
        let before=snapshot(&db.pool).await?;
        refused(&mut conn).await?;
        for choice in ["TRUE","False"," true","false ","t","f","1","0",""] {
            input(&mut conn,env.environment_id,id,&expected,choice).await?;
            refused(&mut conn).await?;assert_eq!(snapshot(&db.pool).await?,before);
        }
        for field in ["schema_version","environment_id","client_id","expected_row_sha256","dpop_bound_access_tokens","operator_reference"] {
            input(&mut conn,env.environment_id,id,&expected,"true").await?;
            sqlx::query(&format!("UPDATE pg_temp.client_dpop_minimum_repair_input SET {field}=NULL")).execute(&mut *conn).await?;
            refused(&mut conn).await?;
        }
        for change in [
            "schema_version=2", "expected_row_sha256=upper(expected_row_sha256)",
            "expected_row_sha256=repeat('a',63)","operator_reference=''",
            "operator_reference='contains space'","operator_reference=repeat('x',257)",
            "operator_reference=chr(10)", "operator_reference=chr(233)",
            "environment_id=pg_catalog.gen_random_uuid()", "client_id=pg_catalog.gen_random_uuid()",
        ] {
            input(&mut conn,env.environment_id,id,&expected,"true").await?;
            sqlx::query(&format!("UPDATE pg_temp.client_dpop_minimum_repair_input SET {change}")).execute(&mut *conn).await?;
            refused(&mut conn).await?;assert_eq!(snapshot(&db.pool).await?,before);
        }
        input(&mut conn,env.environment_id,id,&expected,"true").await?;
        sqlx::query("INSERT INTO pg_temp.client_dpop_minimum_repair_input SELECT * FROM pg_temp.client_dpop_minimum_repair_input").execute(&mut *conn).await?;
        refused(&mut conn).await?;
        input(&mut conn,env.environment_id,id,&expected,"true").await?;
        sqlx::query("UPDATE aegaeon.clients SET updated_at=updated_at+interval '1 second' WHERE id=$1").bind(id).execute(&db.pool).await?;
        let changed=snapshot(&db.pool).await?;
        refused(&mut conn).await?;assert_eq!(snapshot(&db.pool).await?,changed);
        drop(conn);Ok(())
    }.await;
    db.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; physical guard and column shape"]
async fn pg_client_dpop_fresh_schema_preflight_checks_actual_guard_shape() -> TestResult {
    let db = Database::create(false).await?;
    let result=async {
        preflight_client_dpop_minimum(&db.pool).await?;
        for (break_sql,restore) in [
            ("ALTER TABLE aegaeon.clients DISABLE TRIGGER clients_dpop_minimum_guard","ALTER TABLE aegaeon.clients ENABLE TRIGGER clients_dpop_minimum_guard"),
            ("ALTER TABLE aegaeon.clients ALTER COLUMN dpop_bound_access_tokens DROP DEFAULT","ALTER TABLE aegaeon.clients ALTER COLUMN dpop_bound_access_tokens SET DEFAULT false"),
            ("ALTER FUNCTION aegaeon.guard_client_dpop_minimum() SECURITY DEFINER","ALTER FUNCTION aegaeon.guard_client_dpop_minimum() SECURITY INVOKER"),
            ("ALTER TABLE aegaeon.clients ALTER COLUMN dpop_bound_access_tokens SET NOT NULL","ALTER TABLE aegaeon.clients ALTER COLUMN dpop_bound_access_tokens DROP NOT NULL"),
        ] {
            sqlx::raw_sql(break_sql).execute(&db.pool).await?;
            assert!(preflight_client_dpop_minimum(&db.pool).await.is_err(),"{break_sql}");
            sqlx::raw_sql(restore).execute(&db.pool).await?;
            preflight_client_dpop_minimum(&db.pool).await?;
        }
        sqlx::raw_sql("CREATE FUNCTION aegaeon.wrong_dpop_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; DROP TRIGGER clients_dpop_minimum_guard ON aegaeon.clients; CREATE TRIGGER clients_dpop_minimum_guard BEFORE INSERT OR UPDATE ON aegaeon.clients FOR EACH ROW EXECUTE FUNCTION aegaeon.wrong_dpop_guard()").execute(&db.pool).await?;
        assert!(preflight_client_dpop_minimum(&db.pool).await.is_err());
        sqlx::raw_sql("DROP TRIGGER clients_dpop_minimum_guard ON aegaeon.clients; CREATE TRIGGER clients_dpop_minimum_guard AFTER INSERT OR UPDATE ON aegaeon.clients FOR EACH ROW EXECUTE FUNCTION aegaeon.guard_client_dpop_minimum()").execute(&db.pool).await?;
        assert!(preflight_client_dpop_minimum(&db.pool).await.is_err());
        Ok(())
    }.await;
    db.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; repair waits for environment lock then rejects changed complete row"]
async fn pg_client_dpop_repair_rechecks_after_observed_lock_wait() -> TestResult {
    let db = Database::client_dpop_predecessor().await?;
    let result=async {
        let env=setup_test_environment(&db.pool).await?;
        let id=seed(&db.pool,&env,"ACTIVE").await?;
        sqlx::raw_sql(MIGRATION).execute(&db.pool).await?;
        let mut conn=db.pool.acquire().await?;
        sqlx::query(INPUT).execute(&mut *conn).await?;
        let expected=digest(&mut conn,id).await?;
        input(&mut conn,env.environment_id,id,&expected,"true").await?;
        let mut blocker=db.pool.begin().await?;
        let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE").bind(env.environment_id).execute(&mut *blocker).await?;
        sqlx::query("UPDATE aegaeon.clients SET updated_at=updated_at+interval '1 second' WHERE id=$1").bind(id).execute(&mut *blocker).await?;
        let repair=sqlx::raw_sql(REPAIR).execute(&mut *conn);
        let release=async {
            tokio::time::timeout(std::time::Duration::from_secs(10),async {
                loop {
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&db.pool).await?;
                    if waiting { return Ok::<_,sqlx::Error>(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await??;
            blocker.commit().await?;
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let (repaired,released)=tokio::join!(repair,release);released?;assert!(repaired.is_err());
        sqlx::query("ROLLBACK").execute(&mut *conn).await?;
        assert!(sqlx::query_scalar::<_,bool>("SELECT dpop_bound_access_tokens IS NULL FROM aegaeon.clients WHERE id=$1").bind(id).fetch_one(&db.pool).await?);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM aegaeon.audit_events").fetch_one(&db.pool).await?,0);
        drop(conn);Ok(())
    }.await;
    db.cleanup().await?;
    result
}
