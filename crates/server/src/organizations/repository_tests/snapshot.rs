use super::*;
use crate::organizations::snapshot::Reader;
use serde_json::Value;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL; MVCC and retained ownership"]
async fn pg_organizations_snapshot_keeps_one_view_and_complete_retained_identity_history(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        // A former subject remains reserved after rename; its owner is retained.
        let historical = format!("prior-subject-{}",f.users[1]);
        sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1").bind(f.users[1]).bind(&historical).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1").bind(f.users[1]).bind(format!("current-subject-{}",f.users[1])).execute(&f.pool).await?;
        let mut tx=f.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
        let mut reader=Reader::start(&mut tx,f.organization.scope).await?;
        assert!(reader.manifest_line().is_err(),"a prefix is never a snapshot");
        let mut transfer=reader.header_line()?;
        // Changes after snapshot capture must not alter either object or member rows.
        let mut writer=f.pool.begin().await?;
        repository::update_membership(&mut writer,f.organization.scope,f.organization.id,MembershipUpdate {user_id:f.users[1],expected_revision:1,state:MembershipState::Suspended,roles:BTreeSet::from(["admin".into()])},&f.actor).await?;
        writer.commit().await?;
        sqlx::query("UPDATE aegaeon.application_organizations SET state='suspended',revision=revision+1 WHERE id=$1").bind(f.organization.id).execute(&f.pool).await?;
        let mut records=Vec::new();
        while let Some(lines)=reader.next(&mut tx).await? {
            for bytes in lines {records.push(serde_json::from_slice::<Value>(&bytes)?);transfer.extend(bytes);}
        }
        tx.commit().await?;
        let manifest:Value=serde_json::from_slice(&reader.manifest_line()?)?;
        assert_eq!(manifest["contentBytes"],transfer.len() as u64);
        assert_eq!(manifest["sections"].as_array().ok_or("sections")?.len(),20);
        for entry in manifest["sections"].as_array().ok_or("sections")? {
            let count=records.iter().filter(|row|row["section"]==entry["section"]).count();
            assert_eq!(entry["count"],count as u64);
        }
        let org=records.iter().find(|row|row["section"]=="organizations" && row["data"]["id"]==f.organization.id.to_string()).ok_or("organization")?;
        assert_eq!(org["data"]["state"],"active");
        let member=records.iter().find(|row|row["section"]=="memberships" && row["data"]["end_user_id"]==f.users[1].to_string()).ok_or("member")?;
        assert_eq!(member["data"]["state"],"active");
        assert!(records.iter().any(|row|row["section"]=="subject_history" && row["data"]["subject"]==historical));
        assert_eq!(records.iter().filter(|row|row["section"]=="owners").count(),2);
        transfer.extend(reader.manifest_line()?);
        let digest=crate::subject_ownership::history::sha256_hex(&transfer);
        let mut imported=crate::organizations::snapshot::input::Input::new(std::io::Cursor::new(&transfer),f.organization.scope,&digest)?;
        let mut parsed=Vec::new();
        while let Some(row)=imported.next_row()? {parsed.push(serde_json::json!({"record":"row","section":row.section,"key":row.key,"data":row.data}));}
        assert_eq!(parsed,records,"native input must preserve every exported row");
        let receipt=imported.finish()?;
        assert_eq!(receipt.sha256,digest);
        assert_eq!(receipt.bytes,transfer.len() as u64);
        let text=String::from_utf8(transfer)?;
        println!("SNAPSHOT_FIXTURE_START\n{text}SNAPSHOT_FIXTURE_END");
        for secret_field in ["password_hash","capability_hash","client_secret_encrypted"] {assert!(!text.contains(secret_field));}
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL; refuses unsupported transaction and scope"]
async fn pg_organizations_snapshot_refuses_read_committed_and_other_domain() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let mut tx = f.pool.begin().await?;
        assert!(Reader::start(&mut tx, f.organization.scope).await.is_err());
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let other = Scope {
            domain_id: Uuid::new_v4(),
            ..f.organization.scope
        };
        assert!(Reader::start(&mut tx, other).await.is_err());
        tx.rollback().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL; scoped definer and preserved private tables"]
async fn pg_organizations_snapshot_history_is_scoped_bounded_and_execute_only() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let error = sqlx::query("SELECT owner_id FROM aegaeon.end_user_identity_owners LIMIT 1")
            .fetch_all(&f.pool).await.expect_err("raw permanent history must stay private");
        assert_eq!(error.as_database_error().and_then(|e|e.code()).as_deref(),Some("42501"));
        let domain=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name) VALUES($1,$2,'empty snapshot scope')")
            .bind(domain).bind(f.env.environment_id).execute(&f.pool).await?;
        let query="SELECT row_key FROM aegaeon.organization_snapshot_history_v1($1,$2,$3,$4,$5)";
        let scoped=sqlx::query_scalar::<_,String>(query).bind(f.env.environment_id).bind(domain)
            .bind("owners").bind(None::<String>).bind(10i32).fetch_all(&f.pool).await?;
        assert!(scoped.is_empty(),"another domain may not expose these owners");
        let mut keys=Vec::new();
        loop {
            let page=sqlx::query_scalar::<_,String>(query).bind(f.env.environment_id).bind(f.organization.scope.domain_id)
                .bind("owners").bind(keys.last()).bind(1i32).fetch_all(&f.pool).await?;
            assert!(page.len()<=1);
            if page.is_empty(){break;}
            keys.extend(page);
            assert!(keys.len()<=2);
        }
        let mut expected=f.users.iter().map(Uuid::to_string).collect::<Vec<_>>();expected.sort();
        assert_eq!(keys,expected);
        for (environment,collection,limit,after) in [
            (Uuid::new_v4(),"owners",10,None),
            (f.env.environment_id,"unrestricted_history",10,None),
            (f.env.environment_id,"owners",11,None),
            (f.env.environment_id,"owners",0,None),
            (f.env.environment_id,"owners",10,Some("x".repeat(4097))),
        ] {
            let error=sqlx::query(query).bind(environment).bind(f.organization.scope.domain_id)
                .bind(collection).bind(after).bind(limit).fetch_all(&f.pool).await.expect_err("invalid supplier call");
            assert_eq!(error.as_database_error().and_then(|e|e.code()).as_deref(),Some("22023"));
        }
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL; deleted identities retain their history"]
async fn pg_organizations_snapshot_keeps_deleted_identity_owner_and_subjects() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1")
            .bind(f.users[1])
            .execute(&f.pool)
            .await?;
        let mut tx = f.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let mut reader = Reader::start(&mut tx, f.organization.scope).await?;
        let mut records = Vec::new();
        while let Some(lines) = reader.next(&mut tx).await? {
            for line in lines {
                records.push(serde_json::from_slice::<Value>(&line)?);
            }
        }
        tx.commit().await?;
        assert!(reader.manifest_line().is_ok());
        let owner = f.users[1].to_string();
        assert!(records
            .iter()
            .any(|r| r["section"] == "owners" && r["data"]["owner_id"] == owner));
        assert!(records
            .iter()
            .any(|r| r["section"] == "subject_history" && r["data"]["owner_id"] == owner));
        assert!(!records
            .iter()
            .any(|r| r["section"] == "identities" && r["data"]["id"] == owner));
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; real administrative activation and complete nonsecret history"]
async fn pg_organizations_snapshot_retains_complete_administrative_grant_metadata() -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        let root=super::support_grants::setup(&f).await?;
        let grant=super::support_grants::activate(&f,&root,"snapshot-support").await?;
        let expected:Value=sqlx::query_scalar("SELECT (to_jsonb(g)-'request_digest'-'revocation_digest') || jsonb_build_object('request_digest',encode(request_digest,'hex'),'revocation_digest',encode(revocation_digest,'hex')) FROM aegaeon.organization_admin_access_grants g WHERE id=$1")
            .bind(grant.id).fetch_one(&f.pool).await?;
        let mut tx=f.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
        let mut reader=Reader::start(&mut tx,f.organization.scope).await?;
        let mut actual=None;
        while let Some(lines)=reader.next(&mut tx).await? {
            for line in lines {
                let row:Value=serde_json::from_slice(&line)?;
                if row["section"]=="administrative_grants" && row["data"]["id"]==grant.id.to_string() {
                    assert!(actual.replace(row["data"].clone()).is_none());
                }
            }
        }
        tx.commit().await?;
        assert!(reader.manifest_line().is_ok());
        assert_eq!(actual.as_ref(),Some(&expected),"all nonsecret administrative history columns must survive export");
        Ok(())
    }.await;
    f.cleanup(result).await
}
