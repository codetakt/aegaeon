use super::*;

fn has(rows: &[Value], section: &str, id: Uuid) -> bool {
    rows.iter()
        .any(|r| r["section"] == section && r["key"] == id.to_string())
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; explicit registration absence and provider projections"]
async fn pg_organizations_import_registration_reference_closure_and_absence() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (policy, _) = super::super::support_policy::setup(&f).await?;
        let provider = policy.providers[0].connection_id;
        super::super::support_policy::configure(&f, "dependencies", 1, Some(policy)).await?;
        let id = super::super::clients::registration(&f, "受信者.É").await?;
        let recipients = json!([{"clientRegistrationId":id,"clientIdentifier":"受信者.É"}]);
        sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2 AND audience='management-api'")
            .bind(recipients).bind(f.env.environment_id).execute(&f.pool).await?;
        let bytes = export(&f).await?;
        let rows = records(&bytes);
        assert_eq!(rows[0]["version"],2);
        assert!(has(&rows,"client_dependencies",id),"introspection-only registration omitted");
        assert!(has(&rows,"connection_dependencies",provider),"support provider omitted");
        assert!(!String::from_utf8(bytes.clone())?.contains("client_secret_encrypted"));
        inspect(&f,&bytes).await?;
        for (section, id) in [("client_dependencies",id),("connection_dependencies",provider)] {
            let mut missing = rows.clone();
            missing.retain(|r| !(r["section"] == section && r["key"] == id.to_string()));
            assert!(inspect(&f,&reframe(missing)).await.is_err(),"rehashed omission: {section}");
        }
        let mut injected = rows.clone();
        injected.iter_mut().find(|r|r["section"]=="connection_dependencies").ok_or("provider")?["data"]["configuration"]["client_secret_encrypted"] = json!("forbidden");
        assert!(inspect(&f,&reframe(injected)).await.is_err(),"closed provider disclosure");
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(id).execute(&f.pool).await?;
        let replacement = super::super::clients::registration(&f, "受信者.É").await?;
        assert_ne!(id,replacement);
        let bytes = export(&f).await?;
        let rows = records(&bytes);
        assert!(has(&rows,"client_absences",id));
        assert!(!has(&rows,"client_dependencies",replacement),"same identifier must not rebind old UUID");
        inspect(&f,&bytes).await?;
        let mut missing = rows;
        missing.retain(|r| !(r["section"]=="client_absences" && r["key"]==id.to_string()));
        assert!(inspect(&f,&reframe(missing)).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}
