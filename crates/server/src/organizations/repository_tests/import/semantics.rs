use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; valid hashes do not legalize malformed producer values"]
async fn pg_organizations_import_source_rejects_semantically_invalid_rows() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        super::super::operators::principal(&f).await?;
        super::super::operators::grant(&f, json!(["provision"])).await?;
        let bytes = export(&f).await?;
        assert!(inspect(&f, &bytes).await.is_ok());
        for (section, field, value) in [
            ("organizations", "external_id", json!("bad\nidentifier")),
            ("organizations", "external_id", json!("é".repeat(129))),
            ("organizations", "state", json!("ACTIVE")),
            ("organizations", "created_at", json!("infinity")),
            ("memberships", "roles", json!(["admin", "admin"])),
            ("memberships", "roles", json!(["role with spaces"])),
            ("memberships", "state", json!("deleted")),
            ("roles", "privileges", json!(["read", "read"])),
            ("roles", "privileges", json!([])),
            ("roles", "assignable_roles", json!(["bad role"])),
            ("operators", "capabilities", json!(["configure", "configure"])),
            ("operators", "capabilities", json!(["administrator"])),
            ("domain", "invitation_delivery", json!({"endpoint":"http://delivery.example","credentialSha256":"0".repeat(64)})),
            ("domain", "support_policy", json!({"providers":[],"entitlements":[]})),
            ("environment_dependency", "organization_identity_policy", json!({"registration":true,"passwordRecovery":false,"subjectFormat":"organization_uuid"})),
            ("namespace", "recorded_at", json!("2026-02-30T00:00:00Z")),
        ] {
            let mut changed = records(&bytes);
            let row = changed.iter_mut().find(|r| r["section"] == section)
                .expect("native fixture includes the tested section");
            row["data"][field] = value;
            let reframed = reframe(changed);
            let error = inspect(&f, &reframed).await.expect_err("semantic corruption refused");
            assert!(error.to_string().contains("source row semantics"), "{section}.{field}: {error}");
        }
        // Values at the external-ID byte bound remain exact, including case and
        // Unicode spelling. This is validation, not normalization or adoption.
        for external in ["é".repeat(128), "A/a/É/e\u{301}".into()] {
            let mut changed = records(&bytes);
            let row = changed.iter_mut().find(|r| r["section"] == "organizations").unwrap();
            row["data"]["external_id"] = json!(external);
            assert!(inspect(&f, &reframe(changed)).await.is_ok());
        }
        assert!(inspect(&f, &bytes).await.is_ok(), "fresh retry after refusals");
        Ok(())
    }.await;
    f.cleanup(result).await
}
