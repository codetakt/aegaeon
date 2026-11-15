use super::*;
use crate::web::test_support::{test_admin_pool, test_pg_pool, TestResult};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with provisioned subject and management authority owners"]
async fn pg_subject_history_cli_retains_all_compiled_function_owners() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL required")?;
    let admin = test_admin_pool(&pool).await?;
    let directory = std::env::temp_dir().join(format!("history-catalog-{}", uuid::Uuid::new_v4()));
    let result: TestResult = async {
        let output = PrivateArtifacts::create(&directory)?;
        let mut snapshot = output.new_file("catalog.jsonl")?;
        let mut chains = std::collections::HashMap::from([(
            "physical_catalog",
            HashChain::new("physical_catalog"),
        )]);
        let runtime_role = pool.connect_options().get_username().to_owned();
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT row_key,row_text FROM aegaeon.subject_history_physical_catalog($1)",
        )
        .bind(&runtime_role)
        .fetch_all(&admin)
        .await?;
        let mut catalog = Vec::new();
        for (key, text) in rows {
            retain_source_record(
                "source:physical_catalog",
                &key,
                &text,
                &mut snapshot,
                &mut chains,
                &mut catalog,
            )?;
        }
        let physical = super::super::preflight::physical_contract_hash()?;
        verify_compiled_catalog(&catalog, &physical, &runtime_role)?;
        // The old collector discarded this owner's row, although its functions
        // were included. Preserve that refusal as a negative control.
        let missing_management_owner: Vec<_> = catalog
            .iter()
            .filter(|(_, value)| value["rolname"] != "aegaeon_management_authority_owner")
            .cloned()
            .collect();
        assert!(
            verify_compiled_catalog(&missing_management_owner, &physical, &runtime_role).is_err()
        );
        assert_eq!(catalog.len(), catalog_row_bound()?);
        Ok(())
    }
    .await;
    admin.close().await;
    pool.close().await;
    if directory.exists() {
        std::fs::remove_dir_all(directory)?;
    }
    result
}
